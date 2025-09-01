#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
VM Network Performance Tracing Tool

Provides comprehensive VM network performance measurement with packet tracking
through the entire network stack. Uses LRU hash for packet identification
and tracks packets from first probe point through all stages.

Key features:
- Packet unique identification with LRU hash storage
- Direction based on vnet perspective (rx/tx)
- Qdisc enqueue/dequeue monitoring
- Complete packet path tracing

Usage:
    sudo ./vm_net_perf_trace.py --vnet-dev vnet37 --phys-dev enp94s0f0np0 \
                                --src-ip 192.168.76.198 --direction rx

"""

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl

# Global configuration
direction_filter = 0  # 0=both, 1=vnet_rx(vm_tx), 2=vnet_tx(vm_rx)

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define VM_IFINDEX %d
#define PHY_IFINDEX %d
#define DIRECTION_FILTER %d  // 0=both, 1=vnet_rx, 2=vnet_tx

// Stage definitions - vnet perspective
// VNET RX path (VM TX, packets from VM to external)
#define STG_VNET_RX         1   // netif_receive_skb (vnet) - FIRST POINT
#define STG_OVS_RX          2   // ovs_vport_receive
#define STG_FLOW_EXTRACT_END_RX  3   // ovs_ct_update_key (flow extract phase)
#define STG_CT_RX           4   // nf_conntrack_in
#define STG_CT_OUT_RX       5   // ovs_ct_update_key (conntrack action)
#define STG_QDISC_ENQ       6   // qdisc_enqueue (physical dev)
#define STG_QDISC_DEQ       7   // qdisc_dequeue (physical dev)
#define STG_TX_QUEUE        8   // dev_queue_xmit (physical dev)
#define STG_TX_XMIT         9   // dev_hard_start_xmit (physical dev) - LAST POINT

// VNET TX path (VM RX, packets from external to VM)
#define STG_PHY_RX          11  // netif_receive_skb (physical) - FIRST POINT
#define STG_OVS_TX          12  // ovs_vport_receive
#define STG_FLOW_EXTRACT_END_TX  13   // ovs_ct_update_key (flow extract phase)
#define STG_CT_TX           14  // nf_conntrack_in
#define STG_CT_OUT_TX       15  // ovs_ct_update_key (conntrack action)
#define STG_TUN_XMIT        16  // tun_net_xmit
#define STG_VNET_QDISC_ENQ  17  // qdisc_enqueue (vnet dev)
#define STG_VNET_QDISC_DEQ  18  // qdisc_dequeue (vnet dev)
#define STG_VNET_TX         19  // dev_hard_start_xmit (vnet) - LAST POINT

#define MAX_STAGES          20
#define IFNAMSIZ            16
#define TASK_COMM_LEN       16

// Packet key structure for unique packet identification
struct packet_key_t {
    __be32 sip;         // Canonical source IP
    __be32 dip;         // Canonical destination IP
    u8 proto;           // Protocol type
    u8 pad[3];          // Alignment padding
    
    union {
        // TCP packet identification - using seq as primary identifier
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be32 seq;           // TCP sequence number (main identifier)
        } tcp;
        
        // UDP packet identification - using IP ID as identifier
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be16 id;            // IP identification (main identifier)
            __be16 len;           // UDP length
        } udp;
        
        // ICMP packet identification - using ID+seq as identifier
        struct {
            __be16 id;            // ICMP ID
            __be16 sequence;      // ICMP sequence number
            u8 type;              // ICMP type
            u8 code;              // ICMP code
            u8 pad[2];            // Padding
        } icmp;
    };
};

// Per-stage detailed information
struct stage_info_t {
    u64 timestamp;                // Timestamp for this stage
    u64 skb_ptr;                  // SKB pointer for this stage
    u32 ifindex;                  // Interface index
    char devname[IFNAMSIZ];       // Device name
    s16 queue_mapping;            // SKB queue mapping at this stage
    u32 skb_hash;                 // SKB hash at this stage
    u32 len;                      // Packet length at this stage
    u32 data_len;                 // SKB data length at this stage
    u32 cpu;                      // CPU at this stage
    u8 valid;                     // Whether this stage has valid data
};

// Flow tracking data structure
struct flow_data_t {
    struct stage_info_t stages[MAX_STAGES];  // Per-stage detailed info
    
    // Packet identification info (first stage)
    u32 first_pid;                // PID at first capture
    char first_comm[TASK_COMM_LEN]; // Process name at first capture
    
    // Conntrack timing
    u64 ct_start_time;            // When CT lookup started
    u32 ct_lookup_duration;       // CT lookup duration in nanoseconds
    
    // Qdisc timing
    u64 qdisc_enq_time;           // When packet was enqueued to qdisc
    u32 qdisc_qlen;               // Queue length at dequeue time
    
    // Direction and flow state
    u8 direction;                 // 1=vnet_rx, 2=vnet_tx
    u8 stage_count;               // Number of stages captured
    u8 complete;                  // Flow complete flag
    
    // Backward compatibility fields (deprecated, use stages[] instead)
    u64 ts[MAX_STAGES];           // Backward compatibility - timestamps
    u64 skb_ptr[MAX_STAGES];      // Backward compatibility - skb pointers
    s16 queue_mapping;            // Backward compatibility - initial queue mapping
    u32 skb_hash;                 // Backward compatibility - initial skb hash
    u32 len;                      // Backward compatibility - initial packet length
    u32 data_len;                 // Backward compatibility - initial data length
    char first_ifname[IFNAMSIZ];  // Backward compatibility - first interface name
};

// Event data structure for performance output
struct pkt_event {
    // Packet identification
    u64 pkt_id;                  // Packet unique ID (skb pointer)
    struct packet_key_t key;     // Packet identification key
    
    // Flow tracking data
    struct flow_data_t flow;     // Complete flow data
    
    // Current stage info
    u64 timestamp;               // Current event timestamp
    u32 cpu;                     // Current CPU ID
    u32 ifindex;                 // Current device ifindex
    char devname[16];            // Current device name
    u8 stage;                    // Current stage
    
    // Event type: 0=stage_event, 1=complete_flow
    u8 event_type;
};

// Maps for packet flow tracking - using LRU hash like icmp_rtt_latency.py
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_ARRAY(event_scratch_map, struct pkt_event, 1);
BPF_PERCPU_ARRAY(flow_init_map, struct flow_data_t, 1);  // Per-cpu temp storage for initialization

// Performance statistics
BPF_ARRAY(probe_stats, u64, 32);          // Event counters for each probe point

// Events output
BPF_PERF_OUTPUT(events);

// Helper functions - reusing vm_network_latency.py proven logic
static __always_inline bool is_target_vm_interface(const struct sk_buff *skb) {
    if (VM_IFINDEX == 0) return false;
    
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == VM_IFINDEX);
}

static __always_inline bool is_target_phy_interface(const struct sk_buff *skb) {
    if (PHY_IFINDEX == 0) return false;
    
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == PHY_IFINDEX);
}

// Packet parsing functions - reusing vm_network_latency.py logic
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip) {
    unsigned char *head;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }
    
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return -1;
    }
    
    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_header_offset) < 0) {
        return -1;
    }
    
    return 0;
}

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size) {
    unsigned char *head;
    u16 transport_header_offset;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }
    
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        // Calculate transport header offset from IP header
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
            return -1;
        }
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return -1;
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }
    
    if (bpf_probe_read_kernel(hdr, hdr_size, head + transport_header_offset) < 0) {
        return -1;
    }
    
    return 0;
}

static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key,
    u8 direction  // 1=vnet_rx, 2=vnet_tx
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip) != 0) {
        return 0;
    }
    
    // Apply filters first
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }
    
    // Direction-specific IP filtering
    if (direction == 1) { // vnet_rx: packets from VM (source should be VM IP)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    } else if (direction == 2) { // vnet_tx: packets to VM (destination should be VM IP)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    } else {
        // For both directions, use OR logic (either source OR destination matches)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    }
    
    // Set canonical source/destination for consistent packet identification
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
    // Parse transport layer based on protocol
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp)) != 0) return 0;
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && key->tcp.source != htons(SRC_PORT_FILTER) && key->tcp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.source != htons(DST_PORT_FILTER) && key->tcp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;  // Use IP ID as main identifier
            
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
                key->udp.source = udp.source;
                key->udp.dest = udp.dest;
                key->udp.len = udp.len;
            }
            
            if (SRC_PORT_FILTER != 0 && key->udp.source != htons(SRC_PORT_FILTER) && key->udp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->udp.source != htons(DST_PORT_FILTER) && key->udp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (get_transport_header(skb, &icmp, sizeof(icmp)) != 0) return 0;
            
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            break;
        }
        default:
            return 0;
    }
    
    return 1;
}

// Main event handling function - tracks packets through all stages
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id, u8 direction) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();
    
    // Parse packet key for identification
    if (!parse_packet_key(skb, &key, direction)) {
        return;
    }
    
    // Check if this is the first stage for this direction
    bool is_first_stage = false;
    if ((direction == 1 && stage_id == STG_VNET_RX) ||  // vnet RX path starts
        (direction == 2 && stage_id == STG_PHY_RX)) {    // vnet TX path starts
        is_first_stage = true;
    }
    
    struct flow_data_t *flow_ptr;
    
    if (is_first_stage) {
        // Initialize new flow tracking using per-cpu map
        flow_sessions.delete(&key);  // Clean any old entries
        
        u32 init_key = 0;
        struct flow_data_t *zero_ptr = flow_init_map.lookup(&init_key);
        if (!zero_ptr) {
            return;
        }
        
        // Manual initialization in per-cpu map to avoid stack overflow
        #pragma unroll
        for (int i = 0; i < MAX_STAGES; i++) {
            zero_ptr->stages[i].valid = 0;
            zero_ptr->stages[i].timestamp = 0;
            zero_ptr->stages[i].skb_ptr = 0;
            zero_ptr->ts[i] = 0;
            zero_ptr->skb_ptr[i] = 0;
        }
        zero_ptr->first_pid = 0;
        zero_ptr->ct_start_time = 0;
        zero_ptr->ct_lookup_duration = 0;
        zero_ptr->qdisc_enq_time = 0;
        zero_ptr->qdisc_qlen = 0;
        zero_ptr->direction = 0;
        zero_ptr->stage_count = 0;
        zero_ptr->complete = 0;
        
        flow_ptr = flow_sessions.lookup_or_try_init(&key, zero_ptr);
        if (flow_ptr) {
            // Initialize flow data
            flow_ptr->first_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->first_comm, sizeof(flow_ptr->first_comm));
            
            struct net_device *dev = NULL;
            if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
                bpf_probe_read_kernel_str(flow_ptr->first_ifname, IFNAMSIZ, dev->name);
            }
            
            flow_ptr->direction = direction;
            bpf_probe_read_kernel(&flow_ptr->queue_mapping, sizeof(flow_ptr->queue_mapping), &skb->queue_mapping);
            bpf_probe_read_kernel(&flow_ptr->skb_hash, sizeof(flow_ptr->skb_hash), &skb->hash);
            bpf_probe_read_kernel(&flow_ptr->len, sizeof(flow_ptr->len), &skb->len);
            bpf_probe_read_kernel(&flow_ptr->data_len, sizeof(flow_ptr->data_len), &skb->data_len);
        }
    } else {
        // Look up existing flow
        flow_ptr = flow_sessions.lookup(&key);
    }
    
    if (!flow_ptr) {
        return;
    }
    
    // Record detailed information for this stage
    if (stage_id < MAX_STAGES && !flow_ptr->stages[stage_id].valid) {
        struct stage_info_t *stage = &flow_ptr->stages[stage_id];
        
        stage->timestamp = current_ts;
        stage->skb_ptr = (u64)skb;
        stage->cpu = bpf_get_smp_processor_id();
        
        // Get current device info
        struct net_device *dev = NULL;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel(&stage->ifindex, sizeof(stage->ifindex), &dev->ifindex);
            bpf_probe_read_kernel_str(stage->devname, IFNAMSIZ, dev->name);
        }
        
        // Get current SKB info
        bpf_probe_read_kernel(&stage->queue_mapping, sizeof(stage->queue_mapping), &skb->queue_mapping);
        bpf_probe_read_kernel(&stage->skb_hash, sizeof(stage->skb_hash), &skb->hash);
        bpf_probe_read_kernel(&stage->len, sizeof(stage->len), &skb->len);
        bpf_probe_read_kernel(&stage->data_len, sizeof(stage->data_len), &skb->data_len);
        
        stage->valid = 1;
        flow_ptr->stage_count++;
        
        // Backward compatibility - still fill old fields
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
    }
    
    // Handle special stages
    if (stage_id == STG_QDISC_ENQ || stage_id == STG_VNET_QDISC_ENQ) {
        flow_ptr->qdisc_enq_time = current_ts;
    }
    
    if (stage_id == STG_CT_RX || stage_id == STG_CT_TX) {
        flow_ptr->ct_start_time = current_ts;
    }
    
    if (stage_id == STG_CT_OUT_RX || stage_id == STG_CT_OUT_TX) {
        if (flow_ptr->ct_start_time > 0) {
            flow_ptr->ct_lookup_duration = (u32)(current_ts - flow_ptr->ct_start_time);
        }
    }
    
    flow_sessions.update(&key, flow_ptr);
    
    // Check if this is the last stage 
    bool is_last_stage = false;
    if ((direction == 1 && stage_id == STG_TX_XMIT) ||   // vnet RX path ends
        (direction == 2 && stage_id == STG_VNET_TX)) {    // vnet TX path ends
        is_last_stage = true;
    }
    
    // Only submit event at the last stage
    if (is_last_stage) {
        u32 map_key_zero = 0;
        struct pkt_event *event_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_ptr) {
            return;
        }
        
        event_ptr->pkt_id = (u64)skb;
        event_ptr->key = key;
        event_ptr->timestamp = current_ts;
        event_ptr->cpu = bpf_get_smp_processor_id();
        event_ptr->stage = stage_id;
        event_ptr->event_type = 1;  // complete flow event
        
        // Get current device info
        struct net_device *dev = NULL;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel(&event_ptr->ifindex, sizeof(event_ptr->ifindex), &dev->ifindex);
            bpf_probe_read_kernel_str(event_ptr->devname, IFNAMSIZ, dev->name);
        }
        
        // Copy flow data and submit complete flow event
        if (bpf_probe_read_kernel(&event_ptr->flow, sizeof(event_ptr->flow), flow_ptr) == 0) {
            events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        }
        
        // Clean up flow tracking
        flow_sessions.delete(&key);
    }
    
    // Update statistics
    u32 stat_idx = stage_id %% 32;
    u64 *counter = probe_stats.lookup(&stat_idx);
    if (counter) {
        (*counter)++;
    }
}

// VNET RX Path Probes (VM TX, packets from VM to external)
int kprobe__netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_VNET_RX, 1);  // direction=1 (vnet_rx)
    }
    
    return 0;
}

int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_PHY_RX, 2);  // direction=2 (vnet_tx)
    }
    
    return 0;
}

int kprobe__ovs_vport_receive(struct pt_regs *ctx, void *vport, struct sk_buff *skb, void *tun_info) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_OVS_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_OVS_TX, 2);
    }
    return 0;
}

int kprobe__nf_conntrack_in(struct pt_regs *ctx, struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_CT_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_CT_TX, 2);
    }
    
    return 0;
}

int kprobe__ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, void *info, void *key, bool post_ct, bool keep_nat_flags) {
    if (!skb) return 0;
    
    // Distinguish between flow extract and conntrack action calls
    // post_ct=false indicates flow extract phase (ovs_ct_fill_key)  
    // post_ct=true indicates conntrack action phase (__ovs_ct_lookup)
    if (post_ct) {
        // Conntrack action phase
        if (DIRECTION_FILTER != 2) {  // vnet_rx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // vnet_tx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_TX, 2);
        }
    } else {
        // Flow extract phase
        if (DIRECTION_FILTER != 2) {  // vnet_rx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // vnet_tx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_TX, 2);
        }
    }
    
    return 0;
}

// Qdisc enqueue using tracepoint trace_net_dev_queue
RAW_TRACEPOINT_PROBE(net_dev_queue) {
    // args: struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_QDISC_ENQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_QDISC_ENQ, 2);
    }
    
    return 0;
}

// Qdisc dequeue tracepoint 
RAW_TRACEPOINT_PROBE(qdisc_dequeue) {
    // args: struct Qdisc *qdisc, const struct netdev_queue *txq, int packets, struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_QDISC_DEQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_QDISC_DEQ, 2);
    }
    
    return 0;
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_TX_QUEUE, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_TX, 2);  // Last stage for vnet_tx
    }
    
    return 0;
}

int kprobe__dev_queue_xmit_nit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !is_target_phy_interface(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
    
    handle_stage_event(ctx, skb, STG_TX_XMIT, 1);  // Last stage for vnet_rx
    return 0;
}

// TUN transmit for vnet_tx path
int kprobe__tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !is_target_vm_interface(skb)) return 0;
    if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
    
    handle_stage_event(ctx, skb, STG_TUN_XMIT, 2);
    return 0;
}
"""

# Constants
MAX_STAGES = 20
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# Event data structure - matching BPF structure
class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("data", ctypes.c_uint8 * 8)  # Union data
    ]

# Per-stage information structure
class StageInfo(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("skb_ptr", ctypes.c_uint64),
        ("ifindex", ctypes.c_uint32),
        ("devname", ctypes.c_char * IFNAMSIZ),
        ("queue_mapping", ctypes.c_int16),
        ("skb_hash", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("valid", ctypes.c_uint8)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("stages", StageInfo * MAX_STAGES),
        ("first_pid", ctypes.c_uint32),
        ("first_comm", ctypes.c_char * TASK_COMM_LEN),
        ("ct_start_time", ctypes.c_uint64),
        ("ct_lookup_duration", ctypes.c_uint32),
        ("qdisc_enq_time", ctypes.c_uint64),
        ("qdisc_qlen", ctypes.c_uint32),
        ("direction", ctypes.c_uint8),
        ("stage_count", ctypes.c_uint8),
        ("complete", ctypes.c_uint8),
        # Backward compatibility fields
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("queue_mapping", ctypes.c_int16),
        ("skb_hash", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("first_ifname", ctypes.c_char * IFNAMSIZ)
    ]

class PktEvent(ctypes.Structure):
    _fields_ = [
        ("pkt_id", ctypes.c_uint64),
        ("key", PacketKey),
        ("flow", FlowData),
        ("timestamp", ctypes.c_uint64),
        ("cpu", ctypes.c_uint32),
        ("ifindex", ctypes.c_uint32),
        ("devname", ctypes.c_char * IFNAMSIZ),
        ("stage", ctypes.c_uint8),
        ("event_type", ctypes.c_uint8)
    ]

# Helper Functions - reusing vm_network_latency.py logic
def get_if_index(devname):
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()

def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def get_stage_name(stage_id):
    """Get human-readable stage name"""
    stage_names = {
        # VNET RX path (VM TX, packets from VM to external)
        1: "VNET_RX",
        2: "OVS_RX", 
        3: "FLOW_EXTRACT_END_RX",
        4: "CT_RX",
        5: "CT_OUT_RX",
        6: "QDISC_ENQ",
        7: "QDISC_DEQ",
        8: "TX_QUEUE",
        9: "TX_XMIT",
        
        # VNET TX path (VM RX, packets from external to VM)
        11: "PHY_RX",
        12: "OVS_TX",
        13: "FLOW_EXTRACT_END_TX",
        14: "CT_TX",
        15: "CT_OUT_TX",
        16: "TUN_XMIT",
        17: "VNET_QDISC_ENQ",
        18: "VNET_QDISC_DEQ",
        19: "VNET_TX"
    }
    return stage_names.get(stage_id, "Unknown_%d" % stage_id)

def get_protocol_identifier(key, protocol):
    """Get protocol-specific packet identifier"""
    data = ctypes.string_at(ctypes.addressof(key.data), 8)
    
    if protocol == 6:  # TCP
        # TCP: source(2) + dest(2) + seq(4)
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        seq = struct.unpack("!I", data[4:8])[0]
        return "TCP %d->%d seq=%u" % (source, dest, seq)
    elif protocol == 17:  # UDP
        # UDP: source(2) + dest(2) + id(2) + len(2)
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        ip_id = struct.unpack("!H", data[4:6])[0]
        return "UDP %d->%d id=%u" % (source, dest, ip_id)
    elif protocol == 1:  # ICMP
        # ICMP: id(2) + seq(2) + type(1) + code(1)
        icmp_id = struct.unpack("!H", data[0:2])[0]
        seq = struct.unpack("!H", data[2:4])[0]
        icmp_type = data[4] if len(data) > 4 else 0
        return "ICMP id=%u seq=%u type=%u" % (icmp_id, seq, icmp_type)
    else:
        return "Proto%d" % protocol

def print_event(cpu, data, size):
    """Print performance event"""
    global args
    event = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents
    
    # Now we only receive complete flow events (event_type=1)
    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_names.get(event.key.proto, "Proto%d" % event.key.proto)
    
    # Get protocol-specific packet identifier
    pkt_id = get_protocol_identifier(event.key, event.key.proto)
    
    print("=== FLOW COMPLETE: %d stages captured ===" % event.flow.stage_count)
    
    # Display 5-tuple information
    src_ip = format_ip(event.key.sip)
    dst_ip = format_ip(event.key.dip)
    print("FLOW: %s -> %s (%s)" % (src_ip, dst_ip, pkt_id))
    
    # Display detailed 5-tuple
    direction_str = "VNET_RX" if event.flow.direction == 1 else "VNET_TX"
    if event.key.proto == 6:  # TCP
        tcp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        src_port = struct.unpack("!H", tcp_data[0:2])[0] 
        dst_port = struct.unpack("!H", tcp_data[2:4])[0]
        seq = struct.unpack("!I", tcp_data[4:8])[0]
        print("5-TUPLE: %s:%d -> %s:%d TCP (seq=%u) DIR=%s" % (src_ip, src_port, dst_ip, dst_port, seq, direction_str))
    elif event.key.proto == 17:  # UDP
        udp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        src_port = struct.unpack("!H", udp_data[0:2])[0]
        dst_port = struct.unpack("!H", udp_data[2:4])[0]
        ip_id = struct.unpack("!H", udp_data[4:6])[0]
        print("5-TUPLE: %s:%d -> %s:%d UDP (id=%u) DIR=%s" % (src_ip, src_port, dst_ip, dst_port, ip_id, direction_str))
    elif event.key.proto == 1:  # ICMP
        icmp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        icmp_id = struct.unpack("!H", icmp_data[0:2])[0]
        seq = struct.unpack("!H", icmp_data[2:4])[0]
        icmp_type = icmp_data[4] if len(icmp_data) > 4 else 0
        print("5-TUPLE: %s -> %s ICMP (id=%u seq=%u type=%u) DIR=%s" % (src_ip, dst_ip, icmp_id, seq, icmp_type, direction_str))
    else:
        print("5-TUPLE: %s -> %s Proto%d DIR=%s" % (src_ip, dst_ip, event.key.proto, direction_str))
    
    # Collect valid stages using the new stages array
    stages = []
    for i in range(MAX_STAGES):
        if event.flow.stages[i].valid:
            stages.append((i, event.flow.stages[i]))
    
    # Sort by timestamp to ensure proper order
    stages.sort(key=lambda x: x[1].timestamp)
    
    # Print stages with detailed information from each stage
    prev_ts = None
    for idx, (stage_id, stage_info) in enumerate(stages):
        stage_time = datetime.datetime.fromtimestamp(stage_info.timestamp / 1e9)
        delta_str = ""
        if prev_ts is not None:
            delta_ns = stage_info.timestamp - prev_ts
            delta_str = " (+%.3fus)" % (delta_ns / 1000.0)
        
        # Get exact device name from stage_info
        devname = stage_info.devname.decode('utf-8', 'replace').rstrip('\x00')
        
        print("  Stage %s: %s (KTIME=%luns)%s" % (
            get_stage_name(stage_id), 
            stage_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], 
            stage_info.timestamp, 
            delta_str
        ))
        
        # Print detailed stage information
        print("    SKB: ptr=0x%x len=%d data_len=%d queue_mapping=%d hash=0x%x" % (
            stage_info.skb_ptr, stage_info.len, stage_info.data_len, 
            stage_info.queue_mapping, stage_info.skb_hash
        ))
        
        print("    DEV: %s (ifindex=%d) CPU=%d" % (
            devname, stage_info.ifindex, stage_info.cpu
        ))
        
        prev_ts = stage_info.timestamp
        
    # Show total flow duration
    if len(stages) > 1:
        total_duration = stages[-1][1].timestamp - stages[0][1].timestamp
        print("  TOTAL DURATION: %.3fus" % (total_duration / 1000.0))
    
    # Show detailed packet information
    print("  PACKET: len=%d data_len=%d queue_mapping=%d skb_hash=0x%x" % (
        event.flow.len, event.flow.data_len, event.flow.queue_mapping, event.flow.skb_hash
    ))
    
    # Show process and interface information
    first_comm = event.flow.first_comm.decode('utf-8', 'replace').rstrip('\x00')
    first_ifname = event.flow.first_ifname.decode('utf-8', 'replace').rstrip('\x00')
    print("  PROCESS: pid=%d comm=%s first_dev=%s" % (
        event.flow.first_pid, first_comm, first_ifname
    ))
    
    # Show final stage device information
    final_dev = event.devname.decode('utf-8', 'replace').rstrip('\x00')
    print("  FINAL_STAGE: dev=%s(ifindex=%d) cpu=%d" % (
        final_dev, event.ifindex, event.cpu
    ))
    
    # Show metrics if available
    if event.flow.qdisc_enq_time > 0:
        for stage_id, stage_info in stages:
            if stage_id == 7 or stage_id == 18:  # QDISC_DEQ or VNET_QDISC_DEQ
                sojourn_time_ns = stage_info.timestamp - event.flow.qdisc_enq_time
                qdisc_type = "QDISC" if stage_id == 7 else "VNET_QDISC"
                print("  %s: sojourn=%.3fus qlen=%d" % (qdisc_type, sojourn_time_ns / 1000.0, event.flow.qdisc_qlen))
                break
    
    if event.flow.ct_lookup_duration > 0:
        print("  CT: lookup=%.3fus" % (event.flow.ct_lookup_duration / 1000.0))
        
    print("")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="VM Network Performance Tracing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor VM bidirectional traffic:
    sudo %(prog)s --vnet-dev vnet37 --phys-dev enp94s0f0np0 --vm-ip 192.168.76.198
    
  Monitor only VNET RX traffic (VM TX):
    sudo %(prog)s --vnet-dev vnet37 --phys-dev enp94s0f0np0 --direction rx --src-ip 192.168.76.198
    
  Monitor TCP SSH traffic:
    sudo %(prog)s --vnet-dev vnet37 --phys-dev enp94s0f0np0 --proto tcp --dst-port 22
"""
    )
    
    parser.add_argument('--vnet-dev', type=str, required=True,
                        help='VM virtual interface to monitor (e.g., vnet37)')
    parser.add_argument('--phys-dev', type=str, required=True,
                        help='Physical interface to monitor (e.g., enp94s0f0np0)')
    parser.add_argument('--vm-ip', type=str, required=False,
                        help='VM IP address filter')
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--proto', type=str, choices=['tcp', 'udp', 'icmp', 'all'], 
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--direction', type=str, choices=['rx', 'tx', 'both'], 
                        default='both', help='Direction filter: rx=VNET_RX(VM_TX), tx=VNET_TX(VM_RX) (default: both)')
    parser.add_argument('--enable-ct', action='store_true',
                        help='Enable conntrack measurement')
    parser.add_argument('--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Convert parameters
    if args.vm_ip:
        src_ip_hex = ip_to_hex(args.vm_ip)
        dst_ip_hex = ip_to_hex(args.vm_ip)
    else:
        src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
        dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    
    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.proto]
    
    direction_map = {'rx': 1, 'tx': 2, 'both': 0}
    direction_filter = direction_map[args.direction]
    
    try:
        vm_ifindex = get_if_index(args.vnet_dev)
        phy_ifindex = get_if_index(args.phys_dev)
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)
    
    print("=== VM Network Performance Tracer ===")
    print("Protocol filter: %s" % args.proto.upper())
    print("Direction filter: %s (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)" % args.direction.upper())
    if args.vm_ip:
        print("VM IP filter: %s" % args.vm_ip)
    elif args.src_ip or args.dst_ip:
        if args.src_ip:
            print("Source IP filter: %s" % args.src_ip)
        if args.dst_ip:
            print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("VM interface: %s (ifindex %d)" % (args.vnet_dev, vm_ifindex))
    print("Physical interface: %s (ifindex %d)" % (args.phys_dev, phy_ifindex))
    print("Conntrack measurement: %s" % ("ENABLED" if args.enable_ct else "DISABLED"))
    
    # Debug parameter values
    print("\nDebug: BPF parameters:")
    print("  src_ip_hex=0x%x, dst_ip_hex=0x%x" % (src_ip_hex, dst_ip_hex))
    print("  src_port=%d, dst_port=%d" % (src_port, dst_port))
    print("  protocol_filter=%d, vm_ifindex=%d, phy_ifindex=%d, direction_filter=%d" % 
          (protocol_filter, vm_ifindex, phy_ifindex, direction_filter))
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, vm_ifindex, phy_ifindex, direction_filter
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nActual format string substitution:")
        print("Parameters passed: %d arguments" % len([src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_filter, vm_ifindex, phy_ifindex, direction_filter]))
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event)
    
    print("\nTracing VM network performance... Hit Ctrl-C to end.")
    print("Format: [YYYY-MM-DD HH:MM:SS.mmm] PKT_ID DIR STAGE DEV KTIME=ns")
    print("        FLOW: src -> dst (protocol_identifier)")
    print("        QUEUE/CT/QDISC metrics")
    print("        Complete flow summary at last stage with absolute kernel timestamps")
    print("")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
        print("\n=== Performance Statistics ===")
        
        print("Event counts by probe point:")
        probe_stats = b["probe_stats"]
        for i in range(32):
            count = probe_stats[i].value
            if count > 0:
                print("  Probe %d: %d events" % (i, count))
    finally:
        print("Exiting.")