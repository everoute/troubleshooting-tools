#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Network TCP/UDP Latency Measurement Tool

This tool measures one-way network latency for system-level TCP/UDP traffic,
supporting packet-level tracking using protocol-specific unique identifiers.
It traces the complete network path from protocol stack through OVS to physical interfaces.

Based on:
- icmp_rtt_latency.py: probe point architecture and OVS path handling
- vm_network_latency.py: TCP/UDP packet identification and parsing logic

Usage:
    sudo ./system_tcp_udp_latency.py --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \
                                     --protocol tcp --direction outgoing \
                                     --phy-interface enp94s0f0np0
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

# Global variable for direction filter
direction_filter = 0  # 0=both, 1=outgoing, 2=incoming

# BPF Program - comprehensive implementation based on design document
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>

// IP fragment flags constants
#ifndef IP_MF
#define IP_MF 0x2000    // More Fragments flag
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // Fragment offset mask
#endif

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define DIRECTION_FILTER %d  // 0=both, 1=outgoing, 2=incoming

// TX direction stages (System -> Physical)
#define TX_STAGE_0    0  // ip_send_skb
#define TX_STAGE_1    1  // internal_dev_xmit
#define TX_STAGE_2    2  // ovs_dp_process_packet
#define TX_STAGE_3    3  // ovs_dp_upcall
#define TX_STAGE_4    4  // ovs_flow_key_extract_userspace
#define TX_STAGE_5    5  // ovs_vport_send
#define TX_STAGE_6    6  // dev_queue_xmit (physical)

// RX direction stages (Physical -> System)
#define RX_STAGE_0    7  // __netif_receive_skb (physical)
#define RX_STAGE_1    8  // netdev_frame_hook
#define RX_STAGE_2    9  // ovs_dp_process_packet
#define RX_STAGE_3    10 // ovs_dp_upcall
#define RX_STAGE_4    11 // ovs_flow_key_extract_userspace
#define RX_STAGE_5    12 // ovs_vport_send
#define RX_STAGE_6    13 // tcp_v4_rcv/udp_rcv (protocol specific)

#define MAX_STAGES               14
#define IFNAMSIZ                 16
#define TASK_COMM_LEN            16

// Unified packet key structure supporting TCP/UDP protocols - from vm_network_latency.py
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    u8 protocol;
    
    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            // Remove seq and payload_len - they vary per packet
            // Flow tracking should use only connection 5-tuple
        } tcp;
        
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;       // IP identification field (packet identifier)
            __be16 frag_off;    // Fragment offset (distinguish fragments)
        } udp;
    };
    
    u64 first_seen_ns;  // First capture timestamp (handle retransmissions)
};

// Structure to track TX/RX flow data and timestamps - based on icmp_rtt_latency.py
struct flow_data_t {
    u64 first_seen_ns;        // First capture timestamp (handle retransmissions)
    u64 ts[MAX_STAGES];
    u64 skb_ptr[MAX_STAGES];
    int kstack_id[MAX_STAGES];
    
    // Path1 info (TX for outgoing, RX for incoming)
    u32 p1_pid;
    char p1_comm[TASK_COMM_LEN];
    char p1_ifname[IFNAMSIZ];
    
    // Path2 info (RX for outgoing, TX for incoming)  
    u32 p2_pid;
    char p2_comm[TASK_COMM_LEN];
    char p2_ifname[IFNAMSIZ];
    
    // Protocol specific info
    u8 tcp_flags;
    u16 udp_len;
    
    // Flow state flags
    u8 saw_path1_start:1;
    u8 saw_path1_end:1;
    u8 saw_path2_start:1;
    u8 saw_path2_end:1;
};

// Structure for perf event output
struct event_data_t {
    struct packet_key_t key;
    struct flow_data_t data;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);

// Debug statistics - comprehensive debug framework from bcc-debug-framework.md
BPF_HISTOGRAM(debug_stage_stats, u32);  // Key: (stage_id << 8) | code_point
BPF_HISTOGRAM(ifindex_seen, u32);       // Track which ifindex values we see
BPF_HISTOGRAM(proto_seen, u8);          // Track protocol values seen at TX0

// Code point definitions for debugging
#define CODE_PROBE_ENTRY            1   // Probe function entry
#define CODE_INTERFACE_FILTER       2   // Interface filtering
#define CODE_DIRECTION_FILTER       3   // Direction filtering  
#define CODE_HANDLE_CALLED          4   // handle_stage_event called
#define CODE_HANDLE_ENTRY           5   // handle_stage_event entry
#define CODE_PARSE_ENTRY            6   // parse_packet_key entry
#define CODE_PARSE_SUCCESS          7   // parse_packet_key success
#define CODE_PARSE_IP_FILTER        8   // filtered by IP
#define CODE_PARSE_PROTO_FILTER     9   // filtered by protocol
#define CODE_PARSE_PORT_FILTER     10   // filtered by port
#define CODE_PARSE_TCP_SUCCESS     11   // TCP parse success
#define CODE_PARSE_UDP_SUCCESS     12   // UDP parse success
#define CODE_FLOW_CREATE           14   // flow creation (stage 0 only)
#define CODE_FLOW_LOOKUP           15   // flow lookup (non-stage 0)
#define CODE_FLOW_FOUND            16   // flow found
#define CODE_FLOW_NOT_FOUND        17   // flow not found
#define CODE_SKB_READ_FAIL         18   // failed to read skb
#define CODE_PERF_SUBMIT           19   // perf event submitted
#define CODE_IP_HDR_ERROR          20   // IP header read error
#define CODE_PROTO_ICMP            21   // ICMP protocol seen
#define CODE_PROTO_OTHER           22   // Other protocol seen
#define CODE_PROTO_SEEN            23   // Protocol value seen (for debugging)

// Special counters for interface debugging
BPF_ARRAY(interface_debug, u64, 4);
#define IF_DBG_NULL_DEV             0   // dev is NULL
#define IF_DBG_READ_FAIL            1   // ifindex read failed

// Helper function to record debug statistics
static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}

// Key debugging - print key components for analysis
BPF_PERF_OUTPUT(key_debug_events);

struct key_debug_t {
    u8 stage_id;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 tcp_seq;
    u8 payload_len;
    u32 timestamp;
};

static __always_inline void debug_key(struct pt_regs *ctx, struct packet_key_t *key, u8 stage_id) {
    struct key_debug_t debug_data = {};
    debug_data.stage_id = stage_id;
    debug_data.src_ip = key->src_ip;
    debug_data.dst_ip = key->dst_ip;
    debug_data.src_port = key->tcp.src_port;
    debug_data.dst_port = key->tcp.dst_port;
    debug_data.tcp_seq = 0;  // Removed from key structure
    debug_data.payload_len = 0;  // Removed from key structure
    debug_data.timestamp = bpf_ktime_get_ns() / 1000000;  // Convert to ms
    
    key_debug_events.perf_submit(ctx, &debug_data, sizeof(debug_data));
}

// Helper function for interface debugging
static __always_inline void interface_debug_inc(int idx) {
    u64 *val = interface_debug.lookup(&idx);
    if (val) {
        (*val)++;
    }
}

// Helper function to check if an interface index matches our targets
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        interface_debug_inc(IF_DBG_NULL_DEV);
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        interface_debug_inc(IF_DBG_READ_FAIL);
        return false;
    }
    
    // Track all interface indices we see
    u32 idx = (u32)ifindex;
    ifindex_seen.increment(idx);
    
    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}

// Helper functions for packet parsing - from vm_network_latency.py
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip, u8 stage_id) {
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

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size, u8 stage_id) {
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

// TCP protocol parsing - simplified and more robust
static __always_inline int parse_tcp_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    struct tcphdr tcp;
    if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) != 0) return 0;
    
    key->tcp.src_port = tcp.source;
    key->tcp.dst_port = tcp.dest;
    
    // Sequence number removed from key structure
    // Flow tracking uses only connection 5-tuple
    
    // Use a simplified payload length calculation to avoid inconsistencies
    // For flow tracking, we only need to distinguish major packet types
    struct iphdr ip;
    u16 payload_len = 0;
    if (get_ip_header(skb, &ip, stage_id) == 0) {
        u16 ip_len = ntohs(ip.tot_len);
        u16 ip_hdr_len = (ip.ihl & 0x0F) * 4;
        u16 tcp_hdr_len = (tcp.doff & 0x0F) * 4;
        if (tcp_hdr_len < 20) tcp_hdr_len = 20; // Minimum TCP header size
        if (ip_len > ip_hdr_len + tcp_hdr_len) {
            payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
        }
    }
    
    // Payload length removed from key structure
    // Different stages calculate it differently causing mismatch
    
    return 1;
}

// UDP protocol parsing - from vm_network_latency.py
static __always_inline int parse_udp_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) return 0;
    
    key->udp.ip_id = ip.id;
    
    // Get fragmentation information
    u16 frag_off_flags = ntohs(ip.frag_off);
    u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;  // More Fragments bit
    u16 frag_offset = frag_off_flags & 0x1FFF;          // Fragment offset (8-byte units)
    
    u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;
    
    if (is_fragment) {
        // Fragment packet: use frag_offset to distinguish different fragments
        key->udp.frag_off = frag_offset * 8;  // Convert to byte offset
        
        // Only first fragment has UDP header
        if (frag_offset == 0) {
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
                key->udp.src_port = udp.source;
                key->udp.dst_port = udp.dest;
            }
        } else {
            // Subsequent fragments: port information not available
            key->udp.src_port = 0;
            key->udp.dst_port = 0;
        }
    } else {
        // Non-fragment packet: frag_off = 0, parse UDP header normally
        key->udp.frag_off = 0;
        struct udphdr udp;
        if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
            key->udp.src_port = udp.source;
            key->udp.dst_port = udp.dest;
        }
    }
    
    return 1;
}

// Specialized parsing function for userspace SKB - from vm_network_latency.py
static __always_inline int parse_packet_key_userspace(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    debug_inc(stage_id, CODE_PARSE_ENTRY);
    
    if (skb == NULL) {
        return 0;
    }

    unsigned char *skb_head;
    if(bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }
    
    unsigned long skb_data_ptr_val; 
    if(bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset; 
    
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN tags - exactly like icmp_rtt_latency.py
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        net_offset += VLAN_HLEN; 
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 0;
        }
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
             net_offset += VLAN_HLEN;
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + (2 * VLAN_HLEN) + 2) < 0) {
                 return 0;
             }
        }
    }
    
    if (h_proto != htons(ETH_P_IP)) {
        return 0;
    }
    
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0) {
        return 0;
    }
    
    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;
    
    // Apply filters
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        debug_inc(stage_id, CODE_PARSE_PROTO_FILTER);
        // Track what protocol we're filtering out (only for TX0)
        if (stage_id == TX_STAGE_0) {
            proto_seen.increment(ip.protocol);
            if (ip.protocol == IPPROTO_ICMP) {
                debug_inc(stage_id, CODE_PROTO_ICMP);
            } else {
                debug_inc(stage_id, CODE_PROTO_OTHER);
            }
        }
        return 0;
    }
    
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    unsigned int trans_offset = net_offset + (ip_ihl * 4);
    
    // Parse transport layer
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) < 0) {
                return 0;
            }
            key->tcp.src_port = tcp.source;
            key->tcp.dst_port = tcp.dest;
            
            // Sequence number removed from key structure
            
            // Use same payload length bucketing as regular parsing
            u16 ip_len = ntohs(ip.tot_len);
            u16 ip_hdr_len = (ip.ihl & 0x0F) * 4;
            u16 tcp_hdr_len = (tcp.doff & 0x0F) * 4;
            if (tcp_hdr_len < 20) tcp_hdr_len = 20; // Minimum TCP header size
            
            u16 payload_len = 0;
            if (ip_len > ip_hdr_len + tcp_hdr_len) {
                payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
            }
            
            // Payload length removed from key structure
            
            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            debug_inc(stage_id, CODE_PARSE_TCP_SUCCESS);
            break;
        }
        case IPPROTO_UDP: {
            // Set ip_id exactly like regular UDP parsing
            key->udp.ip_id = ip.id;
            
            // Fragment handling exactly like regular parsing
            u16 frag_off_flags = ntohs(ip.frag_off);
            u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;  // More Fragments bit
            u16 frag_offset = frag_off_flags & 0x1FFF;          // Fragment offset (8-byte units)
            u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;
            
            if (is_fragment) {
                key->udp.frag_off = frag_offset * 8;
                if (frag_offset == 0) {
                    // First fragment - parse UDP header
                    struct udphdr udp;
                    if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
                        key->udp.src_port = udp.source;
                        key->udp.dst_port = udp.dest;
                    } else {
                        key->udp.src_port = 0;
                        key->udp.dst_port = 0;
                    }
                } else {
                    // Subsequent fragments - no UDP header
                    key->udp.src_port = 0;
                    key->udp.dst_port = 0;
                }
            } else {
                key->udp.frag_off = 0;
                struct udphdr udp;
                if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) < 0) {
                    return 0;
                }
                key->udp.src_port = udp.source;
                key->udp.dst_port = udp.dest;
            }
            
            // Apply port filters only if not fragmented or is first fragment
            if (!is_fragment || frag_offset == 0) {
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                    return 0;
                }
            }
            
            debug_inc(stage_id, CODE_PARSE_UDP_SUCCESS);
            break;
        }
        default:
            return 0;
    }
    
    debug_inc(stage_id, CODE_PARSE_SUCCESS);
    return 1;
}

static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    debug_inc(stage_id, CODE_PARSE_ENTRY);
    
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) {
        return 0;
    }
    
    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;
    
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        debug_inc(stage_id, CODE_PARSE_PROTO_FILTER);
        // Track what protocol we're filtering out (only for TX0)
        if (stage_id == TX_STAGE_0) {
            proto_seen.increment(ip.protocol);
            if (ip.protocol == IPPROTO_ICMP) {
                debug_inc(stage_id, CODE_PROTO_ICMP);
            } else {
                debug_inc(stage_id, CODE_PROTO_OTHER);
            }
        }
        return 0;
    }
    
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    
    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (!parse_tcp_key(skb, key, stage_id)) return 0;
            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            debug_inc(stage_id, CODE_PARSE_TCP_SUCCESS);
            break;
        case IPPROTO_UDP:
            if (!parse_udp_key(skb, key, stage_id)) return 0;
            if (key->udp.frag_off == 0) { // Only apply port filter for non-fragments or first fragment
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                    return 0;
                }
            }
            debug_inc(stage_id, CODE_PARSE_UDP_SUCCESS);
            break;
        default:
            return 0;
    }
    
    debug_inc(stage_id, CODE_PARSE_SUCCESS);
    return 1;
}

// Event submission function
static __always_inline void submit_event(struct pt_regs *ctx, struct packet_key_t *key, struct flow_data_t *flow) {
    u32 map_key_zero = 0;
    struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
    if (!event_data_ptr) {
        return;
    }
    
    event_data_ptr->key = *key;
    if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow) != 0) {
        return;
    }
    
    events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
    // Note: PERF_SUBMIT events are tracked by the Python side, not here
}

// Common event handling function
static __always_inline void handle_stage_event(struct pt_regs *ctx, struct sk_buff *skb, u8 stage_id) {
    debug_inc(stage_id, CODE_HANDLE_ENTRY);
    
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, stage_id)) {
        return;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;
    
    // Flow creation for start stages
    if (stage_id == TX_STAGE_0 || stage_id == RX_STAGE_0) {
        debug_inc(stage_id, CODE_FLOW_CREATE);
        // debug_key(ctx, &key, stage_id);  // Temporarily disabled - too many events
        struct flow_data_t zero = {};
        flow_sessions.delete(&key);
        flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);
        if (!flow_ptr) {
            debug_inc(stage_id, CODE_FLOW_NOT_FOUND);
            return;
        }
        
        flow_ptr->first_seen_ns = current_ts;
        
        if (stage_id == TX_STAGE_0) {
            flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
            flow_ptr->saw_path1_start = 1;
        } else if (stage_id == RX_STAGE_0) {
            flow_ptr->p2_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p2_comm, sizeof(flow_ptr->p2_comm));
            flow_ptr->saw_path2_start = 1;
        }
        
        // Record interface name
        struct net_device *dev;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            if (stage_id == TX_STAGE_0) {
                bpf_probe_read_kernel_str(flow_ptr->p1_ifname, IFNAMSIZ, dev->name);
            } else {
                bpf_probe_read_kernel_str(flow_ptr->p2_ifname, IFNAMSIZ, dev->name);
            }
        }
        
        // Record protocol specific info
        if (key.protocol == IPPROTO_TCP) {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) == 0) {
                flow_ptr->tcp_flags = tcp.rst << 2 | tcp.syn << 1 | tcp.fin;
            }
        } else if (key.protocol == IPPROTO_UDP) {
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
                flow_ptr->udp_len = ntohs(udp.len);
            }
        }
        
    } else {
        debug_inc(stage_id, CODE_FLOW_LOOKUP);
        // debug_key(ctx, &key, stage_id);  // Temporarily disabled - too many events
        flow_ptr = flow_sessions.lookup(&key);
        if (!flow_ptr) {
            debug_inc(stage_id, CODE_FLOW_NOT_FOUND);
            return;
        }
    }
    
    debug_inc(stage_id, CODE_FLOW_FOUND);
    
    // Update timestamp if not already recorded
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
        flow_ptr->kstack_id[stage_id] = stack_id;
        
        // Mark end stages
        if (stage_id == TX_STAGE_6) {
            flow_ptr->saw_path1_end = 1;
        } else if (stage_id == RX_STAGE_6) {
            flow_ptr->saw_path2_end = 1;
        }
        
        flow_sessions.update(&key, flow_ptr);
    }
    
    // Check for complete paths and submit events
    bool path1_complete = (stage_id == TX_STAGE_6 && flow_ptr->saw_path1_start && flow_ptr->saw_path1_end);
    bool path2_complete = (stage_id == RX_STAGE_6 && flow_ptr->saw_path2_start && flow_ptr->saw_path2_end);
    
    if (path1_complete || path2_complete) {
        submit_event(ctx, &key, flow_ptr);
        flow_sessions.delete(&key);
    }
}

// Specialized event handling function for userspace SKB parsing
static __always_inline void handle_stage_event_userspace(struct pt_regs *ctx, struct sk_buff *skb, u8 stage_id) {
    debug_inc(stage_id, CODE_HANDLE_ENTRY);
    
    struct packet_key_t key = {};
    if (!parse_packet_key_userspace(skb, &key, stage_id)) {
        return;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;
    
    debug_inc(stage_id, CODE_FLOW_LOOKUP);
    flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        debug_inc(stage_id, CODE_FLOW_NOT_FOUND);
        return;
    }
    debug_inc(stage_id, CODE_FLOW_FOUND);
    
    // Update flow data 
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
        flow_ptr->kstack_id[stage_id] = stack_id;
        
        flow_sessions.update(&key, flow_ptr);
    }
}

// TX Direction Probes (System -> Physical) - based on design document

// Special parsing function for __tcp_transmit_skb stage using sock info
static __always_inline int parse_tcp_transmit_skb(
    struct sock *sk,
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    debug_inc(stage_id, CODE_PARSE_ENTRY);
    
    if (!sk || !skb) {
        return 0;
    }
    
    // Get IP info from inet_sock structure
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) {
        return 0;
    }
    
    // Read source and destination IPs from sock
    __be32 src_ip, dst_ip;
    if (bpf_probe_read_kernel(&src_ip, sizeof(src_ip), &inet->inet_saddr) != 0 ||
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &inet->inet_daddr) != 0) {
        return 0;
    }
    
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->protocol = IPPROTO_TCP;  // We know it's TCP
    
    // Apply IP filters
    if (SRC_IP_FILTER != 0 && src_ip != SRC_IP_FILTER && dst_ip != SRC_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    if (DST_IP_FILTER != 0 && src_ip != DST_IP_FILTER && dst_ip != DST_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    
    // Get TCP port info from inet_sock
    __be16 src_port, dst_port;
    if (bpf_probe_read_kernel(&src_port, sizeof(src_port), &inet->inet_sport) != 0 ||
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &inet->inet_dport) != 0) {
        return 0;
    }
    
    key->tcp.src_port = src_port;
    key->tcp.dst_port = dst_port;
    
    // Apply port filters
    if (SRC_PORT_FILTER != 0 && src_port != htons(SRC_PORT_FILTER) && dst_port != htons(SRC_PORT_FILTER)) {
        debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
        return 0;
    }
    if (DST_PORT_FILTER != 0 && src_port != htons(DST_PORT_FILTER) && dst_port != htons(DST_PORT_FILTER)) {
        debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
        return 0;
    }
    
    // TCP sequence number removed from key structure
    // Flow tracking uses only connection 5-tuple for consistency
    
    // Get payload length from skb
    __u32 skb_len = 0;
    if (bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        // Estimate TCP header size (typically 20-60 bytes)
        __u32 estimated_tcp_header = 20;  // Minimum TCP header size
        __u32 payload_len = (skb_len > estimated_tcp_header) ? (skb_len - estimated_tcp_header) : 0;
        
        // Payload length removed from key structure
        // TX0 uses estimation while other stages use exact calculation
    } else {
        // Payload length removed from key structure
    }
    
    debug_inc(stage_id, CODE_PARSE_TCP_SUCCESS);
    debug_inc(stage_id, CODE_PARSE_SUCCESS);
    return 1;
}

// TX Stage 0: __tcp_transmit_skb - TCP transmission entry point  
// At this stage, use sock structure info instead of SKB headers
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, 
                               int clone_it, gfp_t gfp_mask, u32 rcv_nxt) {
    debug_inc(TX_STAGE_0, CODE_PROBE_ENTRY);
    
    if (DIRECTION_FILTER == 2) { // incoming only
        debug_inc(TX_STAGE_0, CODE_DIRECTION_FILTER);
        return 0;
    }
    
    // Only handle TCP protocol
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) {
        return 0;
    }
    
    debug_inc(TX_STAGE_0, CODE_HANDLE_CALLED);
    debug_inc(TX_STAGE_0, CODE_HANDLE_ENTRY);
    
    struct packet_key_t key = {};
    if (!parse_tcp_transmit_skb(sk, skb, &key, TX_STAGE_0)) {
        return 0;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    // Flow creation for TX stage 0
    debug_inc(TX_STAGE_0, CODE_FLOW_CREATE);
    // debug_key(ctx, &key, TX_STAGE_0);  // Temporarily disabled - too many events
    struct flow_data_t zero = {};
    flow_sessions.delete(&key);
    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);
    if (!flow_ptr) {
        debug_inc(TX_STAGE_0, CODE_FLOW_NOT_FOUND);
        return 0;
    }
    
    debug_inc(TX_STAGE_0, CODE_FLOW_FOUND);
    
    flow_ptr->first_seen_ns = current_ts;
    flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
    flow_ptr->saw_path1_start = 1;
    
    // Record interface name from sock
    if (sk->sk_bound_dev_if) {
        // Try to get interface name - this is more complex, for now just record ifindex if needed
    }
    
    // Record timestamp
    flow_ptr->ts[TX_STAGE_0] = current_ts;
    flow_ptr->skb_ptr[TX_STAGE_0] = (u64)skb;
    flow_ptr->kstack_id[TX_STAGE_0] = stack_id;
    
    flow_sessions.update(&key, flow_ptr);
    
    return 0;
}

// TX Stage 1: internal_dev_xmit - Internal device transmission
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 2) return 0; // incoming only
    handle_stage_event(ctx, skb, TX_STAGE_1);
    return 0;
}

// OVS processing stages (common for TX/RX) - from icmp_rtt_latency.py
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) { // outgoing or both
        handle_stage_event(ctx, skb, TX_STAGE_2);
    }
    if (DIRECTION_FILTER != 1) { // incoming or both
        handle_stage_event(ctx, skb, RX_STAGE_2);
    }
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) { // outgoing or both
        handle_stage_event(ctx, skb, TX_STAGE_3);
    }
    if (DIRECTION_FILTER != 1) { // incoming or both
        handle_stage_event(ctx, skb, RX_STAGE_3);
    }
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    if (DIRECTION_FILTER != 2) { // outgoing or both
        handle_stage_event_userspace(ctx, skb, TX_STAGE_4);
    }
    if (DIRECTION_FILTER != 1) { // incoming or both
        handle_stage_event_userspace(ctx, skb, RX_STAGE_4);
    }
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    if (DIRECTION_FILTER != 2) { // outgoing or both
        handle_stage_event(ctx, skb, TX_STAGE_5);
    }
    if (DIRECTION_FILTER != 1) { // incoming or both
        handle_stage_event(ctx, skb, RX_STAGE_5);
    }
    return 0;
}

// TX Stage 6: dev_queue_xmit - Physical interface transmission
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!is_target_ifindex(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0; // incoming only
    handle_stage_event(ctx, skb, TX_STAGE_6);
    return 0;
}

// RX Direction Probes (Physical -> System)

// RX Stage 0: __netif_receive_skb - Physical interface reception
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!is_target_ifindex(skb)) return 0;
    if (DIRECTION_FILTER == 1) return 0; // outgoing only
    handle_stage_event(ctx, skb, RX_STAGE_0);
    return 0;
}

// RX Stage 1: netdev_frame_hook - Network frame processing hook
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }
    
    if (DIRECTION_FILTER != 1) { // incoming or both
        handle_stage_event(ctx, skb, RX_STAGE_1);
    }
    return 0;
}

// RX Stage 6: Protocol-specific reception - tcp_v4_rcv for TCP
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 1) return 0; // outgoing only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

// RX Stage 6: Protocol-specific reception - udp_rcv for UDP  
int kprobe____udp4_lib_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct udp_table *udptable) {
    if (DIRECTION_FILTER == 1) return 0; // outgoing only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_UDP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

"""

# Constants
MAX_STAGES = 14
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# Protocol-specific structures - from vm_network_latency.py
class TCPData(ctypes.Structure):
    _fields_ = [
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("payload_len", ctypes.c_uint16)
    ]

class UDPData(ctypes.Structure):
    _fields_ = [
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("ip_id", ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16)
    ]

class ProtocolUnion(ctypes.Union):
    _fields_ = [
        ("tcp", TCPData),
        ("udp", UDPData)
    ]

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
        ("proto_data", ProtocolUnion),
        ("first_seen_ns", ctypes.c_uint64)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("first_seen_ns", ctypes.c_uint64),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("kstack_id", ctypes.c_int * MAX_STAGES),
        ("p1_pid", ctypes.c_uint32),
        ("p1_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p1_ifname", ctypes.c_char * IFNAMSIZ),
        ("p2_pid", ctypes.c_uint32),
        ("p2_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p2_ifname", ctypes.c_char * IFNAMSIZ),
        ("tcp_flags", ctypes.c_uint8),
        ("udp_len", ctypes.c_uint16),
        ("saw_path1_start", ctypes.c_uint8, 1),
        ("saw_path1_end", ctypes.c_uint8, 1),
        ("saw_path2_start", ctypes.c_uint8, 1),
        ("saw_path2_end", ctypes.c_uint8, 1)
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("data", FlowData)
    ]

# Helper Functions - from icmp_rtt_latency.py
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

def format_latency(ts_start, ts_end):
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0:
        return " N/A ".rjust(10)
    
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(10)

def print_path_latencies(flow, start_stage, end_stage, path_type):
    """Print latencies for TX or RX path, handling skipped stages intelligently"""
    
    # Find actual stages with non-zero timestamps
    active_stages = []
    for i in range(start_stage, end_stage + 1):
        if flow.ts[i] > 0:
            active_stages.append(i)
    
    if len(active_stages) < 2:
        print("  No latency data available")
        return
    
    # Print stage-to-stage latencies for consecutive active stages
    for i in range(len(active_stages) - 1):
        stage1 = active_stages[i]
        stage2 = active_stages[i + 1]
        latency = format_latency(flow.ts[stage1], flow.ts[stage2])
        print("  [%d->%d] %s -> %s: %s us" % (
            stage1, stage2, get_stage_name(stage1), get_stage_name(stage2), latency
        ))
    
    # Print total path latency
    if flow.ts[active_stages[0]] > 0 and flow.ts[active_stages[-1]] > 0:
        total_latency = format_latency(flow.ts[active_stages[0]], flow.ts[active_stages[-1]])
        print("  Total %s Latency: %s us" % (path_type, total_latency))

def get_stage_name(stage_id):
    """Get human-readable stage name"""
    stage_names = {
        0: "TX_S0_ip_send_skb",           1: "TX_S1_internal_dev_xmit",
        2: "TX_S2_ovs_dp_process",        3: "TX_S3_ovs_dp_upcall",
        4: "TX_S4_ovs_flow_key_extract",  5: "TX_S5_ovs_vport_send",
        6: "TX_S6_dev_queue_xmit",
        7: "RX_S0_netif_receive_skb",     8: "RX_S1_netdev_frame_hook",
        9: "RX_S2_ovs_dp_process",        10: "RX_S3_ovs_dp_upcall",
        11: "RX_S4_ovs_flow_key_extract", 12: "RX_S5_ovs_vport_send",
        13: "RX_S6_tcp_v4_rcv/udp_rcv"
    }
    return stage_names.get(stage_id, "Unknown_%d" % stage_id)

def print_event(cpu, data, size):
    """Print packet latency event"""
    global args
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    protocol_names = {6: "TCP", 17: "UDP"}
    protocol_name = protocol_names.get(key.protocol, "Unknown")
    
    direction_str = "Outgoing (System -> Remote)" if args.direction == "outgoing" else "Incoming (Remote -> System)"
    
    print("=== System Network %s Latency Trace: %s ===" % (protocol_name, time_str))
    print("Direction: %s" % direction_str)
    print("Flow: %s -> %s (%s)" % (
        format_ip(key.src_ip), format_ip(key.dst_ip), protocol_name
    ))
    
    if key.protocol == 6:  # TCP
        tcp_flags_str = ""
        if flow.tcp_flags & 0x01: tcp_flags_str += "FIN "
        if flow.tcp_flags & 0x02: tcp_flags_str += "SYN "
        if flow.tcp_flags & 0x04: tcp_flags_str += "RST "
        tcp_flags_str = tcp_flags_str.strip() if tcp_flags_str else "ACK"
        
        print("TCP Segment: %s:%d -> %s:%d (seq=%u, payload=%d bytes, flags=%s)" % (
            format_ip(key.src_ip), socket.ntohs(key.proto_data.tcp.src_port),
            format_ip(key.dst_ip), socket.ntohs(key.proto_data.tcp.dst_port),
            socket.ntohl(key.proto_data.tcp.seq), key.proto_data.tcp.payload_len,
            tcp_flags_str
        ))
    elif key.protocol == 17:  # UDP
        if key.proto_data.udp.frag_off > 0:
            print("UDP Fragment: %s:%d -> %s:%d (ip_id=%d, frag_offset=%d bytes, len=%d)" % (
                format_ip(key.src_ip), socket.ntohs(key.proto_data.udp.src_port),
                format_ip(key.dst_ip), socket.ntohs(key.proto_data.udp.dst_port),
                key.proto_data.udp.ip_id, key.proto_data.udp.frag_off, flow.udp_len
            ))
        else:
            print("UDP Packet: %s:%d -> %s:%d (ip_id=%d, len=%d bytes, no fragmentation)" % (
                format_ip(key.src_ip), socket.ntohs(key.proto_data.udp.src_port),
                format_ip(key.dst_ip), socket.ntohs(key.proto_data.udp.dst_port),
                key.proto_data.udp.ip_id, flow.udp_len
            ))
    
    # Show process info
    if flow.p1_pid > 0:
        print("TX Process: PID=%d COMM=%s IF=%s" % (
            flow.p1_pid, 
            flow.p1_comm.decode('utf-8', 'replace'),
            flow.p1_ifname.decode('utf-8', 'replace')
        ))
    if flow.p2_pid > 0:
        print("RX Process: PID=%d COMM=%s IF=%s" % (
            flow.p2_pid, 
            flow.p2_comm.decode('utf-8', 'replace'),
            flow.p2_ifname.decode('utf-8', 'replace')
        ))
    
    # Show TX path if direction is outgoing or both
    if direction_filter in [0, 1]:  # both or outgoing
        print("\nTX Path Latencies (us):")
        print_path_latencies(flow, 0, 6, "TX")
    
    # Show RX path if direction is incoming or both  
    if direction_filter in [0, 2]:  # both or incoming
        print("\nRX Path Latencies (us):")
        print_path_latencies(flow, 7, 13, "RX")
    
    # Show total one-way latency if both paths are available
    if (flow.ts[0] > 0 and flow.ts[13] > 0):  # TX start to RX end
        total_latency = format_latency(flow.ts[0], flow.ts[13])
        print("\nTotal One-Way Latency: %s us" % total_latency)
    elif (flow.ts[7] > 0 and flow.ts[6] > 0):  # RX start to TX end (for incoming)
        total_latency = format_latency(flow.ts[7], flow.ts[6])
        print("\nTotal One-Way Latency: %s us" % total_latency)
    
    print("\n" + "="*80 + "\n")

# Global list to store key debug events for analysis
key_debug_data = []

def print_key_debug(cpu, data, size):
    """Print key debug event for flow matching analysis"""
    import ctypes
    import socket
    
    # Define the structure to match the C struct
    class KeyDebugEvent(ctypes.Structure):
        _fields_ = [
            ("stage_id", ctypes.c_uint8),
            ("src_ip", ctypes.c_uint32),
            ("dst_ip", ctypes.c_uint32),
            ("src_port", ctypes.c_uint16),
            ("dst_port", ctypes.c_uint16),
            ("tcp_seq", ctypes.c_uint32),
            ("payload_len", ctypes.c_uint8),
            ("timestamp", ctypes.c_uint32),
        ]
    
    event = ctypes.cast(data, ctypes.POINTER(KeyDebugEvent)).contents
    
    # Store for analysis
    key_debug_data.append({
        'stage_id': event.stage_id,
        'src_ip': format_ip(event.src_ip),
        'dst_ip': format_ip(event.dst_ip),
        'src_port': socket.ntohs(event.src_port),
        'dst_port': socket.ntohs(event.dst_port),
        'tcp_seq': event.tcp_seq,
        'payload_len': event.payload_len,
        'timestamp': event.timestamp
    })
    
    # Only print key info for first 5 entries to avoid spam
    if len(key_debug_data) <= 5:
        print("KEY_DEBUG: Stage %d: %s:%d -> %s:%d seq=0x%08x len=%d ts=%d" % (
            event.stage_id,
            format_ip(event.src_ip), socket.ntohs(event.src_port),
            format_ip(event.dst_ip), socket.ntohs(event.dst_port),
            event.tcp_seq, event.payload_len, event.timestamp
        ))

def analyze_key_consistency():
    """Analyze key consistency between stages"""
    if not key_debug_data:
        print("\nNo key debug data available for analysis")
        return
    
    print("\n=== Key Consistency Analysis ===")
    
    # Group by similar connection tuples (ignoring seq and payload_len for now)
    connections = {}
    for entry in key_debug_data:
        key = (entry['src_ip'], entry['dst_ip'], entry['src_port'], entry['dst_port'])
        if key not in connections:
            connections[key] = []
        connections[key].append(entry)
    
    print("Found %d unique connections:" % len(connections))
    
    for i, (conn_key, stages) in enumerate(connections.items()):
        if i >= 5:  # Limit to first 5 connections for readability
            break
            
        print("\nConnection %d: %s:%d -> %s:%d" % (i+1, conn_key[0], conn_key[2], conn_key[1], conn_key[3]))
        
        # Sort by stage_id
        stages.sort(key=lambda x: x['stage_id'])
        
        # Check for differences in seq and payload_len
        for stage in stages:
            print("  Stage %d: seq=0x%08x len=%d" % (stage['stage_id'], stage['tcp_seq'], stage['payload_len']))

def print_debug_statistics(b):
    """Print comprehensive debug statistics - from bcc-debug-framework.md"""
    
    # Define stage names
    stage_names = {
        0: "TX0___tcp_transmit_skb",
        1: "TX1_internal_dev_xmit", 
        2: "TX2_ovs_dp_process_packet",
        3: "TX3_ovs_dp_upcall",
        4: "TX4_ovs_flow_key_extract_userspace",
        5: "TX5_ovs_vport_send",
        6: "TX6_dev_queue_xmit",
        7: "RX0___netif_receive_skb",
        8: "RX1_netdev_frame_hook",
        9: "RX2_ovs_dp_process_packet", 
        10: "RX3_ovs_dp_upcall",
        11: "RX4_ovs_flow_key_extract_userspace",
        12: "RX5_ovs_vport_send",
        13: "RX6_tcp_v4_rcv/udp_rcv"
    }
    
    # Define code point names
    code_names = {
        1: "PROBE_ENTRY",
        2: "INTERFACE_FILTER", 
        3: "DIRECTION_FILTER",
        4: "HANDLE_CALLED",
        5: "HANDLE_ENTRY",
        6: "PARSE_ENTRY",
        7: "PARSE_SUCCESS",
        8: "PARSE_IP_FILTER",
        9: "PARSE_PROTO_FILTER",
        10: "PARSE_PORT_FILTER",
        11: "PARSE_TCP_SUCCESS",
        12: "PARSE_UDP_SUCCESS", 
        14: "FLOW_CREATE",
        15: "FLOW_LOOKUP",
        16: "FLOW_FOUND",
        17: "FLOW_NOT_FOUND",
        18: "SKB_READ_FAIL",
        19: "PERF_SUBMIT",
        20: "IP_HDR_ERROR",
        21: "PROTO_ICMP",
        22: "PROTO_OTHER"
    }
    
    print("\n=== Debug Statistics ===")
    print("\nStage Statistics:")
    stage_stats = b["debug_stage_stats"]
    for k, v in sorted(stage_stats.items(), key=lambda x: x[0].value):
        if v.value > 0:
            stage_id = k.value >> 8
            code_point = k.value & 0xFF
            stage_name = stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)
            code_name = code_names.get(code_point, "CODE_%d" % code_point)
            print("  %s.%s: %d" % (stage_name, code_name, v.value))
    
    print("\nInterface Debug:")
    interface_debug = b["interface_debug"]
    if interface_debug[0].value > 0:
        print("  NULL_DEV: %d" % interface_debug[0].value)
    if interface_debug[1].value > 0:
        print("  READ_FAIL: %d" % interface_debug[1].value)
    
    print("\nInterface indices seen:")
    ifindex_hist = b["ifindex_seen"]
    for k, v in ifindex_hist.items():
        if v.value > 0:
            print("  ifindex %d: %d packets" % (k.value, v.value))
    
    # Print protocol distribution at TX0
    print("\nProtocols filtered at TX0:")
    proto_hist = b["proto_seen"]
    proto_names = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF", 132: "SCTP"}
    for k, v in sorted(proto_hist.items(), key=lambda x: x[1].value, reverse=True):
        if v.value > 0:
            proto_name = proto_names.get(k.value, "Protocol_%d" % k.value)
            print("  %s: %d packets" % (proto_name, v.value))

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="System Network TCP/UDP Latency Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor TCP traffic (most reliable packet-level tracking):
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --protocol tcp --direction outgoing \\
                  --phy-interface enp94s0f0np0

  Monitor UDP traffic (including fragmentation handling):
    sudo %(prog)s --src-ip 70.0.0.33 --dst-port 53 \\
                  --protocol udp --direction both \\
                  --phy-interface enp94s0f0np0

  Monitor specific TCP connection packet-level latency:
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --src-port 12345 --dst-port 80 \\
                  --protocol tcp --direction both \\
                  --phy-interface enp94s0f0np0

  Monitor all TCP/UDP protocols:
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --protocol all \\
                  --phy-interface enp94s0f0np0
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'all'], 
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--direction', type=str, choices=['outgoing', 'incoming', 'both'], 
                        default='both', help='Direction filter (default: both)')
    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface to monitor (e.g., enp94s0f0np0)')
    
    args = parser.parse_args()
    
    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    
    protocol_map = {'tcp': 6, 'udp': 17, 'all': 0}
    protocol_filter = protocol_map[args.protocol]
    
    direction_map = {'outgoing': 1, 'incoming': 2, 'both': 0}
    direction_filter = direction_map[args.direction]
    
    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        ifindex1 = get_if_index(phy_interfaces[0].strip())
        ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)
    
    print("=== System Network TCP/UDP Latency Tracer ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s" % args.direction.upper())
    if args.src_ip:
        print("Source IP filter: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, ifindex1, ifindex2))
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, ifindex1, ifindex2, direction_filter
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event)
    # b["key_debug_events"].open_perf_buffer(print_key_debug)  # Temporarily disabled
    
    print("\nTracing system network TCP/UDP latency... Hit Ctrl-C to end.")
    print("Generate some TCP/UDP traffic to see results...\n")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
        print_debug_statistics(b)
        analyze_key_consistency()
    finally:
        print("Exiting.")