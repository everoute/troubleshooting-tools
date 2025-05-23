#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# 注意事项：
#   1) 如果是 oe 系统:
#      a) 请修改第一行 python2 为 python3:  #!/usr/bin/env python2  ->  #!/usr/bin/env python3
#      b) 修改 from bcc import BPF 为 from bpfcc import BPF
#   2) 如果是 el7 系统:
#      a) 安装 bcc 和 python-bcc 0.21.0:
# curl -fLO http://192.168.24.6/tmp/bpftools/x86_64/bcc-0.21.0-1.el7.x86_64.rpm
# curl -fLO http://192.168.24.6/tmp/bpftools/noarch/python-bcc-0.21.0-1.el7.noarch.rpm 
# rpm -ivh bcc-0.21.0-1.el7.x86_64.rpm python-bcc-0.21.0-1.el7.noarch.rpm --force 

# 使用说明:
# ./system_network_latency.py --help
#
# This tool traces unidirectional latency for TCP, UDP, and ICMP packets 
# through the Linux network stack and OVS. It can filter by L4 properties 
# such as ports (for TCP/UDP) or type/id/seq (for ICMP).

# optional arguments:
#   -h, --help            show this help message and exit
#   --src-ip SRC_IP       Source IP to filter on. For "outgoing" trace, this is 
#                         the traced packet source. For "incoming" trace, this 
#                         is the local IP receiving the packet.
#   --dst-ip DST_IP       Destination IP to filter on. For "outgoing" trace, 
#                         this is the traced packet destination. For "incoming" 
#                         trace, this is the remote IP sending the packet.
#   --protocol {tcp,udp,icmp}
#                         Protocol to trace.
#   --sport SPORT         Source port for TCP/UDP (0 for wildcard).
#   --dport DPORT         Destination port for TCP/UDP (0 for wildcard).
#   --icmp-type ICMP_TYPE
#                         ICMP type (-1 for wildcard).
#   --icmp-id ICMP_ID     ICMP ID (0 for wildcard).
#   --icmp-seq ICMP_SEQ   ICMP sequence number (0 for wildcard).
#   --phy-iface1 PHY_IFACE1
#                         First physical interface to monitor (e.g., for
#                         dev_queue_xmit on outgoing path, or __netif_receive_skb
#                         on incoming path).
#   --phy-iface2 PHY_IFACE2
#                         Second physical interface to monitor. If not provided,
#                         phy-iface1 will be used for both checks (effectively
#                         monitoring a single interface).
#   --latency-ms LATENCY_MS
#                         Minimum unidirectional latency threshold in ms to report
#                         (default: 0, report all).
#   --direction {outgoing,incoming}
#                         Direction of packet trace: "outgoing" (local host to remote) 
#                         or "incoming" (remote host to local). Default: outgoing.
#   --disable-kernel-stacks
#                         Disable printing of kernel stack traces for each
#                         stage.

# This tool traces the unidirectional latency of TCP, UDP, or ICMP packets:
# - TX path (outgoing): Application -> Protocol Stack -> OVS Internal Port -> OVS Kernel Module -> Physical NIC -> External
# - RX path (incoming): External -> Physical NIC -> OVS Kernel Module -> OVS Internal Port -> Protocol Stack -> Application
#
# It identifies individual packets matching the specified filters and reports 
# segment latencies along their path through the host.
#
# 以下为中文使用示例：
# 1. 使用方式及参数示例：
#    1.1) 追踪从 192.168.1.10 发往 5.6.7.8 的 TCP 流量 (端口 12345 -> 80) 的出向延迟:
#    sudo ./system_network_latency.py --protocol tcp --src-ip 192.168.1.10 --dst-ip 5.6.7.8 \
#                                     --sport 12345 --dport 80 \
#                                     --phy-iface1 eth0 --direction outgoing
#
#    1.2) 追踪从外部到本机 192.168.1.10 的 UDP 流量 (目标端口 53) 的入向延迟:
#    sudo ./system_network_latency.py --protocol udp --src-ip 192.168.1.10 --dst-ip 5.6.7.8 \
#                                     --dport 53 --phy-iface1 eth0 --direction incoming
#
#    1.3) 追踪从 192.168.1.10 发往 5.6.7.8 的 ICMP Echo 请求 (Type 8) 的出向延迟:
#    sudo ./system_network_latency.py --protocol icmp --src-ip 192.168.1.10 --dst-ip 5.6.7.8 \
#                                     --icmp-type 8 --phy-iface1 eth0 --direction outgoing
#
# 2. 输出信息说明：
#    - 单向路径各个阶段的分段延迟，单位微秒
#    - 总单向延迟（STAGE_0 起始到 STAGE_6 结束），单位微秒
#    - SKB 指针地址信息及可选的内核栈回溯，用于深度排查


from bcc import BPF
#from bpfcc import BPF
from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl # Needed for ioctl

# --- BPF Program ---
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
#define LATENCY_THRESHOLD_NS %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define TRACE_DIRECTION %d // 0 for Outgoing (default), 1 for Incoming

// New L4 Filters
#define PROTO_FILTER %d 
#define SPORT_FILTER %d // 0 means wildcard
#define DPORT_FILTER %d // 0 means wildcard
#define ICMP_TYPE_FILTER %d // -1 means wildcard
#define ICMP_ID_FILTER %d   // 0 means wildcard
#define ICMP_SEQ_FILTER %d  // 0 means wildcard

// Define stages for a unidirectional path
#define STAGE_0    0
#define STAGE_1    1
#define STAGE_2    2
#define STAGE_3    3
#define STAGE_4    4
#define STAGE_5    5
#define STAGE_6    6

#define MAX_UNIDIR_STAGES        7
#define MAX_STAGES               MAX_UNIDIR_STAGES // Updated to reflect unidirectional
#define IFNAMSIZ                 16
#define TASK_COMM_LEN            16


// Packet key structure to uniquely identify and match ICMP request/reply pairs
// Note: sip and dip in this key will be canonical (SRC_IP_FILTER, DST_IP_FILTER)
struct packet_key_t {
    __be32 sip;
    __be32 dip;
    u8 proto;
    __be16 ip_id; // To store the IP ID
    __u16 frag_offset; // To store fragment offset (0 for unfragmented or first fragment)

    union {
        struct {
            __be16 sport;
            __be16 dport;
        } tcp_udp;
        struct {
            u8 type;
            __be16 id;
            __be16 seq;
        } icmp;
    } l4;
};

// Structure to track unidirectional flow data and timestamps
struct flow_data_t {
    u64 ts[MAX_UNIDIR_STAGES];
    u64 skb_ptr[MAX_UNIDIR_STAGES];
    int kstack_id[MAX_UNIDIR_STAGES];
    
    // Tracking info for the path
    u32 pid; 
    char comm[TASK_COMM_LEN]; 
    char ifname[IFNAMSIZ]; 
        
    // L4 type info (e.g. ICMP type, or 0 for TCP/UDP)
    u8 l4_type; 
    
    // Flags for path tracking
    u8 saw_path_start:1;
    u8 saw_path_end:1;
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

// Helper function to check if an interface index matches our targets
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}

// Function to manually parse SKB data coming from userspace (different structure)
static __always_inline int parse_packet_key_userspace(struct sk_buff *skb, struct packet_key_t *key, 
                                                     int path_is_primary) { // Removed u8 *icmp_type_out
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
    
    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    // u8 expected_icmp_type_val; // Removed ICMP-specific type check for broader L4

    if (path_is_primary) { 
        if (!(actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)) return 0;
        // expected_icmp_type_val = ICMP_ECHO; // Removed
    } else { 
        if (!(actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)) return 0;
        // expected_icmp_type_val = ICMP_ECHOREPLY; // Removed
    }

    // Protocol filter
    if (ip.protocol != PROTO_FILTER) {
        return 0;
    }
    
    // Store IP ID and Fragment Offset
    key->ip_id = ip.id;
    u16 frag_off_val_userspace = ntohs(ip.frag_off);
    key->frag_offset = frag_off_val_userspace & 0x1FFF; // IP_OFFSET mask

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }
    unsigned int trans_offset = net_offset + (ip_ihl * 4);

    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcph;
            if (bpf_probe_read_kernel(&tcph, sizeof(tcph), skb_head + trans_offset) < 0) {
                return 0;
            }
            if (SPORT_FILTER != 0 && tcph.source != htons(SPORT_FILTER)) {
                return 0;
            }
            if (DPORT_FILTER != 0 && tcph.dest != htons(DPORT_FILTER)) {
                return 0;
            }
            key->l4.tcp_udp.sport = tcph.source;
            key->l4.tcp_udp.dport = tcph.dest;
            key->proto = IPPROTO_TCP;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr udph;
            if (bpf_probe_read_kernel(&udph, sizeof(udph), skb_head + trans_offset) < 0) {
                return 0;
            }
            if (SPORT_FILTER != 0 && udph.source != htons(SPORT_FILTER)) {
                return 0;
            }
            if (DPORT_FILTER != 0 && udph.dest != htons(DPORT_FILTER)) {
                return 0;
            }
            key->l4.tcp_udp.sport = udph.source;
            key->l4.tcp_udp.dport = udph.dest;
            key->proto = IPPROTO_UDP;
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmph;
            if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset) < 0) {
                return 0;
            }
            // Removed: if (icmph.type != expected_icmp_type_val) return 0;
            // *icmp_type_out = icmph.type; // Output param removed
            key->l4.icmp.type = icmph.type;
            key->l4.icmp.id = icmph.un.echo.id;
            key->l4.icmp.seq = icmph.un.echo.sequence;
            key->proto = IPPROTO_ICMP;
            break;
        }
        default:
            return 0; // Not a targeted protocol (or PROTO_FILTER mismatch handled earlier)
    }
    
    key->sip = SRC_IP_FILTER; 
    key->dip = DST_IP_FILTER;
    // key->proto is set in switch cases
    // L4 specific fields (id, seq for icmp or ports for tcp/udp) are set in switch cases

    return 1;
}

static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key, 
                                           int path_is_primary, u8 current_stage_id) {
    // User-space parsing is triggered by specific stages, check current_stage_id
    if (current_stage_id == STAGE_4) { // Assuming STAGE_4 is ovs_flow_key_extract_userspace
         return parse_packet_key_userspace(skb, key, path_is_primary);
    }
    
    if (skb == NULL) {
        return 0;
    }

    unsigned char *head;
    u16 network_header_offset; 
    u16 transport_header_offset_val; // Renamed to avoid conflict with skb field if any

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset_val, sizeof(transport_header_offset_val), &skb->transport_header) < 0) {
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048 ) { 
        return 0; 
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    // u8 expected_icmp_type_val; // Removed for general L4 parsing

    if (path_is_primary) { 
        if (!(actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)) return 0;
        // expected_icmp_type_val = ICMP_ECHO; // Removed
    } else { 
        if (!(actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)) return 0;
        // expected_icmp_type_val = ICMP_ECHOREPLY; // Removed
    }

    // Protocol filter
    if (ip.protocol != PROTO_FILTER) {
        return 0;
    }
    
    // Store IP ID and Fragment Offset
    key->ip_id = ip.id; // network byte order
    u16 frag_off_val_kernel = ntohs(ip.frag_off);
    key->frag_offset = frag_off_val_kernel & 0x1FFF; // IP_OFFSET mask
    
    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {
        return 0;
    }

    // Calculate L4 header offset
    // If skb->transport_header is not set by the kernel hook, calculate it.
    if (transport_header_offset_val == 0 || transport_header_offset_val == (u16)~0U || transport_header_offset_val == network_header_offset) {
        transport_header_offset_val = network_header_offset + (ip_ihl * 4);
    }

    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcph;
            if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header_offset_val) < 0) {
                return 0;
            }
            if (SPORT_FILTER != 0 && tcph.source != htons(SPORT_FILTER)) {
                return 0;
            }
            if (DPORT_FILTER != 0 && tcph.dest != htons(DPORT_FILTER)) {
                return 0;
            }
            key->l4.tcp_udp.sport = tcph.source;
            key->l4.tcp_udp.dport = tcph.dest;
            key->proto = IPPROTO_TCP;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr udph;
            if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset_val) < 0) {
                return 0;
            }
            if (SPORT_FILTER != 0 && udph.source != htons(SPORT_FILTER)) {
                return 0;
            }
            if (DPORT_FILTER != 0 && udph.dest != htons(DPORT_FILTER)) {
                return 0;
            }
            key->l4.tcp_udp.sport = udph.source;
            key->l4.tcp_udp.dport = udph.dest;
            key->proto = IPPROTO_UDP;
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmph;
            if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset_val) < 0) {
                return 0;
            }
            // Removed: if (icmph.type != expected_icmp_type_val) return 0;
            // *icmp_type_out = icmph.type; // Output param removed
            key->l4.icmp.type = icmph.type;
            key->l4.icmp.id = icmph.un.echo.id;
            key->l4.icmp.seq = icmph.un.echo.sequence;
            key->proto = IPPROTO_ICMP;
            break;
        }
        default:
            return 0; // Not a targeted protocol (or PROTO_FILTER mismatch handled earlier)
    }
    
    key->sip = SRC_IP_FILTER; 
    key->dip = DST_IP_FILTER;
    // key->proto is set in switch cases
    // L4 specific fields (id, seq for icmp or ports for tcp/udp) are set in switch cases

    return 1;
}

static __always_inline void handle_event(struct pt_regs *ctx, struct sk_buff *skb, 
                                         u64 current_stage_id, struct packet_key_t *parsed_packet_key) { 
    if (skb == NULL) {
        return;
    }

    // Interface filtering for STAGE_0 (incoming) and STAGE_6 (outgoing)
    if (current_stage_id == STAGE_0 && TRACE_DIRECTION == 1 && !is_target_ifindex(skb)) {
        return;
    }
    if (current_stage_id == STAGE_6 && TRACE_DIRECTION == 0 && !is_target_ifindex(skb)) {
        return;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;

    if (current_stage_id == STAGE_0) {
        struct flow_data_t zero = {}; 
        flow_sessions.delete(parsed_packet_key);
        flow_ptr = flow_sessions.lookup_or_try_init(parsed_packet_key, &zero);
    } else {
        flow_ptr = flow_sessions.lookup(parsed_packet_key);
    }

    if (!flow_ptr) {
        return; 
    }

    // Record timestamp if not already set for this stage
    // Ensure current_stage_id is within bounds for the arrays
    if (current_stage_id < MAX_UNIDIR_STAGES && flow_ptr->ts[current_stage_id] == 0) { 
        flow_ptr->ts[current_stage_id] = current_ts;
        flow_ptr->skb_ptr[current_stage_id] = (u64)skb;
        flow_ptr->kstack_id[current_stage_id] = stack_id;

        if (current_stage_id == STAGE_0) { 
            flow_ptr->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->comm, sizeof(flow_ptr->comm));
            
            struct net_device *dev;
            if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
                bpf_probe_read_kernel_str(flow_ptr->ifname, IFNAMSIZ, dev->name);
            } else {
                char unk[] = "unknown";
                __builtin_memcpy(flow_ptr->ifname, unk, sizeof(unk)); 
            }

            if (parsed_packet_key->proto == IPPROTO_ICMP) {
                flow_ptr->l4_type = parsed_packet_key->l4.icmp.type;
            } else {
                flow_ptr->l4_type = 0; 
            }
            flow_ptr->saw_path_start = 1;
        }

        if (current_stage_id == MAX_UNIDIR_STAGES - 1) { 
            flow_ptr->saw_path_end = 1;
        }
        // flow_sessions.update(parsed_packet_key, flow_ptr); // Consider if explicit update is needed
    } 

    // Check if path is complete and submit event
    if (current_stage_id == MAX_UNIDIR_STAGES - 1 && 
        flow_ptr->saw_path_start && flow_ptr->saw_path_end) {
        
        u64 latency_start_ts = flow_ptr->ts[STAGE_0];
        u64 latency_end_ts = flow_ptr->ts[MAX_UNIDIR_STAGES - 1];

        if (LATENCY_THRESHOLD_NS > 0) {
            if (latency_start_ts == 0 || latency_end_ts == 0 || (latency_end_ts - latency_start_ts) < LATENCY_THRESHOLD_NS) {
                flow_sessions.delete(parsed_packet_key); 
                return; 
            }
        }
        
        u32 map_key_zero = 0; 
        struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_data_ptr) {
            return; 
        }
        
        event_data_ptr->key = *parsed_packet_key; 
        
        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr) != 0) {
            flow_sessions.delete(parsed_packet_key); 
            return;
        }
        
        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
        
        flow_sessions.delete(parsed_packet_key); 
    }
}

int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed
    
    if (TRACE_DIRECTION == 0) { // Outgoing: ip_send_skb is STAGE_0
        if (parse_packet_key(skb, &key, 1, STAGE_0)) { // path_is_primary = 1
            handle_event(ctx, skb, STAGE_0, &key); 
        }
    }
    // For unidirectional, ip_send_skb is not STAGE_0 for incoming.
    }
    return 0;
}

int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed
    
    if (TRACE_DIRECTION == 0) { // Outgoing: internal_dev_xmit is STAGE_1
        if (parse_packet_key(skb, &key, 1, STAGE_1)) { // path_is_primary = 1
            handle_event(ctx, skb, STAGE_1, &key); 
        }
    }
    // For unidirectional, internal_dev_xmit is not a primary stage for incoming.
    }
    return 0;
}

int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed
    
    if (TRACE_DIRECTION == 1) { // Incoming: __netif_receive_skb is STAGE_0
        if (parse_packet_key(skb, &key, 1, STAGE_0)) { // path_is_primary = 1
            handle_event(ctx, skb, STAGE_0, &key);
        }
    }
    // For unidirectional, __netif_receive_skb is not STAGE_0 for outgoing.
    }
    return 0;
}

int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    struct sk_buff *skb = NULL; 
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }
    
    struct packet_key_t key_parsed = {}; 
    // u8 icmp_type_parsed = 0; // Removed
    
    if (TRACE_DIRECTION == 1) { // Incoming: netdev_frame_hook is STAGE_1
         if (parse_packet_key(skb, &key_parsed, 1, STAGE_1)) { // path_is_primary = 1
            handle_event(ctx, skb, STAGE_1, &key_parsed);
        }
    }
    // For unidirectional, netdev_frame_hook is not a primary stage for outgoing.
    }
    return 0;
}

int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {}; 
    // u8 icmp_type = 0; // Removed

    // This is an intermediate stage (STAGE_2) for the defined path.
    if (parse_packet_key(skb, &key, 1, STAGE_2)) { // path_is_primary = 1
        handle_event(ctx, skb, STAGE_2, &key);
    }
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed

    // Intermediate stage (STAGE_3)
    if (parse_packet_key(skb, &key, 1, STAGE_3)) { // path_is_primary = 1
        handle_event(ctx, skb, STAGE_3, &key);
    }
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed

    // Intermediate stage (STAGE_4)
    if (parse_packet_key(skb, &key, 1, STAGE_4)) { // path_is_primary = 1
        handle_event(ctx, skb, STAGE_4, &key);
    }
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed

    // Intermediate stage (STAGE_5)
    if (parse_packet_key(skb, &key, 1, STAGE_5)) { // path_is_primary = 1
        handle_event(ctx, skb, STAGE_5, &key);
    }
    return 0;
}

int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    // The is_target_ifindex check is handled by handle_event for STAGE_6 if TRACE_DIRECTION == 0.
        
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed
    
    if (TRACE_DIRECTION == 0) { // Outgoing: dev_queue_xmit is STAGE_6
        if (parse_packet_key(skb, &key, 1, STAGE_6)) { // path_is_primary = 1
            handle_event(ctx, skb, STAGE_6, &key);
        }
    }
    // For unidirectional, dev_queue_xmit is not a primary stage for incoming.
    }
    return 0;
}

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    // u8 icmp_type = 0; // Removed
    
    if (TRACE_DIRECTION == 1) { // Incoming: icmp_rcv is STAGE_6 for ICMP packets
        if (parse_packet_key(skb, &key, 1, STAGE_6)) { // path_is_primary = 1
             if (key.proto == IPPROTO_ICMP) { // Ensure it's an ICMP packet as probe is ICMP specific
                handle_event(ctx, skb, STAGE_6, &key);
            }
        }
    }
    // For unidirectional, icmp_rcv is not part of an outgoing trace.
    }
    return 0;
}
"""

# Constants
IFNAMSIZ = 16
TASK_COMM_LEN = 16
MAX_UNIDIR_STAGES = 7 # Max stages for a single path

# Define L4 Sctructures for PacketKey Union
class _TcpUdpL4(ctypes.Structure):
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16)
    ]

class _IcmpL4(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("id", ctypes.c_uint16), # ICMP echo/reply ID, distinct from IP ID
        ("seq", ctypes.c_uint16)
    ]

class L4Union(ctypes.Union):
    _fields_ = [
        ("tcp_udp", _TcpUdpL4),
        ("icmp", _IcmpL4)
    ]

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),         # Canonical source IP for the trace
        ("dip", ctypes.c_uint32),         # Canonical destination IP for the trace
        ("proto", ctypes.c_uint8),        # Protocol (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
        ("ip_id", ctypes.c_uint16),       # IP Identification field
        ("frag_offset", ctypes.c_uint16), # Fragment offset (0 for unfragmented or first fragment)
        ("l4", L4Union)                   # Layer 4 specific data
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * MAX_UNIDIR_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_UNIDIR_STAGES),
        ("kstack_id", ctypes.c_int * MAX_UNIDIR_STAGES),
        ("pid", ctypes.c_uint32),               # PID associated with start of the path
        ("comm", ctypes.c_char * TASK_COMM_LEN), # Comm for the path
        ("ifname", ctypes.c_char * IFNAMSIZ),    # Interface for path start
        ("l4_type", ctypes.c_uint8),            # L4 type (e.g., ICMP type, 0 for TCP/UDP)
        ("saw_path_start", ctypes.c_uint8, 1),  # Flag: saw path start
        ("saw_path_end", ctypes.c_uint8, 1)     # Flag: saw path end
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey), # Updated PacketKey
        ("data", FlowData)  # Updated FlowData
    ]


# --- Helper Functions ---
def get_if_index(devname): # No changes needed
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname) # pragma: no cover
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e: # pragma: no cover
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e)) # pragma: no cover
    finally:
        s.close()

def ip_to_hex(ip_str): # No changes needed
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int) # BPF expects network byte order for filters
    except socket.error: # pragma: no cover
        print "Error: Invalid IP address format '%s'" % ip_str # pragma: no cover
        sys.exit(1) # pragma: no cover

def format_ip(addr): # No changes needed
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def format_latency(ts_start, ts_end): # No changes needed
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0: # Only return N/A if one of the timestamps is actually zero
        return " N/A ".rjust(7)
    
    # Calculate delta, which can be negative if ts_end < ts_start
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(7)


def get_detailed_stage_name(stage_id, direction):
    """Returns a detailed stage name including the BPF probe point based on direction."""
    
    base_names = {
        0: "P1:S0_INIT", 1: "P1:S1_STACK_PROC", 2: "P1:S2_OVS_DP_PROC",
        3: "P1:S3_OVS_UPCALL", 4: "P1:S4_OVS_KEYEXT", 5: "P1:S5_OVS_VPORT_SND",
        6: "P1:S6_FINAL",
        7: "P2:S0_INIT", 8: "P2:S1_STACK_PROC", 9: "P2:S2_OVS_DP_PROC",
        10: "P2:S3_OVS_UPCALL", 11: "P2:S4_OVS_KEYEXT", 12: "P2:S5_OVS_VPORT_SND",
        13: "P2:S6_FINAL"
    }
    
    probe_map_outgoing = {
        0: "ip_send_skb",       1: "internal_dev_xmit",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",     4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "dev_queue_xmit",
        7: "__netif_receive_skb", 8: "netdev_frame_hook",  9: "ovs_dp_process_packet",
        10: "ovs_dp_upcall",    11: "ovs_flow_key_extract_userspace",12: "ovs_vport_send",
        13: "icmp_rcv"
    }
    
    probe_map_incoming = {
        0: "__netif_receive_skb", 1: "netdev_frame_hook",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",     4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "icmp_rcv",
        7: "ip_send_skb",       8: "internal_dev_xmit",  9: "ovs_dp_process_packet",
        10: "ovs_dp_upcall",    11: "ovs_flow_key_extract_userspace",12: "ovs_vport_send",
        13: "dev_queue_xmit"
    }

    base_name = base_names.get(stage_id, "Unknown Stage")
    probe_name = ""
    
    # Simplified for unidirectional path (stages 0-6)
    # The BPF code now uses STAGE_0 to STAGE_6 for the single path being traced.
    # TRACE_DIRECTION determines which set of kprobes map to these stages.
    if stage_id < MAX_UNIDIR_STAGES:
        if direction == "outgoing":
            probe_name = probe_map_outgoing.get(stage_id, "N/A")
        elif direction == "incoming":
            probe_name = probe_map_incoming.get(stage_id, "N/A")
        else: # Should not happen
            probe_name = "N/A" # pragma: no cover
    else:
        base_name = "Invalid Stage" # pragma: no cover
        probe_name = "N/A" # pragma: no cover
        
    return "%s (%s)" % (base_name, probe_name)

def _print_latency_segment(start_idx, end_idx, flow_data, direction_str, label_suffix=""):
    """Helper function to print a single latency segment."""
    # Ensure indices are within bounds of MAX_UNIDIR_STAGES
    if start_idx >= MAX_UNIDIR_STAGES or end_idx >= MAX_UNIDIR_STAGES:
        return # Or handle error appropriately

    latency = format_latency(flow_data.ts[start_idx], flow_data.ts[end_idx])
    start_name = get_detailed_stage_name(start_idx, direction_str)
    end_name = get_detailed_stage_name(end_idx, direction_str)
    effective_label_suffix = " " + label_suffix if label_suffix else ""
    
    idx_part_str = "  [%2d->%-2d]" % (start_idx, end_idx)
    stages_desc_str = "%s -> %s" % (start_name, end_name)
    
    stages_desc_padded_width = 105 
    
    print("%s %-*s: %s us%s" % (
        idx_part_str, 
        stages_desc_padded_width, 
        stages_desc_str, 
        latency, 
        effective_label_suffix
    ))

def _print_kernel_stack_trace_for_stage(stage_idx, stack_id):
    """Helper function to print a single kernel stack trace."""
    global args, b
    if stage_idx >= MAX_UNIDIR_STAGES:
        return # Or handle error
    stage_name = get_detailed_stage_name(stage_idx, args.direction)
    print "  Stage %d (%s):" % (stage_idx, stage_name)

    if stack_id <= 0:
        print "    <BPF 'get_stackid' call failed or returned no stack: id=%d>" % stack_id # pragma: no cover
        return

    try:
        if not b:
            print "    <BPF object 'b' is not available for stack traces>" # pragma: no cover
            return

        stack_table = b.get_table("stack_traces")
        resolved_one = False
        for addr in stack_table.walk(stack_id):
            sym = b.ksym(addr, show_offset=True)
            print "    %s" % sym
            resolved_one = True
        
        if not resolved_one:
            print "    <Stack trace walk for id %d yielded no symbols>" % stack_id # pragma: no cover

    except KeyError: # pragma: no cover
        print "    <'stack_traces' table not found in BPF object. Kernel may lack CONFIG_BPF_STACK_TRACE.>" # pragma: no cover
        if b and hasattr(b, 'tables'): # pragma: no cover
            print "    Available tables: %s" % list(b.tables.keys()) # pragma: no cover
        else: # pragma: no cover
            print "    BPF object 'b' or 'b.tables' not available to list tables." # pragma: no cover
    except Exception as e: # pragma: no cover
        print "    <Python error during stack trace resolution for id %d: %s>" % (stack_id, e) # pragma: no cover

def print_all_kernel_stack_traces(flow_data):
    """Prints kernel stack traces for all relevant stages in the flow."""
    print "\nKernel Stack Traces (Stages 0-%d):" % (MAX_UNIDIR_STAGES - 1)
    for i in range(MAX_UNIDIR_STAGES): # Iterate up to MAX_UNIDIR_STAGES
        if flow_data.ts[i] != 0: # Only print for stages that have a timestamp
            _print_kernel_stack_trace_for_stage(i, flow_data.kstack_id[i])

def print_event(cpu, data, size):
    global args 
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    trace_dir_str = "Outgoing (Local -> Remote)" if args.direction == "outgoing" else "Incoming (Remote -> Local)"
    
    print "=== Unidirectional Latency Trace: %s (%s) ===" % (time_str, trace_dir_str)
    
    session_info = "Session: %s -> %s (Proto: %d, IP_ID: %d, FragOff: %d" % (
        format_ip(key.sip), 
        format_ip(key.dip),
        key.proto,
        socket.ntohs(key.ip_id), # IP ID is network byte order in key
        key.frag_offset # Fragment offset is already host byte order (masked part of ip.frag_off)
    )

    if key.proto == socket.IPPROTO_TCP:
        session_info += ", TCP Sport: %d, Dport: %d)" % (socket.ntohs(key.l4.tcp_udp.sport), socket.ntohs(key.l4.tcp_udp.dport))
    elif key.proto == socket.IPPROTO_UDP:
        session_info += ", UDP Sport: %d, Dport: %d)" % (socket.ntohs(key.l4.tcp_udp.sport), socket.ntohs(key.l4.tcp_udp.dport))
    elif key.proto == socket.IPPROTO_ICMP:
        session_info += ", ICMP Type: %d, ID: %d, Seq: %d)" % (
            key.l4.icmp.type, 
            socket.ntohs(key.l4.icmp.id), 
            socket.ntohs(key.l4.icmp.seq)
        )
    else:
        session_info += ")"
    print session_info
    
    path_desc_padding_width = 45 
    path_desc = "Trace Path Details (%s)" % (args.src_ip if args.direction == "outgoing" else args.dst_ip)

    print "%-*s: PID=%-6d COMM=%-12s IF=%-10s L4_Type=%d" % (
        path_desc_padding_width,
        path_desc,
        flow.pid, 
        flow.comm.decode('utf-8', 'replace'),
        flow.ifname.decode('utf-8', 'replace'),
        flow.l4_type
    )
        
    print "\nSKB Pointers (Stages 0-%d):" % (MAX_UNIDIR_STAGES -1)
    stage_name_padding_width = 45 
    for i in range(MAX_UNIDIR_STAGES):
        if flow.skb_ptr[i] != 0:
            stage_name_str = get_detailed_stage_name(i, args.direction)
            print "  Stage %2d (%-*s): 0x%x" % (
                i, stage_name_padding_width, stage_name_str, flow.skb_ptr[i]
            )
    
    print "\nPath Segment Latencies (us):"
    _print_latency_segment(0, 1, flow, args.direction) # S0 -> S1
    _print_latency_segment(1, 2, flow, args.direction) # S1 -> S2

    # OVS Path (Stages 2-5)
    has_s2 = flow.ts[2] > 0
    has_s3 = flow.ts[3] > 0 # OVS Upcall
    has_s4 = flow.ts[4] > 0 # OVS Key Extract
    has_s5 = flow.ts[5] > 0 # OVS Vport Send

    if has_s2 and has_s3: 
        _print_latency_segment(2, 3, flow, args.direction) # S2 (OVS_DP_PROC) -> S3 (OVS_UPCALL)

    if has_s3 and has_s4 and has_s5: # Full upcall path: S3 -> S4 -> S5
        _print_latency_segment(3, 4, flow, args.direction) # S3 (OVS_UPCALL) -> S4 (OVS_KEYEXT)
        _print_latency_segment(4, 5, flow, args.direction) # S4 (OVS_KEYEXT) -> S5 (OVS_VPORT_SND)
    elif has_s3 and not has_s4 and has_s5: 
        _print_latency_segment(3, 5, flow, args.direction, label_suffix="(S4 N/A)")
    elif has_s2 and not has_s3 and not has_s4 and has_s5: # Kernel path through OVS, no upcall (S3 & S4 are zero)
        _print_latency_segment(2, 5, flow, args.direction, label_suffix="(OVS No Upcall: S3,S4 N/A)")
    elif has_s2 and has_s5 : # Generic S2 to S5 if some OVS stages are missing
        # This case might be redundant given the above, but can be a fallback
        if not (has_s3 and has_s4): # if not full upcall
             _print_latency_segment(2, 5, flow, args.direction, label_suffix="(OVS Partial Path)")


    _print_latency_segment(5, 6, flow, args.direction) # S5 -> S6

    if flow.ts[0] > 0 and flow.ts[MAX_UNIDIR_STAGES - 1] > 0:
        total_latency = format_latency(flow.ts[0], flow.ts[MAX_UNIDIR_STAGES - 1])
        print "  Total Path Latency (S0->S%d): %s us" % (MAX_UNIDIR_STAGES -1, total_latency)
    
    if not args.disable_kernel_stacks:
        print_all_kernel_stack_traces(flow)
    
    print "\n" + "="*50 + "\n"

if __name__ == "__main__":
    if os.geteuid() != 0:
        print "This program must be run as root" # pragma: no cover
        sys.exit(1) # pragma: no cover
    
    parser = argparse.ArgumentParser(
        description="Trace unidirectional TCP/UDP/ICMP latency through the Linux network stack and OVS, with L4 filtering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Trace unidirectional network latency for TCP, UDP, and ICMP packets through the Linux network stack and OVS.

Examples:
  Trace outgoing TCP path from 1.2.3.4:12345 to 5.6.7.8:80 on eth0:
    sudo ./system_network_latency.py --protocol tcp --src-ip 1.2.3.4 --dst-ip 5.6.7.8 \\
                                     --sport 12345 --dport 80 \\
                                     --phy-iface1 eth0 --direction outgoing

  Trace incoming UDP path to 1.2.3.4 (local) from 5.6.7.8 (remote) for DNS (port 53) on eth0:
    sudo ./system_network_latency.py --protocol udp --src-ip 1.2.3.4 --dst-ip 5.6.7.8 \\
                                     --dport 53 --phy-iface1 eth0 --direction incoming

  Trace outgoing ICMP Echo Request (type 8) from 1.2.3.4 to 5.6.7.8 on eth0:
    sudo ./system_network_latency.py --protocol icmp --src-ip 1.2.3.4 --dst-ip 5.6.7.8 \\
                                     --icmp-type 8 --phy-iface1 eth0 --direction outgoing
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=True, 
                        help='Source IP to filter on. For "outgoing" trace, this is the traced packet source. For "incoming" trace, this is the local IP receiving the packet.')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP to filter on. For "outgoing" trace, this is the traced packet destination. For "incoming" trace, this is the remote IP sending the packet.')
    parser.add_argument('--protocol', type=str, required=True, choices=['tcp', 'udp', 'icmp'],
                        help='Protocol to trace (tcp, udp, or icmp).')
    parser.add_argument('--sport', type=int, default=0,
                        help='Source port for TCP/UDP (0 for wildcard).')
    parser.add_argument('--dport', type=int, default=0,
                        help='Destination port for TCP/UDP (0 for wildcard).')
    parser.add_argument('--icmp-type', type=int, default=-1,
                        help='ICMP type (-1 for wildcard, e.g., 8 for Echo Request).')
    parser.add_argument('--icmp-id', type=int, default=0,
                        help='ICMP ID (for Echo/Reply, 0 for wildcard).')
    parser.add_argument('--icmp-seq', type=int, default=0,
                        help='ICMP sequence number (for Echo/Reply, 0 for wildcard).')
    parser.add_argument('--phy-iface1', type=str, required=True,
                        help='First physical interface to monitor (e.g., for dev_queue_xmit on outgoing path, or __netif_receive_skb on incoming path).')
    parser.add_argument('--phy-iface2', type=str, required=False, default=None,
                        help='Second physical interface to monitor. If not provided, phy-iface1 will be used for both checks.')
    parser.add_argument('--latency-ms', type=float, default=0,
                        help='Minimum unidirectional latency threshold in ms to report (default: 0, report all).')
    parser.add_argument('--direction', type=str, choices=["outgoing", "incoming"], default="outgoing",
                        help='Direction of packet trace: "outgoing" (local host to remote) or "incoming" (remote host to local). Default: outgoing.')
    parser.add_argument('--disable-kernel-stacks', action='store_true', default=False,
                      help='Disable printing of kernel stack traces for each stage.')
    
    args = parser.parse_args()
    
    direction_val = 0 if args.direction == "outgoing" else 1 
    
    try:
        ifindex1 = get_if_index(args.phy_iface1)
        if args.phy_iface2:
            ifindex2 = get_if_index(args.phy_iface2)
        else:
            ifindex2 = ifindex1 # Use ifindex1 if iface2 is not provided
    except OSError as e:
        print "Error getting interface index: %s" % e # pragma: no cover
        sys.exit(1) # pragma: no cover
        
    src_ip_hex_val = ip_to_hex(args.src_ip)
    dst_ip_hex_val = ip_to_hex(args.dst_ip)
    
    latency_threshold_ns_val = int(args.latency_ms * 1000000)
    
    proto_val = 0
    if args.protocol == "tcp":
        proto_val = socket.IPPROTO_TCP
    elif args.protocol == "udp":
        proto_val = socket.IPPROTO_UDP
    elif args.protocol == "icmp":
        proto_val = socket.IPPROTO_ICMP

    print "=== Unidirectional Network Latency Tracer ==="
    print "Trace Direction: %s, Protocol: %s" % (args.direction.upper(), args.protocol.upper())
    print "SRC_IP_FILTER (Configured Source for BPF): %s (0x%x)" % (args.src_ip, socket.ntohl(src_ip_hex_val)) 
    print "DST_IP_FILTER (Configured Dest for BPF): %s (0x%x)" % (args.dst_ip, socket.ntohl(dst_ip_hex_val))
    if args.protocol == "tcp" or args.protocol == "udp":
        print "SPORT_FILTER: %s, DPORT_FILTER: %s" % (args.sport if args.sport else "Any", args.dport if args.dport else "Any")
    elif args.protocol == "icmp":
        print "ICMP_TYPE_FILTER: %s, ICMP_ID_FILTER: %s, ICMP_SEQ_FILTER: %s" % \
              (args.icmp_type if args.icmp_type != -1 else "Any", 
               args.icmp_id if args.icmp_id else "Any", 
               args.icmp_seq if args.icmp_seq else "Any")

    if args.phy_iface2 and args.phy_iface1 != args.phy_iface2:
        print "Monitoring physical interfaces: %s (ifindex %d) and %s (ifindex %d)" % \
              (args.phy_iface1, ifindex1, args.phy_iface2, ifindex2)
    else:
        print "Monitoring physical interface: %s (ifindex %d)" % \
              (args.phy_iface1, ifindex1)
    
    if latency_threshold_ns_val > 0:
        print "Reporting only paths with latency >= %.3f ms" % args.latency_ms
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex_val,
            dst_ip_hex_val,
            latency_threshold_ns_val,
            ifindex1,
            ifindex2,
            direction_val,
            proto_val,
            args.sport, # Defaults to 0 if not provided
            args.dport, # Defaults to 0 if not provided
            args.icmp_type, # Defaults to -1 if not provided
            args.icmp_id,   
            args.icmp_seq   
        ))
    except Exception as e: # pragma: no cover
        print "Error loading BPF program: %s" % e # pragma: no cover
        print "\nEnsure all kprobe function names in the BPF C code are correct for your kernel version." # pragma: no cover
        sys.exit(1) # pragma: no cover
        
    probe_functions = [
        ("ip_send_skb", "kprobe__ip_send_skb"),
        ("internal_dev_xmit", "kprobe__internal_dev_xmit"),
        ("__netif_receive_skb", "kprobe____netif_receive_skb"),
        ("netdev_frame_hook", "kprobe__netdev_frame_hook"),
        ("ovs_dp_process_packet", "kprobe__ovs_dp_process_packet"),
        ("ovs_dp_upcall", "kprobe__ovs_dp_upcall"),
        ("ovs_flow_key_extract_userspace", "kprobe__ovs_flow_key_extract_userspace"),
        ("ovs_vport_send", "kprobe__ovs_vport_send"),
        ("dev_queue_xmit", "kprobe__dev_queue_xmit"),
        ("icmp_rcv", "kprobe__icmp_rcv")
    ]

    b["events"].open_perf_buffer(print_event) 
    
    print "\nTracing Unidirectional Latency for src_ip=%s, dst_ip=%s, direction=%s ... Hit Ctrl-C to end." % (args.src_ip, args.dst_ip, args.direction)
    
    try:
        while True:
            b.perf_buffer_poll() # pragma: no cover
    except KeyboardInterrupt: # pragma: no cover
        print "\nDetaching..." # pragma: no cover
    finally: # pragma: no cover
        print "Exiting." # pragma: no cover
