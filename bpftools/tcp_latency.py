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
# ./tcp_latency.py --help
# usage: tcp_latency.py [-h] --src-ip SRC_IP --dst-ip DST_IP 
#                       [--src-port SRC_PORT] [--dst-port DST_PORT]
#                       --phy-iface1 PHY_IFACE1 [--phy-iface2 PHY_IFACE2]
#                       [--latency-ms LATENCY_MS]
#                       [--direction {outgoing,incoming}]
#                       [--disable-kernel-stacks]

# Trace TCP packet latency through the Linux network stack and OVS.

# optional arguments:
#   -h, --help            show this help message and exit
#   --src-ip SRC_IP       Source IP address for TCP connections
#   --dst-ip DST_IP       Destination IP address for TCP connections
#   --src-port SRC_PORT   Source port for TCP connections (optional, 0 = any)
#   --dst-port DST_PORT   Destination port for TCP connections (optional, 0 = any)
#   --phy-iface1 PHY_IFACE1
#                         First physical interface to monitor
#   --phy-iface2 PHY_IFACE2
#                         Second physical interface to monitor
#   --latency-ms LATENCY_MS
#                         Minimum latency threshold in ms to report
#                         (default: 0, report all).
#   --direction {outgoing,incoming}
#                         Direction of TCP trace: "outgoing" (TX) or "incoming" (RX).
#                         Default: outgoing.
#   --disable-kernel-stacks
#                         Disable printing of kernel stack traces for each
#                         stage.

# Examples:
#   Outgoing TCP from 192.168.1.10:8080 to 192.168.1.20:80, interfaces eth0, eth1:
#     sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                           --src-port 8080 --dst-port 80 \
#                           --phy-iface1 eth0 --phy-iface2 eth1 --direction outgoing

#   Incoming TCP to 192.168.1.10:80 from any source, interface eth0:
#     sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 0.0.0.0 \
#                           --dst-port 80 \
#                           --phy-iface1 eth0 --direction incoming

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
import fcntl

# --- BPF Program ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
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
#define LATENCY_THRESHOLD_NS %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define TRACE_DIRECTION %d // 0 for Outgoing, 1 for Incoming

// Define stages for single path (unidirectional)
#define STAGE_0    0  // Start point: __tcp_transmit_skb (TX) or __netif_receive_skb (RX)
#define STAGE_1    1  // internal_dev_xmit (TX) or netdev_frame_hook (RX)
#define STAGE_2    2  // ovs_dp_process_packet
#define STAGE_3    3  // ovs_dp_upcall (optional)
#define STAGE_4    4  // ovs_flow_key_extract_userspace (optional)
#define STAGE_5    5  // ovs_vport_send
#define STAGE_6    6  // __dev_queue_xmit (TX) or tcp_v4_rcv (RX)

#define MAX_STAGES               7
#define IFNAMSIZ                 16
#define TASK_COMM_LEN            16

// Packet key structure to uniquely identify TCP packets
struct packet_key_t {
    __be32 saddr;   // Source IP
    __be32 daddr;   // Destination IP
    __be16 sport;   // Source port
    __be16 dport;   // Destination port
    __be32 seq;     // TCP sequence number
    __be32 ack_seq; // TCP ack sequence number
};

// Structure to track flow data and timestamps
struct flow_data_t {
    u64 ts[MAX_STAGES];
    u64 skb_ptr[MAX_STAGES];
    int kstack_id[MAX_STAGES];
    
    // Tracking info
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    
    // TCP flags
    u8 tcp_flags;
    
    // Flags for stage tracking
    u8 saw_start:1;
    u8 saw_end:1;
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

// Function to parse TCP packet from userspace context
static __always_inline int parse_packet_key_userspace(struct sk_buff *skb, struct packet_key_t *key, 
                                                     u8 *tcp_flags_out) {
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
    
    // Handle VLAN tags
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
    
    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    // Apply IP filters
    if (SRC_IP_FILTER != 0 && DST_IP_FILTER != 0) {
        if (TRACE_DIRECTION == 0) { // Outgoing
            if (!(ip.saddr == SRC_IP_FILTER && ip.daddr == DST_IP_FILTER)) return 0;
        } else { // Incoming
            if (!(ip.saddr == DST_IP_FILTER && ip.daddr == SRC_IP_FILTER)) return 0;
        }
    } else if (SRC_IP_FILTER != 0) {
        if (ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) return 0;
    } else if (DST_IP_FILTER != 0) {
        if (ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    // Calculate transport offset based on net_offset and ip_ihl
    unsigned int trans_offset = net_offset + (ip_ihl * 4);
    
    struct tcphdr tcp;
    if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) < 0) {
        return 0;
    }

    // Apply port filters
    if (SRC_PORT_FILTER != 0) {
        if (tcp.source != htons(SRC_PORT_FILTER) && tcp.dest != htons(SRC_PORT_FILTER)) return 0;
    }
    if (DST_PORT_FILTER != 0) {
        if (tcp.source != htons(DST_PORT_FILTER) && tcp.dest != htons(DST_PORT_FILTER)) return 0;
    }

    *tcp_flags_out = ((u8 *)&tcp)[13] & 0x3F; // Get TCP flags
    key->saddr = ip.saddr;
    key->daddr = ip.daddr;
    key->sport = tcp.source;
    key->dport = tcp.dest;
    key->seq = tcp.seq;
    key->ack_seq = tcp.ack_seq;

    return 1;
}

// Function to parse TCP packet from kernel context
static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key, 
                                           u8 *tcp_flags_out, u8 stage_id_for_log_only) {
    if (stage_id_for_log_only == STAGE_4) {
         return parse_packet_key_userspace(skb, key, tcp_flags_out);
    }
    
    if (skb == NULL) {
        return 0;
    }

    unsigned char *head;
    u16 network_header_offset; 
    u16 transport_header_offset; 

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048 ) { 
        return 0; 
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }

    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    // Apply IP filters
    if (SRC_IP_FILTER != 0 && DST_IP_FILTER != 0) {
        if (TRACE_DIRECTION == 0) { // Outgoing
            if (!(ip.saddr == SRC_IP_FILTER && ip.daddr == DST_IP_FILTER)) return 0;
        } else { // Incoming
            if (!(ip.saddr == DST_IP_FILTER && ip.daddr == SRC_IP_FILTER)) return 0;
        }
    } else if (SRC_IP_FILTER != 0) {
        if (ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) return 0;
    } else if (DST_IP_FILTER != 0) {
        if (ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }
    
    struct tcphdr tcp;
    if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header_offset) < 0) {
        return 0;
    }

    // Apply port filters
    if (SRC_PORT_FILTER != 0) {
        if (tcp.source != htons(SRC_PORT_FILTER) && tcp.dest != htons(SRC_PORT_FILTER)) return 0;
    }
    if (DST_PORT_FILTER != 0) {
        if (tcp.source != htons(DST_PORT_FILTER) && tcp.dest != htons(DST_PORT_FILTER)) return 0;
    }

    *tcp_flags_out = ((u8 *)&tcp)[13] & 0x3F; // Get TCP flags
    key->saddr = ip.saddr;
    key->daddr = ip.daddr;
    key->sport = tcp.source;
    key->dport = tcp.dest;
    key->seq = tcp.seq;
    key->ack_seq = tcp.ack_seq;

    return 1;
}

static __always_inline void handle_event(struct pt_regs *ctx, struct sk_buff *skb, 
                                         u64 current_stage_id, struct packet_key_t *parsed_packet_key, u8 tcp_flags) {
    if (skb == NULL) {
        return;
    }

    // Check interface for first and last stages
    if (TRACE_DIRECTION == 0 && current_stage_id == STAGE_6) { // Outgoing, last stage
        if (!is_target_ifindex(skb)){
            return;
        }
    }
    if (TRACE_DIRECTION == 1 && current_stage_id == STAGE_0) { // Incoming, first stage
         if (!is_target_ifindex(skb)){
            return;
        }
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

    if (flow_ptr->ts[current_stage_id] == 0) { 
        flow_ptr->ts[current_stage_id] = current_ts;
        flow_ptr->skb_ptr[current_stage_id] = (u64)skb;
        flow_ptr->kstack_id[current_stage_id] = stack_id;

        struct net_device *dev;
        char if_name_buffer[IFNAMSIZ];
        __builtin_memset(if_name_buffer, 0, IFNAMSIZ);

        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel_str(if_name_buffer, IFNAMSIZ, dev->name);
        } else {
            char unk[] = "unknown";
            bpf_probe_read_kernel_str(if_name_buffer, sizeof(unk), unk); 
        }

        if (current_stage_id == STAGE_0) { 
            flow_ptr->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->comm, sizeof(flow_ptr->comm));
            bpf_probe_read_kernel_str(flow_ptr->ifname, IFNAMSIZ, if_name_buffer);
            flow_ptr->tcp_flags = tcp_flags;
            flow_ptr->saw_start = 1;
        }

        if (current_stage_id == STAGE_6) { 
            flow_ptr->saw_end = 1;
        }

        flow_sessions.update(parsed_packet_key, flow_ptr);
    } 

    // Submit event when we reach the end
    if (current_stage_id == STAGE_6 && flow_ptr->saw_start && flow_ptr->saw_end) {
        u64 total_latency = flow_ptr->ts[STAGE_6] - flow_ptr->ts[STAGE_0];
        
        if (LATENCY_THRESHOLD_NS > 0) {
            if (total_latency < LATENCY_THRESHOLD_NS) {
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

// Probe functions for TCP path

// Outgoing: Start at __tcp_transmit_skb (with double underscore)
// Incoming: Start at __netif_receive_skb
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) { // Only for outgoing
        return 0;
    }
    
    struct packet_key_t key = {};
    u8 tcp_flags = 0;
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_0)) {
        handle_event(ctx, skb, STAGE_0, &key, tcp_flags);
    }
    return 0;
}

int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 1) { // Only for incoming
        return 0;
    }
    
    struct packet_key_t key = {};
    u8 tcp_flags = 0;
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_0)) {
        handle_event(ctx, skb, STAGE_0, &key, tcp_flags);
    }
    return 0;
}

// Stage 1: internal_dev_xmit (TX) or netdev_frame_hook (RX)
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) { // Only for outgoing
        return 0;
    }
    
    struct packet_key_t key = {};
    u8 tcp_flags = 0;
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_1)) {
        handle_event(ctx, skb, STAGE_1, &key, tcp_flags);
    }
    return 0;
}

int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    if (TRACE_DIRECTION != 1) { // Only for incoming
        return 0;
    }
    
    struct sk_buff *skb = NULL; 
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }
    
    struct packet_key_t key = {}; 
    u8 tcp_flags = 0; 
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_1)) {
        handle_event(ctx, skb, STAGE_1, &key, tcp_flags);
    }
    return 0;
}

// Stage 2: ovs_dp_process_packet (both directions)
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {}; 
    u8 tcp_flags = 0;

    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_2)) { 
        handle_event(ctx, skb, STAGE_2, &key, tcp_flags);
    }
    return 0;
}

// Stage 3: ovs_dp_upcall (optional, both directions)
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {};
    u8 tcp_flags = 0;

    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_3)) {
        handle_event(ctx, skb, STAGE_3, &key, tcp_flags);
    }
    return 0;
}

// Stage 4: ovs_flow_key_extract_userspace (optional, both directions)
int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }
    struct packet_key_t key = {};
    u8 tcp_flags = 0;

    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_4)) { 
        handle_event(ctx, skb, STAGE_4, &key, tcp_flags);
    }
    return 0;
}

// Stage 5: ovs_vport_send (both directions)
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 tcp_flags = 0;

    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_5)) {
        handle_event(ctx, skb, STAGE_5, &key, tcp_flags);
    }
    return 0;
}

// Stage 6: __dev_queue_xmit (TX) or tcp_v4_rcv (RX)
int kprobe____dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) { // Only for outgoing
        return 0;
    }
    
    if (!is_target_ifindex(skb)) {
        return 0;
    }
        
    struct packet_key_t key = {};
    u8 tcp_flags = 0;
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_6)) {
        handle_event(ctx, skb, STAGE_6, &key, tcp_flags);
    }
    return 0;
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 1) { // Only for incoming
        return 0;
    }
    
    struct packet_key_t key = {};
    u8 tcp_flags = 0;
    
    if (parse_packet_key(skb, &key, &tcp_flags, STAGE_6)) {
        handle_event(ctx, skb, STAGE_6, &key, tcp_flags);
    }
    return 0;
}
"""

# Constants
MAX_STAGES = 7
IFNAMSIZ = 16
TASK_COMM_LEN = 16

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32), 
        ("daddr", ctypes.c_uint32), 
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack_seq", ctypes.c_uint32)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("kstack_id", ctypes.c_int * MAX_STAGES),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("ifname", ctypes.c_char * IFNAMSIZ),
        ("tcp_flags", ctypes.c_uint8),
        ("saw_start", ctypes.c_uint8, 1), 
        ("saw_end", ctypes.c_uint8, 1)
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("data", FlowData)
    ]

# --- Helper Functions ---
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
        return socket.htonl(host_int) # BPF expects network byte order for filters
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def format_latency(ts_start, ts_end):
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0:
        return " N/A ".rjust(7)
    
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(7)

def get_tcp_flags_str(flags):
    """Convert TCP flags to string representation"""
    flag_str = ""
    if flags & 0x01: flag_str += "F"  # FIN
    if flags & 0x02: flag_str += "S"  # SYN
    if flags & 0x04: flag_str += "R"  # RST
    if flags & 0x08: flag_str += "P"  # PSH
    if flags & 0x10: flag_str += "A"  # ACK
    if flags & 0x20: flag_str += "U"  # URG
    return flag_str if flag_str else "."

def get_detailed_stage_name(stage_id, direction):
    """Returns a detailed stage name including the BPF probe point based on direction."""
    
    probe_map_outgoing = {
        0: "__tcp_transmit_skb",  1: "internal_dev_xmit",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",     4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "__dev_queue_xmit"
    }
    
    probe_map_incoming = {
        0: "__netif_receive_skb", 1: "netdev_frame_hook",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",       4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "tcp_v4_rcv"
    }
    
    base_names = {
        0: "S0_INIT", 1: "S1_STACK_PROC", 2: "S2_OVS_DP_PROC",
        3: "S3_OVS_UPCALL", 4: "S4_OVS_KEYEXT", 5: "S5_OVS_VPORT_SND",
        6: "S6_FINAL"
    }

    base_name = base_names.get(stage_id, "Unknown Stage")
    
    if direction == "outgoing":
        probe_name = probe_map_outgoing.get(stage_id, "N/A")
    else:
        probe_name = probe_map_incoming.get(stage_id, "N/A")
        
    return "%s (%s)" % (base_name, probe_name)

def _print_latency_segment(start_idx, end_idx, flow_data, direction_str, label_suffix=""):
    """Helper function to print a single latency segment."""
    latency = format_latency(flow_data.ts[start_idx], flow_data.ts[end_idx])
    start_name = get_detailed_stage_name(start_idx, direction_str)
    end_name = get_detailed_stage_name(end_idx, direction_str)
    effective_label_suffix = " " + label_suffix if label_suffix else ""
    
    idx_part_str = "  [%d->%d]" % (start_idx, end_idx)
    stages_desc_str = "%s -> %s" % (start_name, end_name)
    
    stages_desc_padded_width = 85
    
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
    stage_name = get_detailed_stage_name(stage_idx, args.direction)
    print("  Stage %d (%s):" % (stage_idx, stage_name))

    if stack_id <= 0:
        print("    <BPF 'get_stackid' call failed or returned no stack: id=%d>" % stack_id)
        return

    try:
        if not b:
            print("    <BPF object 'b' is not available for stack traces>")
            return

        stack_table = b.get_table("stack_traces")
        resolved_one = False
        for addr in stack_table.walk(stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("    %s" % sym)
            resolved_one = True
        
        if not resolved_one:
            print("    <Stack trace walk for id %d yielded no symbols>" % stack_id)

    except KeyError:
        print("    <'stack_traces' table not found in BPF object. Kernel may lack CONFIG_BPF_STACK_TRACE.>")
        if b and hasattr(b, 'tables'):
            print("    Available tables: %s" % list(b.tables.keys()))
        else:
            print("    BPF object 'b' or 'b.tables' not available to list tables.")
    except Exception as e:
        print("    <Python error during stack trace resolution for id %d: %s>" % (stack_id, e))

def print_all_kernel_stack_traces(flow_data):
    """Prints kernel stack traces for all relevant stages in the flow."""
    print("\nKernel Stack Traces:")
    for i in range(MAX_STAGES):
        if flow_data.ts[i] != 0:
            _print_kernel_stack_trace_for_stage(i, flow_data.kstack_id[i])

def print_event(cpu, data, size):
    global args 
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    trace_dir_str = "Outgoing (TX)" if args.direction == "outgoing" else "Incoming (RX)"
    
    print("=== TCP Latency Trace: %s (%s) ===" % (time_str, trace_dir_str))
    print("Session: %s:%d -> %s:%d (SEQ: %u, ACK: %u, FLAGS: %s)" % (
        format_ip(key.saddr), 
        socket.ntohs(key.sport),
        format_ip(key.daddr),   
        socket.ntohs(key.dport),
        socket.ntohl(key.seq),
        socket.ntohl(key.ack_seq),
        get_tcp_flags_str(flow.tcp_flags)
    ))
    
    print("Process: PID=%-6d COMM=%-12s IF=%-10s" % (
        flow.pid, 
        flow.comm.decode('utf-8', 'replace'),
        flow.ifname.decode('utf-8', 'replace')
    ))
        
    print("\nSKB Pointers:")
    stage_name_padding_width = 45
    for i in range(MAX_STAGES):
        if flow.skb_ptr[i] != 0:
            stage_name_str = get_detailed_stage_name(i, args.direction)
            print("  Stage %d (%-*s): 0x%x" % (
                i, stage_name_padding_width, stage_name_str, flow.skb_ptr[i]
            ))
    
    print("\nLatencies (us):")
    # Always print 0->1 and 1->2 if timestamps exist
    _print_latency_segment(0, 1, flow, args.direction)
    _print_latency_segment(1, 2, flow, args.direction)

    # OVS Kernel Path vs OVS Upcall Path
    has_s2 = flow.ts[2] > 0
    has_s3 = flow.ts[3] > 0 # OVS Upcall
    has_s4 = flow.ts[4] > 0 # OVS Key Extract
    has_s5 = flow.ts[5] > 0 # OVS Vport Send

    if has_s2 and has_s3: # From OVS DP to OVS Upcall
        _print_latency_segment(2, 3, flow, args.direction)

    if has_s3 and has_s4 and has_s5: # Full upcall path: S3 -> S4 -> S5
        _print_latency_segment(3, 4, flow, args.direction) # OVS Upcall -> OVS KeyExt
        _print_latency_segment(4, 5, flow, args.direction) # OVS KeyExt -> OVS VportSnd
    elif has_s3 and not has_s4 and has_s5: # Upcall happened, S4 missing, but S3 and S5 present
        _print_latency_segment(3, 5, flow, args.direction, label_suffix="(S4 N/A)")
    elif has_s2 and not has_s3 and not has_s4 and has_s5: # Kernel path, no upcall (S3 & S4 are zero)
        _print_latency_segment(2, 5, flow, args.direction, label_suffix="(OVS No Upcall)")

    _print_latency_segment(5, 6, flow, args.direction)

    if flow.ts[0] > 0 and flow.ts[6] > 0:
        total_latency = format_latency(flow.ts[0], flow.ts[6])
        print("\nTotal Latency: %s us" % total_latency)
    
    if not args.disable_kernel_stacks:
        print_all_kernel_stack_traces(flow)
    
    print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Trace TCP packet latency through the Linux network stack and OVS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Outgoing TCP from 192.168.1.10:8080 to 192.168.1.20:80, interfaces eth0, eth1:
    sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                          --src-port 8080 --dst-port 80 \\
                          --phy-iface1 eth0 --phy-iface2 eth1 --direction outgoing

  Incoming TCP to 192.168.1.10:80 from any source, interface eth0:
    sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 0.0.0.0 \\
                          --dst-port 80 \\
                          --phy-iface1 eth0 --direction incoming
                          
  Monitor all TCP traffic between two IPs:
    sudo ./tcp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                          --phy-iface1 eth0 --direction outgoing
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=True, 
                      help='Source IP address for TCP connections')
    parser.add_argument('--dst-ip', type=str, required=True,
                      help='Destination IP address for TCP connections (use 0.0.0.0 for any)')
    parser.add_argument('--src-port', type=int, default=0,
                      help='Source port for TCP connections (optional, 0 = any)')
    parser.add_argument('--dst-port', type=int, default=0,
                      help='Destination port for TCP connections (optional, 0 = any)')
    parser.add_argument('--phy-iface1', type=str, required=True,
                      help='First physical interface to monitor')
    parser.add_argument('--phy-iface2', type=str, required=False, default=None,
                      help='Second physical interface to monitor')
    parser.add_argument('--latency-ms', type=float, default=0,
                      help='Minimum latency threshold in ms to report (default: 0, report all).')
    parser.add_argument('--direction', type=str, choices=["outgoing", "incoming"], default="outgoing",
                      help='Direction of TCP trace: "outgoing" (TX) or "incoming" (RX). Default: outgoing.')
    parser.add_argument('--disable-kernel-stacks', action='store_true', default=False,
                      help='Disable printing of kernel stack traces for each stage.')
    
    args = parser.parse_args()
    
    direction_val = 0 if args.direction == "outgoing" else 1 
    
    try:
        ifindex1 = get_if_index(args.phy_iface1)
        if args.phy_iface2:
            ifindex2 = get_if_index(args.phy_iface2)
        else:
            ifindex2 = ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)
        
    src_ip_hex_val = ip_to_hex(args.src_ip)
    dst_ip_hex_val = ip_to_hex(args.dst_ip)
    
    latency_threshold_ns_val = int(args.latency_ms * 1000000)
    
    print("=== TCP Latency Tracer ===")
    print("Trace Direction: %s" % args.direction.upper())
    print("Source IP: %s (0x%x)" % (args.src_ip, socket.ntohl(src_ip_hex_val))) 
    print("Destination IP: %s (0x%x)" % (args.dst_ip, socket.ntohl(dst_ip_hex_val)))
    
    if args.src_port > 0:
        print("Source Port: %d" % args.src_port)
    if args.dst_port > 0:
        print("Destination Port: %d" % args.dst_port)
        
    if args.phy_iface2 and args.phy_iface1 != args.phy_iface2:
        print("Monitoring physical interfaces: %s (ifindex %d) and %s (ifindex %d)" % 
              (args.phy_iface1, ifindex1, args.phy_iface2, ifindex2))
    else:
        print("Monitoring physical interface: %s (ifindex %d)" % 
              (args.phy_iface1, ifindex1))
    
    if latency_threshold_ns_val > 0:
        print("Reporting only packets with latency >= %.3f ms" % args.latency_ms)
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex_val, 
            dst_ip_hex_val, 
            args.src_port,
            args.dst_port,
            latency_threshold_ns_val,
            ifindex1, 
            ifindex2,
            direction_val  
        ))
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nEnsure all kprobe function names in the BPF C code are correct for your kernel version.")
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event) 
    
    print("\nTracing TCP latency for src_ip=%s, dst_ip=%s, direction=%s ... Hit Ctrl-C to end." % 
          (args.src_ip, args.dst_ip, args.direction))
    
    try:
        while True:
            b.perf_buffer_poll() 
    except KeyboardInterrupt:
        print("\nDetaching...")
    finally:
        print("Exiting.")