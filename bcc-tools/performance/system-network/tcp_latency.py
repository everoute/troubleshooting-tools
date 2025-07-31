#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TCP Latency Tracer - Corrected Version
# Based on successful icmp_rtt_latency.py probe point selection

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
from time import sleep, strftime
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl

# Use the same successful probe points as ICMP tracer, but adapted for TCP
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define TRACE_DIRECTION %d

BPF_PERF_OUTPUT(events);

struct tcp_event_t {
    u64 ts;
    u32 stage_id;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 seq;
    u32 ack_seq;
    u8 tcp_flags;
    u32 pid;
    char comm[16];
    char ifname[16];
};

// Helper function to check interface
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

static __always_inline int process_tcp_packet(struct pt_regs *ctx, struct sk_buff *skb, u32 stage_id) {
    if (!skb) return 0;
    
    unsigned char *head;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return 0;
    }
    
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return 0;
    }
    
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }
    
    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Apply IP filters based on direction
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
    if (ip_ihl < 5) return 0;
    
    u16 transport_header_offset;
    if (bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }
    
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U) {
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
    
    struct tcp_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.stage_id = stage_id;
    event.src_ip = ip.saddr;
    event.dst_ip = ip.daddr;
    event.src_port = tcp.source;
    event.dst_port = tcp.dest;
    event.seq = tcp.seq;
    event.ack_seq = tcp.ack_seq;
    event.tcp_flags = ((u8 *)&tcp)[13] & 0x3F;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        bpf_probe_read_kernel_str(event.ifname, sizeof(event.ifname), dev->name);
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 0: Use __tcp_transmit_skb but with a different approach
// At this stage, network headers may not be set, so we track by SKB pointer
// and rely on later stages to provide packet details
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) return 0; // Only for outgoing
    if (!skb) return 0;
    
    // Create a minimal event just to mark Stage 0 timing with SKB pointer
    struct tcp_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.stage_id = 0;
    event.src_ip = 0; // Will be filled by later stages
    event.dst_ip = 0; // Will be filled by later stages
    event.src_port = 0;
    event.dst_port = 0;
    event.seq = 0;
    event.ack_seq = 0;
    event.tcp_flags = 0;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Store SKB pointer as a "flow ID" for Stage 0
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        bpf_probe_read_kernel_str(event.ifname, sizeof(event.ifname), dev->name);
    }
    
    // Submit with SKB pointer as identifier - later stages will match this
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 0: Keep __netif_receive_skb for incoming (works fine)
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 1) return 0; // Only for incoming
    if (!is_target_ifindex(skb)) return 0;
    return process_tcp_packet(ctx, skb, 0);
}

// Stage 1: Stack processing (keep existing, they work)
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) return 0;
    return process_tcp_packet(ctx, skb, 1);
}

int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    if (TRACE_DIRECTION != 1) return 0;
    
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }
    return process_tcp_packet(ctx, skb, 1);
}

// Stage 2-5: OVS processing (keep existing, they work)
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    return process_tcp_packet(ctx, skb, 2);
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    return process_tcp_packet(ctx, skb, 3);
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    return process_tcp_packet(ctx, skb, 4);
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    return process_tcp_packet(ctx, skb, 5);
}

// Stage 6: Final probes (keep existing, they work)
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 0) return 0;
    if (!is_target_ifindex(skb)) return 0;
    return process_tcp_packet(ctx, skb, 6);
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (TRACE_DIRECTION != 1) return 0;
    return process_tcp_packet(ctx, skb, 6);
}
"""

class TcpEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("stage_id", ctypes.c_uint32),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack_seq", ctypes.c_uint32),
        ("tcp_flags", ctypes.c_uint8),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("ifname", ctypes.c_char * 16)
    ]

# Storage for tracking flows
flows = {}
stage_names = {
    0: "IP_SEND/NETIF_RCV", 1: "STACK_PROC", 2: "OVS_DP_PROC",
    3: "OVS_UPCALL", 4: "OVS_KEYEXT", 5: "OVS_VPORT", 6: "DEV_QUEUE/TCP_RCV"
}

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

def get_tcp_flags_str(flags):
    flag_str = ""
    if flags & 0x01: flag_str += "F"  # FIN
    if flags & 0x02: flag_str += "S"  # SYN
    if flags & 0x04: flag_str += "R"  # RST
    if flags & 0x08: flag_str += "P"  # PSH
    if flags & 0x10: flag_str += "A"  # ACK
    if flags & 0x20: flag_str += "U"  # URG
    return flag_str if flag_str else "."

def print_event(cpu, data, size):
    global args
    event = ctypes.cast(data, ctypes.POINTER(TcpEvent)).contents
    
    # Create flow key
    flow_key = (event.src_ip, event.dst_ip, event.src_port, event.dst_port, 
                socket.ntohl(event.seq), socket.ntohl(event.ack_seq))
    
    if flow_key not in flows:
        flows[flow_key] = {
            'stages': {},
            'first_ts': event.ts,
            'pid': event.pid,
            'comm': event.comm.decode('utf-8', 'replace'),
            'ifname': event.ifname.decode('utf-8', 'replace'),
            'tcp_flags': event.tcp_flags
        }
    
    flows[flow_key]['stages'][event.stage_id] = event.ts
    
    # Print event immediately
    now = datetime.datetime.now()
    time_str = now.strftime("%H:%M:%S.%f")[:-3]
    
    print("[%s] Stage %d (%s): %s:%d -> %s:%d (SEQ:%u ACK:%u FLAGS:%s) PID:%d COMM:%s IF:%s" % (
        time_str,
        event.stage_id,
        stage_names.get(event.stage_id, "UNKNOWN"),
        format_ip(event.src_ip),
        socket.ntohs(event.src_port),
        format_ip(event.dst_ip),
        socket.ntohs(event.dst_port),
        socket.ntohl(event.seq),
        socket.ntohl(event.ack_seq),
        get_tcp_flags_str(event.tcp_flags),
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        event.ifname.decode('utf-8', 'replace')
    ))
    
    # If we have both start and end stages, calculate latency
    flow = flows[flow_key]
    if 0 in flow['stages'] and 6 in flow['stages']:
        total_latency_ns = flow['stages'][6] - flow['stages'][0]
        total_latency_us = total_latency_ns / 1000.0
        
        print("  ==> COMPLETE FLOW LATENCY: %.3f us" % total_latency_us)
        
        # Print stage-by-stage latencies
        sorted_stages = sorted(flow['stages'].keys())
        for i in range(len(sorted_stages) - 1):
            start_stage = sorted_stages[i]
            end_stage = sorted_stages[i + 1]
            stage_latency_ns = flow['stages'][end_stage] - flow['stages'][start_stage]
            stage_latency_us = stage_latency_ns / 1000.0
            print("      Stage %d->%d: %.3f us" % (start_stage, end_stage, stage_latency_us))
        
        # Clean up completed flow
        del flows[flow_key]
        print()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    print("=== TCP Latency Tracer (Corrected Version) ===")
    
    parser = argparse.ArgumentParser(
        description="TCP latency tracer with corrected probe points",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--src-ip', type=str, required=True, 
                      help='Source IP address')
    parser.add_argument('--dst-ip', type=str, required=True,
                      help='Destination IP address')
    parser.add_argument('--src-port', type=int, default=0,
                      help='Source port (0 = any)')
    parser.add_argument('--dst-port', type=int, default=0,
                      help='Destination port (0 = any)')
    parser.add_argument('--phy-iface1', type=str, required=True,
                      help='Physical interface to monitor')
    parser.add_argument('--phy-iface2', type=str, required=False, default=None,
                      help='Second physical interface to monitor')
    parser.add_argument('--direction', type=str, choices=["outgoing", "incoming"], default="outgoing",
                      help='Direction: outgoing or incoming')
    
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
    
    print("Source IP: %s (0x%x)" % (args.src_ip, socket.ntohl(src_ip_hex_val))) 
    print("Destination IP: %s (0x%x)" % (args.dst_ip, socket.ntohl(dst_ip_hex_val)))
    print("Direction: %s" % args.direction.upper())
    print("Interface: %s (ifindex %d)" % (args.phy_iface1, ifindex1))
    print("KEY CHANGE: Using ip_send_skb instead of __tcp_transmit_skb for Stage 0")
    
    print("\nLoading BPF program...")
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex_val, dst_ip_hex_val, args.src_port, args.dst_port,
            ifindex1, ifindex2, direction_val  
        ))
        print("BPF program loaded successfully!")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event) 
    
    print("\nTracing TCP latency... Press Ctrl-C to stop")
    print("Generate some TCP traffic to see results...\n")
    
    try:
        while True:
            b.perf_buffer_poll() 
    except KeyboardInterrupt:
        print("\nStopping tracer...")
    finally:
        print("Exiting.")