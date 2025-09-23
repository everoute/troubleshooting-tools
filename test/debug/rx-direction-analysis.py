#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
RX Direction Analysis Tool

系统分析socket方向信息和数据包header地址对应关系：
- Socket中存储的是本地视角的连接信息
- inet_saddr/inet_sport: 本地发送地址/端口（在RX时是目标） 
- inet_daddr/inet_dport: 远程地址/端口（在RX时是源地址）
- 数据包header中的地址是网络视角的源和目标

核心对应关系分析：
RX方向：数据包从远程发送到本地
- Packet src (skb) = Socket remote (inet_daddr/dport)  
- Packet dst (skb) = Socket local (inet_rcv_saddr/num)
"""

from bcc import BPF
import time
import argparse
import socket
import struct

# Enhanced BPF program for direction analysis
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <net/tcp_states.h>

// Filter configuration
#define TARGET_IP 0x%x

// Direction analysis event
struct direction_event {
    u64 timestamp;
    u32 probe_id;          // 1=tcp_v4_rcv, 2=sock_queue_rcv_skb, 3=tcp_recvmsg
    u32 pid;
    char comm[16];
    
    // SKB packet header information (network view)
    u64 skb_addr;
    u32 pkt_src_ip;        // Packet source IP (from network header)
    u32 pkt_dst_ip;        // Packet destination IP (from network header)
    u16 pkt_src_port;      // Packet source port (from network header)  
    u16 pkt_dst_port;      // Packet destination port (from network header)
    u8 pkt_protocol;
    u8 pkt_parse_success;
    
    // Socket connection information (local view)
    u64 sk_addr;
    u32 sock_local_ip;     // Local IP (inet_rcv_saddr for bound, inet_saddr for sending)
    u32 sock_remote_ip;    // Remote IP (inet_daddr)  
    u16 sock_local_port;   // Local port (inet_num)
    u16 sock_remote_port;  // Remote port (inet_dport)
    u8 sock_state;         // TCP state
    u8 sock_parse_success;
    
    // Direction analysis
    u8 direction_rx;       // 1 if packet direction matches RX expectation
    u8 addresses_match;    // 1 if packet and socket addresses correlate correctly
    
    // Additional socket info
    u32 sock_sending_ip;   // inet_saddr (used when sending)
    u16 sock_sending_port; // inet_sport (used when sending)
    u8 sock_family;
    u8 sock_type;
};

BPF_PERF_OUTPUT(events);

// Helper: Parse packet header from SKB
static __always_inline int parse_packet_header(struct sk_buff *skb, struct direction_event *event) {
    if (!skb) return 0;
    
    event->skb_addr = (u64)skb;
    
    // Get network header
    unsigned char *head = NULL;
    u16 network_header = 0;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0 ||
        bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) != 0) {
        return 0;
    }
    
    if (network_header == (u16)~0U || network_header > 2048 || !head) {
        return 0;
    }
    
    // Parse IP header
    struct iphdr ip_hdr;
    if (bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr), head + network_header) != 0) {
        return 0;
    }
    
    if (ip_hdr.version != 4) return 0;
    
    // Extract packet addressing (network view)
    event->pkt_src_ip = ip_hdr.saddr;     // Network packet source
    event->pkt_dst_ip = ip_hdr.daddr;     // Network packet destination
    event->pkt_protocol = ip_hdr.protocol;
    
    // Parse transport header for ports
    u16 transport_header = 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) != 0) {
        return 1; // IP parsed successfully, ports optional
    }
    
    if (transport_header == (u16)~0U || transport_header > 2048) {
        return 1;
    }
    
    if (ip_hdr.protocol == IPPROTO_TCP) {
        struct tcphdr tcp_hdr;
        if (bpf_probe_read_kernel(&tcp_hdr, sizeof(tcp_hdr), head + transport_header) == 0) {
            event->pkt_src_port = tcp_hdr.source;   // Network packet source port
            event->pkt_dst_port = tcp_hdr.dest;     // Network packet destination port
        }
    } else if (ip_hdr.protocol == IPPROTO_UDP) {
        struct udphdr udp_hdr;
        if (bpf_probe_read_kernel(&udp_hdr, sizeof(udp_hdr), head + transport_header) == 0) {
            event->pkt_src_port = udp_hdr.source;
            event->pkt_dst_port = udp_hdr.dest;
        }
    }
    
    return 1;
}

// Helper: Parse socket connection information
static __always_inline int parse_socket_info(struct sock *sk, struct direction_event *event) {
    if (!sk) return 0;
    
    event->sk_addr = (u64)sk;
    event->sock_family = sk->sk_family;
    event->sock_state = sk->sk_state;
    
    // Skip socket type due to bit-field access issues
    event->sock_type = 0;
    
    if (event->sock_family != AF_INET) return 0;
    
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) return 0;
    
    // Extract socket addressing (local connection view)
    // inet_rcv_saddr: 绑定的本地地址（接收时的本地地址）
    // inet_saddr: 发送时使用的源地址  
    // inet_daddr: 目标地址（连接的远程地址）
    // inet_num: 本地端口号
    // inet_dport: 目标端口（远程端口）
    // inet_sport: 源端口（发送时的本地端口）
    
    if (bpf_probe_read_kernel(&event->sock_local_ip, sizeof(event->sock_local_ip), &inet->sk.__sk_common.skc_rcv_saddr) != 0 ||
        bpf_probe_read_kernel(&event->sock_remote_ip, sizeof(event->sock_remote_ip), &inet->sk.__sk_common.skc_daddr) != 0 ||
        bpf_probe_read_kernel(&event->sock_local_port, sizeof(event->sock_local_port), &inet->sk.__sk_common.skc_num) != 0 ||
        bpf_probe_read_kernel(&event->sock_remote_port, sizeof(event->sock_remote_port), &inet->sk.__sk_common.skc_dport) != 0) {
        return 0;
    }
    
    // Additional socket addresses
    bpf_probe_read_kernel(&event->sock_sending_ip, sizeof(event->sock_sending_ip), &inet->inet_saddr);
    bpf_probe_read_kernel(&event->sock_sending_port, sizeof(event->sock_sending_port), &inet->inet_sport);
    
    return 1;
}

// Helper: Analyze packet direction and address correlation
static __always_inline void analyze_direction(struct direction_event *event) {
    if (!event->pkt_parse_success || !event->sock_parse_success) {
        event->direction_rx = 0;
        event->addresses_match = 0;
        return;
    }
    
    // RX Direction Analysis:
    // 对于接收方向的数据包：
    // - 数据包的源地址/端口 应该匹配 socket的远程地址/端口 (inet_daddr/dport)
    // - 数据包的目标地址/端口 应该匹配 socket的本地地址/端口 (inet_rcv_saddr/num)
    
    bool src_match = (event->pkt_src_ip == event->sock_remote_ip && 
                      event->pkt_src_port == event->sock_remote_port);
    bool dst_match = (event->pkt_dst_ip == event->sock_local_ip && 
                      event->pkt_dst_port == event->sock_local_port);
    
    event->direction_rx = (src_match && dst_match) ? 1 : 0;
    event->addresses_match = event->direction_rx;
}

// Helper: Apply filters
static __always_inline int should_trace(struct direction_event *event) {
    if (TARGET_IP != 0) {
        bool ip_match = false;
        
        // Check any IP involvement
        if (event->pkt_parse_success && 
            (event->pkt_src_ip == TARGET_IP || event->pkt_dst_ip == TARGET_IP)) {
            ip_match = true;
        }
        
        if (event->sock_parse_success &&
            (event->sock_local_ip == TARGET_IP || event->sock_remote_ip == TARGET_IP)) {
            ip_match = true;
        }
        
        if (!ip_match) return 0;
    }
    
    return 1;
}

// Probe 1: tcp_v4_rcv - Protocol layer with packet and socket
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 1;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Parse packet header
    event.pkt_parse_success = parse_packet_header(skb, &event);
    
    // Try to get socket from SKB
    struct sock *sk = NULL;
    if (skb && bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk) == 0) {
        event.sock_parse_success = parse_socket_info(sk, &event);
    }
    
    // Analyze direction
    analyze_direction(&event);
    
    if (should_trace(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 2: sock_queue_rcv_skb - Socket buffer layer
int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 2;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Parse packet header
    event.pkt_parse_success = parse_packet_header(skb, &event);
    
    // Parse socket info
    event.sock_parse_success = parse_socket_info(sk, &event);
    
    // Analyze direction
    analyze_direction(&event);
    
    if (should_trace(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 3: tcp_recvmsg - Socket layer (socket only)
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    struct direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 3;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // No packet header available in tcp_recvmsg
    event.pkt_parse_success = 0;
    
    // Parse socket info
    event.sock_parse_success = parse_socket_info(sk, &event);
    
    // Can't analyze packet direction without packet header
    event.direction_rx = 0;
    event.addresses_match = 0;
    
    if (should_trace(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}
"""

def ip_to_hex(ip_str):
    """Convert IP string to hex for BPF filter"""
    if not ip_str:
        return 0
    try:
        return struct.unpack("=I", socket.inet_aton(ip_str))[0]
    except:
        return 0

def hex_to_ip(hex_val):
    """Convert hex back to IP string"""
    if hex_val == 0:
        return "0.0.0.0"
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", hex_val))

def port_to_int(port_net):
    """Convert network byte order port to int"""
    return socket.ntohs(port_net)

def get_probe_name(probe_id):
    """Get probe name by ID"""
    names = {1: "tcp_v4_rcv", 2: "sock_queue_rcv_skb", 3: "tcp_recvmsg"}
    return names.get(probe_id, "unknown_%d" % probe_id)

def get_tcp_state_name(state):
    """Get TCP state name"""
    states = {
        1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
        5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
        9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"
    }
    return states.get(state, "STATE_%d" % state)

def print_event(cpu, data, size):
    """Process and print direction analysis events"""
    event = b["events"].event(data)
    
    print("\n" + "="*80)
    print("PROBE: %-20s [%s] PID: %-5d COMM: %s" % (
        get_probe_name(event.probe_id),
        time.strftime("%H:%M:%S"),
        event.pid,
        event.comm.decode('utf-8', 'replace')
    ))
    
    # Packet Header Analysis (Network View)
    print("\n📦 PACKET HEADER (Network View):")
    if event.pkt_parse_success:
        print("   SKB: %#x" % event.skb_addr)
        print("   Packet Flow: %s:%d -> %s:%d [Protocol: %d]" % (
            hex_to_ip(event.pkt_src_ip), port_to_int(event.pkt_src_port),
            hex_to_ip(event.pkt_dst_ip), port_to_int(event.pkt_dst_port),
            event.pkt_protocol
        ))
        print("   Network Direction: %s -> %s (RX direction to local)" % (
            hex_to_ip(event.pkt_src_ip), hex_to_ip(event.pkt_dst_ip)
        ))
    else:
        print("   ❌ Packet parsing FAILED")
    
    # Socket Connection Analysis (Local View)
    print("\n🔌 SOCKET CONNECTION (Local View):")
    if event.sock_parse_success:
        print("   Socket: %#x Family: %d Type: %d State: %s" % (
            event.sk_addr, event.sock_family, event.sock_type,
            get_tcp_state_name(event.sock_state)
        ))
        print("   Local Binding: %s:%d (inet_rcv_saddr/num)" % (
            hex_to_ip(event.sock_local_ip), event.sock_local_port
        ))
        print("   Remote Endpoint: %s:%d (inet_daddr/dport)" % (
            hex_to_ip(event.sock_remote_ip), port_to_int(event.sock_remote_port)
        ))
        print("   Sending From: %s:%d (inet_saddr/sport)" % (
            hex_to_ip(event.sock_sending_ip), port_to_int(event.sock_sending_port)
        ))
    else:
        print("   ❌ Socket parsing FAILED")
    
    # Direction Correlation Analysis
    print("\n🔍 DIRECTION CORRELATION ANALYSIS:")
    if event.pkt_parse_success and event.sock_parse_success:
        print("   Expected RX mapping:")
        print("     Packet SRC %s:%d <==> Socket REMOTE %s:%d %s" % (
            hex_to_ip(event.pkt_src_ip), port_to_int(event.pkt_src_port),
            hex_to_ip(event.sock_remote_ip), port_to_int(event.sock_remote_port),
            "✅" if (event.pkt_src_ip == event.sock_remote_ip and 
                    event.pkt_src_port == event.sock_remote_port) else "❌"
        ))
        print("     Packet DST %s:%d <==> Socket LOCAL %s:%d %s" % (
            hex_to_ip(event.pkt_dst_ip), port_to_int(event.pkt_dst_port),
            hex_to_ip(event.sock_local_ip), event.sock_local_port,
            "✅" if (event.pkt_dst_ip == event.sock_local_ip and 
                    event.pkt_dst_port == event.sock_local_port) else "❌"
        ))
        
        if event.direction_rx and event.addresses_match:
            print("   🎯 RESULT: PERFECT RX DIRECTION MATCH - Packet correlates correctly with socket")
        else:
            print("   ⚠️  RESULT: Direction mismatch - May indicate parsing error or different flow")
    else:
        print("   ⏭️  Cannot analyze - insufficient parsing data")

def main():
    parser = argparse.ArgumentParser(description='RX Direction Analysis Tool')
    parser.add_argument('--target-ip', help='Target IP address filter')
    parser.add_argument('--duration', type=int, default=15, help='Duration in seconds (default: 15)')
    
    args = parser.parse_args()
    
    # Setup filter
    target_ip_hex = ip_to_hex(args.target_ip) if args.target_ip else 0
    
    print("=== RX Direction Analysis Tool ===")
    print("Analyzing socket direction and packet-to-socket address correlation")
    if args.target_ip:
        print("Target IP filter: %s (0x%x)" % (args.target_ip, target_ip_hex))
    print("Duration: %d seconds" % args.duration)
    print("\nKey Analysis:")
    print("- Packet Header: Network view (src->dst)")  
    print("- Socket Info: Local view (local<->remote)")
    print("- RX Direction: Remote sends TO local")
    print("- Expected: Packet SRC = Socket REMOTE, Packet DST = Socket LOCAL")
    print()
    
    # Compile and load BPF program
    global b
    b = BPF(text=bpf_text % target_ip_hex)
    print("BPF program loaded successfully")
    
    # Setup perf buffer
    b["events"].open_perf_buffer(print_event)
    
    # Start tracing
    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
    finally:
        print("\n" + "="*80)
        print("=== Direction Analysis Completed ===")
        print("Summary: This tool demonstrates how to correlate network packet headers")
        print("with socket connection information to understand RX packet flow direction.")

if __name__ == "__main__":
    main()