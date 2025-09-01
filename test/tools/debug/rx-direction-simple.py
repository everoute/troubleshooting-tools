#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
RX Direction Analysis Tool - Simplified Version

简化版本的socket方向分析工具，避免复杂的BPF内存访问问题。
重点验证socket和数据包地址的对应关系理论。
"""

from bcc import BPF
import time
import argparse
import socket
import struct

# Simplified BPF program 
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Filter configuration
#define TARGET_IP 0x%x

struct simple_direction_event {
    u64 timestamp;
    u32 probe_id;          // 1=tcp_v4_rcv, 2=sock_queue_rcv_skb, 3=tcp_recvmsg
    u32 pid;
    char comm[16];
    
    // Basic addresses for direction analysis
    u64 skb_addr;
    u64 sk_addr;
    
    // Simple packet info (if available)
    u32 pkt_src_ip;
    u32 pkt_dst_ip;
    u16 pkt_src_port;
    u16 pkt_dst_port;
    u8 pkt_protocol;
    u8 pkt_parsed;
    
    // Simple socket info (if available)
    u32 sock_local_ip;     // inet_rcv_saddr
    u32 sock_remote_ip;    // inet_daddr
    u16 sock_local_port;   // inet_num
    u16 sock_remote_port;  // inet_dport
    u8 sock_state;
    u8 sock_parsed;
};

BPF_PERF_OUTPUT(events);

// Simple packet parsing from SKB
static __always_inline int try_parse_packet(struct sk_buff *skb, struct simple_direction_event *event) {
    if (!skb) return 0;
    
    event->skb_addr = (u64)skb;
    
    // Try to get basic packet info - simplified approach
    unsigned char *head = NULL;
    u16 network_header = 0;
    
    // Read head and network_header safely
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) != 0) return 0;
    
    // Basic validation
    if (network_header == (u16)~0U || network_header > 1500 || !head) return 0;
    
    // Try to read IP header
    struct iphdr ip_hdr;
    if (bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr), head + network_header) != 0) return 0;
    
    // Validate IPv4
    if ((ip_hdr.version & 0xF) != 4) return 0;
    
    // Extract basic info
    event->pkt_src_ip = ip_hdr.saddr;
    event->pkt_dst_ip = ip_hdr.daddr;  
    event->pkt_protocol = ip_hdr.protocol;
    
    // Try transport header (optional)
    u16 transport_header = 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) == 0 &&
        transport_header != (u16)~0U && transport_header < 1500) {
        
        if (ip_hdr.protocol == IPPROTO_TCP) {
            struct tcphdr tcp_hdr;
            if (bpf_probe_read_kernel(&tcp_hdr, sizeof(tcp_hdr), head + transport_header) == 0) {
                event->pkt_src_port = tcp_hdr.source;
                event->pkt_dst_port = tcp_hdr.dest;
            }
        }
    }
    
    return 1;
}

// Simple socket parsing
static __always_inline int try_parse_socket(struct sock *sk, struct simple_direction_event *event) {
    if (!sk) return 0;
    
    event->sk_addr = (u64)sk;
    
    // Get basic socket info
    u16 family = 0;
    u8 state = 0;
    
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family) != 0) return 0;
    if (bpf_probe_read_kernel(&state, sizeof(state), &sk->sk_state) != 0) return 0;
    
    event->sock_state = state;
    
    if (family != AF_INET) return 0;
    
    // Try to get inet_sock info - use common struct offsets
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) return 0;
    
    // Read socket addresses using known fields
    if (bpf_probe_read_kernel(&event->sock_local_ip, sizeof(event->sock_local_ip), 
                             &inet->sk.__sk_common.skc_rcv_saddr) != 0) return 0;
    if (bpf_probe_read_kernel(&event->sock_remote_ip, sizeof(event->sock_remote_ip), 
                             &inet->sk.__sk_common.skc_daddr) != 0) return 0;
    if (bpf_probe_read_kernel(&event->sock_local_port, sizeof(event->sock_local_port), 
                             &inet->sk.__sk_common.skc_num) != 0) return 0;
    if (bpf_probe_read_kernel(&event->sock_remote_port, sizeof(event->sock_remote_port), 
                             &inet->sk.__sk_common.skc_dport) != 0) return 0;
    
    return 1;
}

// Apply basic filtering
static __always_inline int should_trace(struct simple_direction_event *event) {
    if (TARGET_IP == 0) return 1;
    
    // Check if any address matches target
    if (event->pkt_parsed && 
        (event->pkt_src_ip == TARGET_IP || event->pkt_dst_ip == TARGET_IP)) return 1;
        
    if (event->sock_parsed && 
        (event->sock_local_ip == TARGET_IP || event->sock_remote_ip == TARGET_IP)) return 1;
    
    return (TARGET_IP == 0) ? 1 : 0;
}

// Probe 1: tcp_v4_rcv
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct simple_direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 1;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Try to parse packet
    event.pkt_parsed = try_parse_packet(skb, &event);
    
    // Try to get socket from SKB
    struct sock *sk = NULL;
    if (skb && bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk) == 0 && sk) {
        event.sock_parsed = try_parse_socket(sk, &event);
    }
    
    if (should_trace(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 2: sock_queue_rcv_skb
int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct simple_direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 2;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Try to parse packet
    event.pkt_parsed = try_parse_packet(skb, &event);
    
    // Try to parse socket
    event.sock_parsed = try_parse_socket(sk, &event);
    
    if (should_trace(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 3: tcp_recvmsg
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    struct simple_direction_event event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 3;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // No packet available
    event.pkt_parsed = 0;
    
    // Try to parse socket
    event.sock_parsed = try_parse_socket(sk, &event);
    
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
    """Process and print simplified direction events"""
    event = b["events"].event(data)
    
    print("\n--- %s [%s] PID: %d COMM: %s ---" % (
        get_probe_name(event.probe_id),
        time.strftime("%H:%M:%S"),
        event.pid,
        event.comm.decode('utf-8', 'replace')
    ))
    
    # Packet info
    if event.pkt_parsed:
        print("PACKET: %s:%d -> %s:%d [%d] (SKB: %#x)" % (
            hex_to_ip(event.pkt_src_ip), port_to_int(event.pkt_src_port),
            hex_to_ip(event.pkt_dst_ip), port_to_int(event.pkt_dst_port),
            event.pkt_protocol, event.skb_addr
        ))
    else:
        print("PACKET: Not parsed (SKB: %#x)" % event.skb_addr)
    
    # Socket info
    if event.sock_parsed:
        print("SOCKET: Local %s:%d <-> Remote %s:%d [%s] (SK: %#x)" % (
            hex_to_ip(event.sock_local_ip), event.sock_local_port,
            hex_to_ip(event.sock_remote_ip), port_to_int(event.sock_remote_port),
            get_tcp_state_name(event.sock_state), event.sk_addr
        ))
    else:
        print("SOCKET: Not parsed (SK: %#x)" % event.sk_addr)
    
    # Direction analysis
    if event.pkt_parsed and event.sock_parsed:
        src_match = (event.pkt_src_ip == event.sock_remote_ip and 
                    event.pkt_src_port == event.sock_remote_port)
        dst_match = (event.pkt_dst_ip == event.sock_local_ip and 
                    event.pkt_dst_port == event.sock_local_port)
        
        print("ANALYSIS: Packet SRC -> Socket REMOTE: %s" % ("MATCH ✅" if src_match else "MISMATCH ❌"))
        print("          Packet DST -> Socket LOCAL:  %s" % ("MATCH ✅" if dst_match else "MISMATCH ❌"))
        
        if src_match and dst_match:
            print("RESULT: Perfect RX direction correlation! 🎯")
        else:
            print("RESULT: Address correlation issues detected ⚠️")

def main():
    parser = argparse.ArgumentParser(description='Simple RX Direction Analysis Tool')
    parser.add_argument('--target-ip', help='Target IP address filter')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    
    args = parser.parse_args()
    
    target_ip_hex = ip_to_hex(args.target_ip) if args.target_ip else 0
    
    print("=== Simple RX Direction Analysis Tool ===")
    print("Analyzing socket and packet address correlation for RX direction")
    if args.target_ip:
        print("Target IP filter: %s" % args.target_ip)
    print("Duration: %d seconds" % args.duration)
    print("\nTheory: RX packets should have:")
    print("- Packet SRC = Socket REMOTE (where packet comes from)")
    print("- Packet DST = Socket LOCAL  (where packet goes to)")
    print()
    
    global b
    b = BPF(text=bpf_text % target_ip_hex)
    print("BPF program loaded successfully")
    
    b["events"].open_perf_buffer(print_event)
    
    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
    finally:
        print("\n=== Analysis completed ===")

if __name__ == "__main__":
    main()