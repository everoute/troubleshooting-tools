#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
RX 5-tuple Debug Tool

Analyze 5-tuple parsing from different probe points:
- tcp_v4_rcv: Parse 5-tuple from SKB 
- tcp_recvmsg: Parse 5-tuple from SOCK

Compare effectiveness of two parsing methods.
"""

from bcc import BPF
import time
import argparse
import socket
import struct

# BPF程序 - 专注于5元组解析
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

// 目标IP过滤 (0 = 不过滤)
#define TARGET_IP 0x%x

// 调试事件结构
struct tuple_event {
    u64 timestamp;
    u32 probe_id;          // 1=tcp_v4_rcv, 2=tcp_recvmsg
    u32 pid;
    char comm[16];
    
    // 解析结果
    u8 parse_success;      // 是否成功解析
    
    // 5元组信息
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    
    // 附加信息
    u64 skb_addr;
    u64 sock_addr;
};

BPF_PERF_OUTPUT(events);

// 辅助函数：从SKB解析5元组
static __always_inline int parse_skb_tuple(struct sk_buff *skb, struct tuple_event *event) {
    if (!skb) return 0;
    
    event->skb_addr = (u64)skb;
    
    // 尝试获取网络层头部
    unsigned char *head = NULL;
    u16 network_header_offset = 0;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) != 0) {
        return 0;
    }
    
    // 检查网络头部偏移是否有效
    if (network_header_offset == (u16)~0U || network_header_offset > 2048 || !head) {
        return 0;
    }
    
    // 读取IP头部
    struct iphdr ip_header;
    if (bpf_probe_read_kernel(&ip_header, sizeof(ip_header), head + network_header_offset) != 0) {
        return 0;
    }
    
    // 检查是否为IPv4
    if (ip_header.version != 4) {
        return 0;
    }
    
    // 提取IP信息
    event->src_ip = ip_header.saddr;
    event->dst_ip = ip_header.daddr;
    event->protocol = ip_header.protocol;
    
    // 计算传输层头部偏移
    u16 transport_header_offset = 0;
    if (bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) != 0) {
        return 1; // IP信息已获取，传输层可选
    }
    
    if (transport_header_offset == (u16)~0U || transport_header_offset > 2048) {
        return 1; // IP信息已获取，传输层可选
    }
    
    // 根据协议类型解析端口
    if (ip_header.protocol == IPPROTO_TCP) {
        struct tcphdr tcp_header;
        if (bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), head + transport_header_offset) == 0) {
            event->src_port = tcp_header.source;
            event->dst_port = tcp_header.dest;
        }
    } else if (ip_header.protocol == IPPROTO_UDP) {
        struct udphdr udp_header;
        if (bpf_probe_read_kernel(&udp_header, sizeof(udp_header), head + transport_header_offset) == 0) {
            event->src_port = udp_header.source;
            event->dst_port = udp_header.dest;
        }
    }
    
    return 1;
}

// 辅助函数：从SOCK解析5元组
static __always_inline int parse_sock_tuple(struct sock *sk, struct tuple_event *event) {
    if (!sk) return 0;
    
    event->sock_addr = (u64)sk;
    
    // 获取socket family
    u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family) != 0) {
        return 0;
    }
    
    if (family != AF_INET) {
        return 0; // 只处理IPv4
    }
    
    // 获取inet_sock结构
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) {
        return 0;
    }
    
    // 读取连接5元组信息
    if (bpf_probe_read_kernel(&event->src_ip, sizeof(event->src_ip), &inet->inet_saddr) != 0 ||
        bpf_probe_read_kernel(&event->dst_ip, sizeof(event->dst_ip), &inet->inet_daddr) != 0 ||
        bpf_probe_read_kernel(&event->src_port, sizeof(event->src_port), &inet->inet_sport) != 0 ||
        bpf_probe_read_kernel(&event->dst_port, sizeof(event->dst_port), &inet->inet_dport) != 0) {
        return 0;
    }
    
    // 确定协议类型 - tcp_recvmsg context通常是TCP
    event->protocol = IPPROTO_TCP;
    
    return 1;
}

// 检查是否应该跟踪此事件
static __always_inline int should_trace_tuple(struct tuple_event *event) {
    if (TARGET_IP != 0) {
        if (event->src_ip != TARGET_IP && event->dst_ip != TARGET_IP) {
            return 0;
        }
    }
    return 1;
}

// Probe 1: tcp_v4_rcv - 使用SKB解析
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct tuple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 1;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 使用SKB解析5元组
    event.parse_success = parse_skb_tuple(skb, &event);
    
    if (event.parse_success && should_trace_tuple(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 2: sock_queue_rcv_skb - 使用SOCK解析 (有SKB和SOCK两个参数)
int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct tuple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 2;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 这个probe点同时有SKB和SOCK，我们使用SOCK解析
    event.parse_success = parse_sock_tuple(sk, &event);
    
    // 同时记录SKB地址
    if (skb) {
        event.skb_addr = (u64)skb;
    }
    
    if (event.parse_success && should_trace_tuple(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// Probe 3: tcp_recvmsg - 使用SOCK解析 (主要是SOCK，但可能通过其他方式访问SKB)
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
    struct tuple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 3;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 使用SOCK解析5元组
    event.parse_success = parse_sock_tuple(sk, &event);
    
    // tcp_recvmsg参数中没有直接的skb，但可以尝试从socket接收队列获取
    // 注意：这个访问比较复杂，可能在某些内核版本中不可用
    if (sk && event.parse_success) {
        // 尝试从socket的接收队列头部获取SKB（仅作为示例，可能不稳定）
        // 实际的SKB访问在tcp_recvmsg中通常通过复杂的队列操作
        event.skb_addr = 0;  // tcp_recvmsg通常不直接暴露SKB指针
    }
    
    if (event.parse_success && should_trace_tuple(&event)) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}
"""

def ip_to_str(ip):
    """将网络字节序IP转换为字符串"""
    return socket.inet_ntoa(struct.pack('I', ip))

def port_to_int(port):
    """将网络字节序端口转换为整数"""
    return socket.ntohs(port)

def protocol_to_str(proto):
    """协议号转字符串"""
    if proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    elif proto == 1:
        return "ICMP"
    else:
        return "PROTO_%d" % proto

def probe_to_str(probe_id):
    """probe ID转字符串"""
    if probe_id == 1:
        return "tcp_v4_rcv(SKB)"
    elif probe_id == 2:
        return "sock_queue_rcv_skb(SOCK)"
    elif probe_id == 3:
        return "tcp_recvmsg(SOCK)"
    else:
        return "unknown_%d" % probe_id

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    print("[%s] PID:%-5d COMM:%-16s PROBE:%-18s SUCCESS:%-5s" % (
        time.strftime("%H:%M:%S"),
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        probe_to_str(event.probe_id),
        "YES" if event.parse_success else "NO"
    ))
    
    if event.parse_success:
        print("        5-tuple: %s:%d -> %s:%d [%s]" % (
            ip_to_str(event.src_ip), port_to_int(event.src_port),
            ip_to_str(event.dst_ip), port_to_int(event.dst_port),
            protocol_to_str(event.protocol)
        ))
        
        if event.skb_addr:
            print("        SKB: %#x" % event.skb_addr)
        if event.sock_addr:
            print("        SOCK: %#x" % event.sock_addr)
    
    print("")

def main():
    parser = argparse.ArgumentParser(description='RX 5-tuple debug tool')
    parser.add_argument('--target-ip', help='Target IP address filter')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    
    args = parser.parse_args()
    
    # IP地址转换
    target_ip_hex = 0
    if args.target_ip:
        target_ip_hex = struct.unpack("I", socket.inet_aton(args.target_ip))[0]
    
    print("=== RX 5-tuple Debug Tool ===")
    if args.target_ip:
        print("Target IP filter: %s (0x%x)" % (args.target_ip, target_ip_hex))
    else:
        print("No IP filter (all traffic)")
    print("Duration: %d seconds" % args.duration)
    print("Comparing SKB and SOCK tuple parsing methods...")
    print()
    
    global b
    b = BPF(text=bpf_text % target_ip_hex)
    
    # Bind event handler
    b["events"].open_perf_buffer(print_event)
    
    print("Starting trace... Hit Ctrl-C to end")
    print()
    
    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
    finally:
        print("\n=== 5-tuple parsing debug completed ===")

if __name__ == "__main__":
    main()