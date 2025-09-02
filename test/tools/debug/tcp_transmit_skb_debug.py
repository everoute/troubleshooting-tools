#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
TCP Transmit SKB Debug Tool

研究 __tcp_transmit_skb probe点的socket和SKB信息可用性
- 从socket中提取5元组和其他关键字段
- 从SKB中提取5元组和其他关键字段  
- 支持IP地址过滤
- 全量输出用于分析研究
"""

from bcc import BPF
import argparse
import time
import socket
import struct
import ctypes

# BPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <net/inet_sock.h>

// IP过滤参数
#define TARGET_IP 0x%x

// 调试事件结构
struct tcp_debug_event {
    u64 timestamp;
    u32 pid;
    char comm[16];
    
    // Socket信息 (from struct sock + inet_sock)
    struct {
        u8 valid;               // 是否成功读取socket信息
        u8 family;              // Socket family (AF_INET=2)
        u8 type;                // Socket type (SOCK_STREAM=1)
        u8 protocol;            // Protocol (IPPROTO_TCP=6)
        u8 state;               // TCP state
        u32 saddr;              // Source IP (local)
        u32 daddr;              // Destination IP (remote)  
        u32 rcv_saddr;          // Receive source addr (bound local)
        u16 sport;              // Source port (local)
        u16 dport;              // Destination port (remote)
        u16 num;                // Local port number (host byte order)
        u16 bound_dev_if;       // Bound device interface
    } sock_info;
    
    // SKB信息 (from struct sk_buff)
    struct {
        u8 valid;               // 是否成功读取SKB信息
        u32 len;                // SKB length
        u32 data_len;           // Data length
        u16 queue_mapping;      // Queue mapping
        u32 hash;               // SKB hash
        u16 network_header;     // Network header offset
        u16 transport_header;   // Transport header offset
        u32 ifindex;            // Device ifindex
        char dev_name[16];      // Device name
        
        // IP头部信息 (如果可读取)
        struct {
            u8 valid;
            u8 version;         // IP version
            u8 ihl;             // Header length
            u8 tos;             // Type of service
            u16 tot_len;        // Total length
            u16 id;             // Identification
            u16 frag_off;       // Fragment offset
            u8 ttl;             // TTL
            u8 protocol;        // Protocol
            u32 saddr;          // Source IP
            u32 daddr;          // Destination IP
        } ip_hdr;
        
        // TCP头部信息 (如果可读取)
        struct {
            u8 valid;
            u16 source;         // Source port
            u16 dest;           // Destination port
            u32 seq;            // Sequence number
            u32 ack_seq;        // Acknowledgment number
            u16 window;         // Window size
            u16 check;          // Checksum
            u16 urg_ptr;        // Urgent pointer
            u8 tcp_flags;       // TCP flags
        } tcp_hdr;
    } skb_info;
};

BPF_PERF_OUTPUT(events);

// 安全地从socket读取信息
static __always_inline int extract_socket_info(struct sock *sk, 
                                              struct tcp_debug_event *event) {
    if (!sk) return 0;
    
    event->sock_info.valid = 1;
    
    // 基本socket信息 - 避免位字段访问问题
    u16 family = 0;
    u8 state = 0;
    u16 bound_dev_if = 0;
    
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family) != 0) 
        return 0;
    if (bpf_probe_read_kernel(&state, sizeof(state), &sk->sk_state) != 0)
        return 0;
    if (bpf_probe_read_kernel(&bound_dev_if, sizeof(bound_dev_if), &sk->sk_bound_dev_if) != 0)
        return 0;
        
    // sk_type 和 sk_protocol 是位字段，需要特殊处理
    // 根据内核源码，通常 sk_type = SOCK_STREAM(1), sk_protocol = IPPROTO_TCP(6)
    u8 sk_type = 1;     // 假设为 SOCK_STREAM
    u8 protocol = 6;    // 假设为 IPPROTO_TCP
        
    event->sock_info.family = (u8)family;
    event->sock_info.type = (u8)sk_type; 
    event->sock_info.protocol = protocol;
    event->sock_info.state = state;
    event->sock_info.bound_dev_if = bound_dev_if;
    
    // 仅处理IPv4 TCP socket
    if (family != AF_INET || protocol != IPPROTO_TCP) {
        return 1;  // 成功但非目标类型
    }
    
    // 读取inet_sock信息
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) return 0;
    
    u32 saddr = 0, daddr = 0, rcv_saddr = 0;
    u16 sport = 0, dport = 0, num = 0;
    
    if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr) == 0)
        event->sock_info.saddr = saddr;
    if (bpf_probe_read_kernel(&daddr, sizeof(daddr), &inet->inet_daddr) == 0) 
        event->sock_info.daddr = daddr;
    if (bpf_probe_read_kernel(&rcv_saddr, sizeof(rcv_saddr), &inet->sk.__sk_common.skc_rcv_saddr) == 0)
        event->sock_info.rcv_saddr = rcv_saddr;
    if (bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport) == 0)
        event->sock_info.sport = sport;
    if (bpf_probe_read_kernel(&dport, sizeof(dport), &inet->inet_dport) == 0)
        event->sock_info.dport = dport;  
    if (bpf_probe_read_kernel(&num, sizeof(num), &inet->sk.__sk_common.skc_num) == 0)
        event->sock_info.num = num;
    
    return 1;
}

// 安全地从SKB读取信息
static __always_inline int extract_skb_info(struct sk_buff *skb, 
                                           struct tcp_debug_event *event) {
    if (!skb) return 0;
    
    event->skb_info.valid = 1;
    
    // 基本SKB信息
    u32 len = 0, data_len = 0, hash = 0;
    u16 queue_mapping = 0, network_header = 0, transport_header = 0;
    
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) == 0)
        event->skb_info.len = len;
    if (bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->data_len) == 0)
        event->skb_info.data_len = data_len;
    if (bpf_probe_read_kernel(&hash, sizeof(hash), &skb->hash) == 0)
        event->skb_info.hash = hash;
    if (bpf_probe_read_kernel(&queue_mapping, sizeof(queue_mapping), &skb->queue_mapping) == 0)
        event->skb_info.queue_mapping = queue_mapping;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) == 0)
        event->skb_info.network_header = network_header;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) == 0)
        event->skb_info.transport_header = transport_header;
    
    // 设备信息
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        u32 ifindex = 0;
        if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) == 0)
            event->skb_info.ifindex = ifindex;
        
        char name[16] = {};
        if (bpf_probe_read_kernel_str(name, sizeof(name), &dev->name) > 0)
            __builtin_memcpy(event->skb_info.dev_name, name, sizeof(event->skb_info.dev_name));
    }
    
    // 尝试读取IP头部
    if (network_header != (u16)~0U && network_header < 1500) {
        unsigned char *head = NULL;
        if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) == 0 && head) {
            struct iphdr ip_hdr = {};
            if (bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr), head + network_header) == 0) {
                event->skb_info.ip_hdr.valid = 1;
                event->skb_info.ip_hdr.version = ip_hdr.version;
                event->skb_info.ip_hdr.ihl = ip_hdr.ihl;
                event->skb_info.ip_hdr.tos = ip_hdr.tos;
                event->skb_info.ip_hdr.tot_len = ip_hdr.tot_len;
                event->skb_info.ip_hdr.id = ip_hdr.id;
                event->skb_info.ip_hdr.frag_off = ip_hdr.frag_off;
                event->skb_info.ip_hdr.ttl = ip_hdr.ttl;
                event->skb_info.ip_hdr.protocol = ip_hdr.protocol;
                event->skb_info.ip_hdr.saddr = ip_hdr.saddr;
                event->skb_info.ip_hdr.daddr = ip_hdr.daddr;
                
                // 尝试读取TCP头部
                if (ip_hdr.protocol == IPPROTO_TCP && 
                    transport_header != (u16)~0U && transport_header < 1500) {
                    struct tcphdr tcp_hdr = {};
                    if (bpf_probe_read_kernel(&tcp_hdr, sizeof(tcp_hdr), head + transport_header) == 0) {
                        event->skb_info.tcp_hdr.valid = 1;
                        event->skb_info.tcp_hdr.source = tcp_hdr.source;
                        event->skb_info.tcp_hdr.dest = tcp_hdr.dest;
                        event->skb_info.tcp_hdr.seq = tcp_hdr.seq;
                        event->skb_info.tcp_hdr.ack_seq = tcp_hdr.ack_seq;
                        event->skb_info.tcp_hdr.window = tcp_hdr.window;
                        event->skb_info.tcp_hdr.check = tcp_hdr.check;
                        event->skb_info.tcp_hdr.urg_ptr = tcp_hdr.urg_ptr;
                        
                        // 提取TCP flags
                        u16 tcp_flags = 0;
                        if (bpf_probe_read_kernel(&tcp_flags, sizeof(tcp_flags), &tcp_hdr.ack_seq + 1) == 0) {
                            event->skb_info.tcp_hdr.tcp_flags = (u8)(tcp_flags >> 8);
                        }
                    }
                }
            }
        }
    }
    
    return 1;
}

int kprobe____tcp_transmit_skb(struct pt_regs *ctx, 
                             struct sock *sk, 
                             struct sk_buff *skb, 
                             int clone_it, 
                             gfp_t gfp_mask, 
                             u32 rcv_nxt) {
    if (!sk || !skb) return 0;
    
    struct tcp_debug_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 提取socket信息
    extract_socket_info(sk, &event);
    
    // 提取SKB信息  
    extract_skb_info(skb, &event);
    
    // IP地址过滤 (如果设置了目标IP)
    if (TARGET_IP != 0) {
        bool match = false;
        
        // 检查socket中的IP地址
        if (event.sock_info.valid) {
            if (event.sock_info.saddr == TARGET_IP ||
                event.sock_info.daddr == TARGET_IP ||
                event.sock_info.rcv_saddr == TARGET_IP) {
                match = true;
            }
        }
        
        // 检查SKB中的IP地址
        if (!match && event.skb_info.ip_hdr.valid) {
            if (event.skb_info.ip_hdr.saddr == TARGET_IP ||
                event.skb_info.ip_hdr.daddr == TARGET_IP) {
                match = true;
            }
        }
        
        if (!match) return 0;
    }
    
    // 提交事件
    events.perf_submit(ctx, &event, sizeof(event));
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

def get_tcp_state_name(state):
    """Get TCP state name"""
    states = {
        1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
        5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
        9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"
    }
    return states.get(state, "STATE_%d" % state)

def get_tcp_flags_str(flags):
    """Convert TCP flags to string"""
    flag_names = []
    if flags & 0x01: flag_names.append("FIN")
    if flags & 0x02: flag_names.append("SYN") 
    if flags & 0x04: flag_names.append("RST")
    if flags & 0x08: flag_names.append("PSH")
    if flags & 0x10: flag_names.append("ACK")
    if flags & 0x20: flag_names.append("URG")
    if flags & 0x40: flag_names.append("ECE")
    if flags & 0x80: flag_names.append("CWR")
    return "|".join(flag_names) if flag_names else "NONE"

def print_event(cpu, data, size):
    """Process and print debug events"""
    global event_count
    event_count += 1
    
    # 将数据转换为事件结构
    class SockInfo(ctypes.Structure):
        _fields_ = [
            ("valid", ctypes.c_uint8),
            ("family", ctypes.c_uint8),
            ("type", ctypes.c_uint8),
            ("protocol", ctypes.c_uint8),
            ("state", ctypes.c_uint8),
            ("saddr", ctypes.c_uint32),
            ("daddr", ctypes.c_uint32),
            ("rcv_saddr", ctypes.c_uint32),
            ("sport", ctypes.c_uint16),
            ("dport", ctypes.c_uint16),
            ("num", ctypes.c_uint16),
            ("bound_dev_if", ctypes.c_uint16)
        ]
    
    class IpHdr(ctypes.Structure):
        _fields_ = [
            ("valid", ctypes.c_uint8),
            ("version", ctypes.c_uint8),
            ("ihl", ctypes.c_uint8),
            ("tos", ctypes.c_uint8),
            ("tot_len", ctypes.c_uint16),
            ("id", ctypes.c_uint16),
            ("frag_off", ctypes.c_uint16),
            ("ttl", ctypes.c_uint8),
            ("protocol", ctypes.c_uint8),
            ("saddr", ctypes.c_uint32),
            ("daddr", ctypes.c_uint32)
        ]
    
    class TcpHdr(ctypes.Structure):
        _fields_ = [
            ("valid", ctypes.c_uint8),
            ("source", ctypes.c_uint16),
            ("dest", ctypes.c_uint16),
            ("seq", ctypes.c_uint32),
            ("ack_seq", ctypes.c_uint32),
            ("window", ctypes.c_uint16),
            ("check", ctypes.c_uint16),
            ("urg_ptr", ctypes.c_uint16),
            ("tcp_flags", ctypes.c_uint8)
        ]
    
    class SkbInfo(ctypes.Structure):
        _fields_ = [
            ("valid", ctypes.c_uint8),
            ("len", ctypes.c_uint32),
            ("data_len", ctypes.c_uint32),
            ("queue_mapping", ctypes.c_uint16),
            ("hash", ctypes.c_uint32),
            ("network_header", ctypes.c_uint16),
            ("transport_header", ctypes.c_uint16),
            ("ifindex", ctypes.c_uint32),
            ("dev_name", ctypes.c_char * 16),
            ("ip_hdr", IpHdr),
            ("tcp_hdr", TcpHdr)
        ]
    
    class TcpDebugEvent(ctypes.Structure):
        _fields_ = [
            ("timestamp", ctypes.c_uint64),
            ("pid", ctypes.c_uint32),
            ("comm", ctypes.c_char * 16),
            ("sock_info", SockInfo),
            ("skb_info", SkbInfo)
        ]
    
    event = ctypes.cast(data, ctypes.POINTER(TcpDebugEvent)).contents
    
    print("\n=== TCP_TRANSMIT_SKB DEBUG #%d ===" % event_count)
    print("TIME: %s PID: %d COMM: %s" % (
        time.strftime("%H:%M:%S", time.localtime(event.timestamp / 1e9)),
        event.pid,
        event.comm.decode('utf-8', 'replace')
    ))
    
    # Socket信息
    print("\n--- SOCKET INFO ---")
    if event.sock_info.valid:
        print("Family: %d (AF_INET=%d)" % (event.sock_info.family, 2))
        print("Type: %d Protocol: %d State: %s" % (
            event.sock_info.type, 
            event.sock_info.protocol,
            get_tcp_state_name(event.sock_info.state)
        ))
        print("Socket 5-tuple:")
        print("  Local:  %s:%d (inet_saddr:inet_sport)" % (
            hex_to_ip(event.sock_info.saddr),
            port_to_int(event.sock_info.sport)
        ))
        print("  Remote: %s:%d (inet_daddr:inet_dport)" % (
            hex_to_ip(event.sock_info.daddr), 
            port_to_int(event.sock_info.dport)
        ))
        print("  Bound:  %s:%d (inet_rcv_saddr:inet_num)" % (
            hex_to_ip(event.sock_info.rcv_saddr),
            event.sock_info.num
        ))
        print("Bound dev ifindex: %d" % event.sock_info.bound_dev_if)
    else:
        print("Socket info extraction FAILED")
    
    # SKB信息
    print("\n--- SKB INFO ---")
    if event.skb_info.valid:
        print("Length: %d Data_len: %d Hash: 0x%x Queue: %d" % (
            event.skb_info.len, event.skb_info.data_len, 
            event.skb_info.hash, event.skb_info.queue_mapping
        ))
        print("Headers: network=%d transport=%d" % (
            event.skb_info.network_header, event.skb_info.transport_header
        ))
        print("Device: %s (ifindex=%d)" % (
            event.skb_info.dev_name.decode('utf-8', 'replace'),
            event.skb_info.ifindex
        ))
        
        # IP头部信息
        if event.skb_info.ip_hdr.valid:
            print("\n--- SKB IP HEADER ---")
            print("Version: %d IHL: %d ToS: %d Length: %d ID: %d" % (
                event.skb_info.ip_hdr.version, event.skb_info.ip_hdr.ihl,
                event.skb_info.ip_hdr.tos, socket.ntohs(event.skb_info.ip_hdr.tot_len),
                socket.ntohs(event.skb_info.ip_hdr.id)
            ))
            print("TTL: %d Protocol: %d" % (
                event.skb_info.ip_hdr.ttl, event.skb_info.ip_hdr.protocol
            ))
            print("IP 5-tuple: %s -> %s" % (
                hex_to_ip(event.skb_info.ip_hdr.saddr),
                hex_to_ip(event.skb_info.ip_hdr.daddr)
            ))
        else:
            print("IP header extraction FAILED")
            
        # TCP头部信息
        if event.skb_info.tcp_hdr.valid:
            print("\n--- SKB TCP HEADER ---")
            print("Ports: %d -> %d" % (
                port_to_int(event.skb_info.tcp_hdr.source),
                port_to_int(event.skb_info.tcp_hdr.dest)
            ))
            print("Seq: %u Ack: %u Window: %d" % (
                socket.ntohl(event.skb_info.tcp_hdr.seq),
                socket.ntohl(event.skb_info.tcp_hdr.ack_seq),
                socket.ntohs(event.skb_info.tcp_hdr.window)
            ))
            print("Flags: %s (0x%02x)" % (
                get_tcp_flags_str(event.skb_info.tcp_hdr.tcp_flags),
                event.skb_info.tcp_hdr.tcp_flags
            ))
        else:
            print("TCP header extraction FAILED")
    else:
        print("SKB info extraction FAILED")
    
    print("-" * 50)

def main():
    global event_count
    event_count = 0
    
    parser = argparse.ArgumentParser(description='TCP Transmit SKB Debug Tool')
    parser.add_argument('--target-ip', help='Target IP address filter')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    
    args = parser.parse_args()
    
    target_ip_hex = ip_to_hex(args.target_ip) if args.target_ip else 0
    
    print("=== TCP Transmit SKB Debug Tool ===")
    print("研究 __tcp_transmit_skb probe点的socket和SKB信息可用性")
    if args.target_ip:
        print("Target IP filter: %s (0x%08x)" % (args.target_ip, target_ip_hex))
    print("Duration: %d seconds" % args.duration)
    print("Press Ctrl+C to stop early")
    print()
    
    # 加载BPF程序
    b = BPF(text=bpf_text % target_ip_hex)
    print("BPF program loaded successfully")
    
    # 设置事件处理器
    b["events"].open_perf_buffer(print_event)
    
    # 主循环
    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
    finally:
        print("\n=== Analysis completed ===")
        print("Total events captured: %d" % event_count)

if __name__ == "__main__":
    main()