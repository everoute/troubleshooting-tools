#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse
import socket
import time
import ctypes
import struct
import fcntl

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h>  // ETH_P_IP
#include <uapi/linux/ip.h>        // struct iphdr
#include <uapi/linux/udp.h>       // struct udphdr
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// 定义 key: 区分不同流
struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 ifindex;     // 添加网卡索引字段
};

// 上一次包时间戳
BPF_HASH(last_ts_snd, struct flow_key_t, u64); // 发送侧
BPF_HASH(last_ts_rcv, struct flow_key_t, u64); // 接收侧

// 动态配置： 发送 ifindex 集合 / 接收 ifindex 集合
BPF_HASH(send_ifaces, u32, u8);  // key: ifindex, value: 1
BPF_HASH(recv_ifaces, u32, u8);  // 同上

// 动态配置：关心的 UDP 端口
BPF_HASH(allowed_ports, u16, u8); // key: port, value: 1

// 由 python 脚本在编译时替换
#define GAP_THRESHOLD_US THRESHOLD_PLACEHOLDER

static __always_inline int is_send_iface(u32 ifindex)
{
    // 如果在 send_ifaces 里能查到，就认为是发送侧
    u8 *flag = send_ifaces.lookup(&ifindex);
    return flag ? 1 : 0;
}

static __always_inline int is_recv_iface(u32 ifindex)
{
    u8 *flag = recv_ifaces.lookup(&ifindex);
    return flag ? 1 : 0;
}

static __always_inline int is_allowed_port(u16 port_be)
{
    u16 port = ntohs(port_be);
    //u16 port = (port_be >> 8) | (port_be << 8);  // ntohs
    u8 *flag = allowed_ports.lookup(&port);
    return flag ? 1 : 0;
}

// net_dev_xmit: 发送侧
TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    // 获取 ifindex
    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) return 0;

    u32 idx = 0;
    bpf_probe_read_kernel(&idx, sizeof(idx), &dev_ptr->ifindex);
    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev_ptr->name);

    // 如果不是发送侧网卡，则忽略
    if (!is_send_iface(idx)) {
        //bpf_trace_printk("SEND not interested in ifindex=%u, dev_name=%s\n", idx, ifname);
        return 0;
    }

    // protocol
    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    // 读取 IP
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    // UDP
    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    // 是否在关注端口
    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest))
        return 0;

    // 构造 flow key
    struct flow_key_t fkey = {};
    fkey.saddr = iph.saddr;
    fkey.daddr = iph.daddr;
    fkey.sport = ntohs(udph.source);
    fkey.dport = ntohs(udph.dest);
    fkey.ifindex = idx;    // 添加网卡索引

    // 计算相邻包间隔
    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_snd.lookup(&fkey);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        if (delta_us > GAP_THRESHOLD_US) {
            bpf_trace_printk("SEND gap>GAP_THRESHOLD_US: gap=%llu us, port=%u, dev_name=%s\n", delta_us, fkey.dport, ifname);
        }
    }
    last_ts_snd.update(&fkey, &now);

    return 0;
}

// netif_receive_skb: 接收侧
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) return 0;

    u32 idx = 0;
    bpf_probe_read_kernel(&idx, sizeof(idx), &dev_ptr->ifindex);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev_ptr->name);

    if (!is_recv_iface(idx)) {
        //bpf_trace_printk("RECV not interested in ifindex=%u, dev_name=%s\n", idx, ifname);
        return 0;
    }

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest))
        return 0;

    struct flow_key_t fkey = {};
    fkey.saddr = iph.saddr;
    fkey.daddr = iph.daddr;
    fkey.sport = ntohs(udph.source);
    fkey.dport = ntohs(udph.dest);
    fkey.ifindex = idx;    // 添加网卡索引

    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_rcv.lookup(&fkey);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        if (delta_us > GAP_THRESHOLD_US) {
            bpf_trace_printk("RECV gap>GAP_THRESHOLD_US: gap=%llu us, port=%u, dev_name=%s\n", delta_us, fkey.dport, ifname);
        }
    }
    last_ts_rcv.update(&fkey, &now);

    return 0;
}
"""

def build_bpf(threshold_ms):
    """
    将 GAP_THRESHOLD_US 替换成 (threshold_ms * 1000)，构建最终 BPF 源码并返回 BPF 对象
    """
    threshold_us = threshold_ms * 1000
    program = bpf_text.replace("THRESHOLD_PLACEHOLDER", str(threshold_us))
    return BPF(text=program)

def parse_args():
    parser = argparse.ArgumentParser(description="Track multi dev + multi port gaps in eBPF.")
    parser.add_argument("--send-dev", type=str, default="",
                        help="Specify send-side device names (comma or space separated). e.g. --send-dev 'vnet45,vnet46' or --send-dev 'vnet45 vnet46'")
    parser.add_argument("--recv-dev", type=str, default="",
                        help="Specify recv-side device names (comma or space separated). e.g. --recv-dev 'vnet48,vnet49' or --recv-dev 'vnet48 vnet49'")
    parser.add_argument("--ports", type=int, nargs="+", default=[62108, 61969, 61967, 62109, 61970, 61968],
                        help="A list of UDP ports to track. e.g. --ports 62109 61968 61970")
    parser.add_argument("--threshold", type=int, default=100,
                        help="Inter-packet gap threshold (milliseconds). default=100 ms")
    args = parser.parse_args()
    
    # 处理设备列表
    args.send_dev = [dev.strip() for dev in args.send_dev.replace(',', ' ').split() if dev.strip()]
    args.recv_dev = [dev.strip() for dev in args.recv_dev.replace(',', ' ').split() if dev.strip()]
    return args

def get_if_index(ifname):
    """Get interface index from name, a replacement for socket.if_nametoindex()"""
    SIOCGIFINDEX = 0x8933  # From linux/sockios.h
    if len(ifname) > 15:  # 16-1, leaving room for null terminator
        raise OSError("Interface name too long")
    
    # Create a socket to use with ioctl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    
    # Prepare struct ifreq - 32 bytes buffer for interface name and index
    buff = struct.pack('256s', ifname.encode())
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buff)
        idx = struct.unpack('I', res[16:20])[0]  # Interface index is at offset 16
        return idx
    except IOError:
        raise OSError("Device %s not found" % ifname)
    finally:
        s.close()

def main():
    args = parse_args()
    # 1. 构建 BPF 程序
    b = build_bpf(args.threshold)

    # 2. 获取 Map 引用
    send_ifaces = b.get_table("send_ifaces")
    recv_ifaces = b.get_table("recv_ifaces")
    allowed_ports = b.get_table("allowed_ports")

    # 3. 填充 "发送侧网卡 ifindex"
    for devname in args.send_dev:
        try:
            idx = get_if_index(devname)
        except OSError as e:
            print("WARNING: %s" % str(e))
            continue
        send_ifaces[ctypes.c_uint(idx)] = ctypes.c_ubyte(1)
        print("Added send-dev: %s (ifindex=%d)" % (devname, idx))

    # 4. 填充 "接收侧网卡 ifindex"
    for devname in args.recv_dev:
        try:
            idx = get_if_index(devname)
        except OSError as e:
            print("WARNING: %s" % str(e))
            continue
        recv_ifaces[ctypes.c_uint(idx)] = ctypes.c_ubyte(1)
        print("Added recv-dev: %s (ifindex=%d)" % (devname, idx))

    # 5. 填充关心的 ports
    for p in args.ports:
        allowed_ports[ctypes.c_ushort(p)] = ctypes.c_ubyte(1)
    print("Debug: allowed_ports content:")
    for k, v in allowed_ports.items():
        print("Port: %d (0x%04x)" % (k.value, k.value))

    print("Tracking UDP ports:", args.ports)
    print("Gap threshold = %d ms\n" % args.threshold)

    print("Attaching eBPF... press Ctrl+C to exit.\n")

    # 6. 从 trace_pipe 中读取输出
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            # 若不需要过滤，可直接打印 msg
            if "gap>" in msg:
                print("%-18.9f %s" % (ts, msg.decode()))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

