#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse
import socket
import struct
import fcntl
import ctypes

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h>   // ETH_P_IP
#include <uapi/linux/ip.h>         // struct iphdr
#include <uapi/linux/udp.h>        // struct udphdr
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// flow_key: 包含 src/dst MAC + IPv4 + UDP ports
struct flow_key_t {
    unsigned char smac[6];    // source MAC
    unsigned char dmac[6];    // dest MAC
    u32 saddr;                // IPv4 src
    u32 daddr;                // IPv4 dst
    u16 sport;                // UDP src port
    u16 dport;                // UDP dst port
};

// Map: flow_key -> timestamp(ns)
BPF_HASH(send_ts, struct flow_key_t, u64);

// 发送侧 / 接收侧 ifaces
BPF_HASH(send_ifaces, u32, u8); // key=ifindex, val=1
BPF_HASH(recv_ifaces, u32, u8); // 同上

// Allowed UDP ports
BPF_HASH(allowed_ports, u16, u8); // key=port(host order), val=1

// 判断 ifindex 是否在 send_ifaces
static __always_inline int is_send_iface(u32 idx)
{
    u8 *flag = send_ifaces.lookup(&idx);
    return flag ? 1 : 0;
}

// 判断 ifindex 是否在 recv_ifaces
static __always_inline int is_recv_iface(u32 idx)
{
    u8 *flag = recv_ifaces.lookup(&idx);
    return flag ? 1 : 0;
}

// 判断端口是否在 allowed_ports
static __always_inline int is_allowed_port(u16 port_be)
{
    // ntohs
    u16 p = (port_be >> 8) | (port_be << 8);
    u8 *flag = allowed_ports.lookup(&p);
    return flag ? 1 : 0;
}

//// 读取以太头(14字节)，从 skb 获取 mac header 并写入 fkey->dmac 和 fkey->smac
//static __always_inline int read_ethhdr(struct sk_buff *skb, struct flow_key_t *fkey)
//{
//    // 注意：tracepoint 参数给的 skb 需转换成真实 sk_buff
//    struct sk_buff *real_skb = (struct sk_buff *) skb;
//    if (!real_skb)
//        return -1;
//
//    // 获取 mac_header 偏移
//    u32 mac_off = 0;
//    bpf_probe_read_kernel(&mac_off, sizeof(mac_off), &real_skb->mac_header);
//    bpf_trace_printk("read_ethhdr: mac_off=%u\n", mac_off);
//
//    // 读取 skb->head 指针
//    unsigned char *head = 0;
//    bpf_probe_read_kernel(&head, sizeof(head), &real_skb->head);
//    if (!head)
//        return -1;
//
//    // 读取 14 字节的以太网头
//    unsigned char eth[14] = {0};
//    bpf_probe_read_kernel(&eth, sizeof(eth), head + mac_off);
//
//    // 调试：打印原始 ETH header 信息
//    bpf_trace_printk("read_ethhdr: dmac part1: %x:%x:%x\n", eth[0], eth[1], eth[2]);
//    bpf_trace_printk("read_ethhdr: dmac part2: %x:%x:%x\n", eth[3], eth[4], eth[5]);
//    bpf_trace_printk("read_ethhdr: smac part1: %x:%x:%x\n", eth[6], eth[7], eth[8]);
//    bpf_trace_printk("read_ethhdr: smac part2: %x:%x:%x\n", eth[9], eth[10], eth[11]);
//    // 此处也可以打印 eth[12] 和 eth[13] 检查 eth_type
//
//    // 将 14 字节数据切分拷贝到 fkey：前 6 字节为 dmac，后 6 字节为 smac
//    __builtin_memcpy(fkey->dmac, eth, 6);
//    __builtin_memcpy(fkey->smac, eth + 6, 6);
//
//    return 0;
//}


static __always_inline int read_ethhdr(struct sk_buff *skb, struct flow_key_t *fkey)
{

    /* We will access all data through pointers to structs */
    void *data = (void *)(long)skb->data;

    /* for easy access we re-use the Kernel's struct definitions */
    struct ethhdr  *eth  = data;

    // 定义一个局部的 ethhdr 结构实例
    //struct ethhdr eth = {};
    //if (bpf_probe_read_kernel(&eth, sizeof(eth), skb->data) < 0)
    //    return -1;

    bpf_trace_printk("read_ethhdr: h_dest part1: %x:%x:%x\n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_trace_printk("read_ethhdr: h_dest part2: %x:%x:%x\n",
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    // 调试：打印整个以太网头信息，包括目的 MAC、源 MAC 和协议类型
    //bpf_trace_printk("read_ethhdr: h_dest part1: %x:%x:%x\n",
    //    eth.h_dest[0], eth.h_dest[1], eth.h_dest[2]);
    //bpf_trace_printk("read_ethhdr: h_dest part2: %x:%x:%x\n",
    //    eth.h_dest[3], eth.h_dest[4], eth.h_dest[5]);

    // 打印源 MAC 地址，拆分成两次
    //bpf_trace_printk("read_ethhdr: h_source part1: %x:%x:%x\n",
    //    eth.h_source[0], eth.h_source[1], eth.h_source[2]);
    //bpf_trace_printk("read_ethhdr: h_source part2: %x:%x:%x\n",
    //    eth.h_source[3], eth.h_source[4], eth.h_source[5]);

    // 打印协议类型
    //bpf_trace_printk("read_ethhdr: h_proto=%x\n", ntohs(eth.h_proto));

    // 将目的 MAC 和源 MAC 分别拷贝到 flow key 中
    //__builtin_memcpy(fkey->dmac, eth.h_dest, ETH_ALEN);
    //__builtin_memcpy(fkey->smac, eth.h_source, ETH_ALEN);
    __builtin_memcpy(fkey->dmac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(fkey->smac, eth->h_source, ETH_ALEN);

    return 0;
}


// 定义一个宏，用于将 0~15 的数转换为对应的字符
#define HEX_DIGIT(n) (((n) < 10) ? ('0' + (n)) : ('a' + ((n) - 10)))

// 辅助函数：将 6 字节 MAC 地址转换为形如 "aa:bb:cc:dd:ee:ff" 的字符串。
// buf 必须至少有 18 个字节的存储空间 (17 字符 + '\0')
static __always_inline void mac_to_str(const unsigned char *mac, char *buf, int buf_len)
{
    if (buf_len < 18)
        return;
    buf[0] = HEX_DIGIT(mac[0] >> 4);
    buf[1] = HEX_DIGIT(mac[0] & 0xf);
    buf[2] = ':';
    buf[3] = HEX_DIGIT(mac[1] >> 4);
    buf[4] = HEX_DIGIT(mac[1] & 0xf);
    buf[5] = ':';
    buf[6] = HEX_DIGIT(mac[2] >> 4);
    buf[7] = HEX_DIGIT(mac[2] & 0xf);
    buf[8] = ':';
    buf[9] = HEX_DIGIT(mac[3] >> 4);
    buf[10] = HEX_DIGIT(mac[3] & 0xf);
    buf[11] = ':';
    buf[12] = HEX_DIGIT(mac[4] >> 4);
    buf[13] = HEX_DIGIT(mac[4] & 0xf);
    buf[14] = ':';
    buf[15] = HEX_DIGIT(mac[5] >> 4);
    buf[16] = HEX_DIGIT(mac[5] & 0xf);
    buf[17] = '\0';
}

// ---------------------------------------------------
// 接收侧: netif_receive_skb  (VM -> host)
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
    if (!skb) {
        bpf_trace_printk("DEBUG: skb is NULL in netif_receive_skb\n");
        return 0;
    }

    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) {
        bpf_trace_printk("DEBUG: dev_ptr is NULL in netif_receive_skb\n");
        return 0;
    }

    u32 idx = 0;
    bpf_probe_read_kernel(&idx, sizeof(idx), &dev_ptr->ifindex);
    // Debug: log if the interface is not in send_ifaces
    if (!is_send_iface(idx)) {
        //bpf_trace_printk("DEBUG: Interface idx=%u is not a send iface in netif_receive_skb\n", idx);
        return 0;
    }

    struct flow_key_t fkey = {};
    read_ethhdr(skb, &fkey);

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("DEBUG: Non-IP protocol in netif_receive_skb, proto=%x\n", proto);
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), (void *)(skb->head + skb->network_header));
    if (iph.protocol != IPPROTO_UDP) {
        bpf_trace_printk("DEBUG: Non-UDP protocol in netif_receive_skb, iph.protocol=%x\n", iph.protocol);
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), (void *)(skb->head + skb->transport_header));
    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest)) {
        //bpf_trace_printk("DEBUG: UDP port not allowed in netif_receive_skb\n");
        return 0;
    }

    fkey.saddr = iph.saddr;
    fkey.daddr = iph.daddr;
    fkey.sport = udph.source;
    fkey.dport = udph.dest;

    u64 now = bpf_ktime_get_ns();
    send_ts.update(&fkey, &now);

    //bpf_trace_printk("DEBUG: Completed netif_receive_skb probe, stored timestamp\n");
    // 分别转换 source 和 destination MAC 地址为字符串
    char src_mac_str[18] = {0};
    char dst_mac_str[18] = {0};
    mac_to_str(fkey.smac, src_mac_str, sizeof(src_mac_str));
    mac_to_str(fkey.dmac, dst_mac_str, sizeof(dst_mac_str));
    bpf_trace_printk("DEBUG send: src_mac=%s\n", src_mac_str);
    bpf_trace_printk("DEBUG send: dst_mac=%s\n", dst_mac_str);

    return 0;
}

// ---------------------------------------------------
// 发送侧: net_dev_xmit  (host -> VM)
TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *) args->skbaddr;
    if (!skb) {
        bpf_trace_printk("DEBUG: skb is NULL in net_dev_xmit\n");
        return 0;
    }

    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) {
        bpf_trace_printk("DEBUG: dev_ptr is NULL in net_dev_xmit\n");
        return 0;
    }

    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev_ptr->name);
    u32 idx = 0;
    bpf_probe_read_kernel(&idx, sizeof(idx), &dev_ptr->ifindex);
    if (!is_recv_iface(idx)) {
        //bpf_trace_printk("DEBUG: Interface idx=%u is not a recv iface in net_dev_xmit\n", idx);
        return 0;
    }

    struct flow_key_t fkey = {};
    read_ethhdr(skb, &fkey);

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("DEBUG: Non-IP protocol in net_dev_xmit, proto=%x\n", proto);
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), (void *)(skb->head + skb->network_header));
    if (iph.protocol != IPPROTO_UDP) {
        //bpf_trace_printk("DEBUG: Non-UDP protocol in net_dev_xmit, iph.protocol=%x\n", iph.protocol);
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), (void *)(skb->head + skb->transport_header));
    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest)) {
        //bpf_trace_printk("DEBUG: UDP port not allowed in net_dev_xmit\n");
        return 0;
    }

    fkey.saddr = iph.saddr;
    fkey.daddr = iph.daddr;
    fkey.sport = udph.source;
    fkey.dport = udph.dest;

    u64 *p_t = send_ts.lookup(&fkey);
    if (p_t) {
        u64 now = bpf_ktime_get_ns();
        u64 delta_ns = now - *p_t;
        u64 delta_us = delta_ns / 1000;
        bpf_trace_printk("DEBUG: Latency computed: %llu us, port=%u, dev_name=%s\n",
                           delta_us, ntohs(fkey.dport), ifname);

        // 分别转换 source 和 destination MAC 地址为字符串
        char src_mac_str[18] = {0};
        char dst_mac_str[18] = {0};
        mac_to_str(fkey.smac, src_mac_str, sizeof(src_mac_str));
        mac_to_str(fkey.dmac, dst_mac_str, sizeof(dst_mac_str));
        bpf_trace_printk("DEBUG recv: src_mac=%s\n", src_mac_str);
        bpf_trace_printk("DEBUG recv: dst_mac=%s\n", dst_mac_str);

        send_ts.delete(&fkey);
    } else {
        bpf_trace_printk("DEBUG: No matching timestamp found in send_ts\n");
        // 分别转换 source 和 destination MAC 地址为字符串
        char src_mac_str[18] = {0};
        char dst_mac_str[18] = {0};
        mac_to_str(fkey.smac, src_mac_str, sizeof(src_mac_str));
        mac_to_str(fkey.dmac, dst_mac_str, sizeof(dst_mac_str));
        bpf_trace_printk("DEBUG recv: src_mac=%s\n", src_mac_str);
        bpf_trace_printk("DEBUG recv: dst_mac=%s\n", dst_mac_str);
    }

    return 0;
}
"""

# ---------------- Python2 用户态：动态插入 ifindex、端口等 ----------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Measure E2E latency from 'send-dev'(netif_receive_skb) to 'recv-dev'(net_dev_xmit) with MAC+IP+port flow_key"
    )
    parser.add_argument("--send-dev", type=str, default="",
                        help="Comma/space separated vnet for sending VM side, e.g. 'vnet48,vnet41'")
    parser.add_argument("--recv-dev", type=str, default="",
                        help="Comma/space separated vnet for receiving VM side, e.g. 'vnet45,vnet59'")
    parser.add_argument("--ports", type=int, nargs="+", default=[62109],
                        help="UDP ports to watch, e.g. --ports 62109 61968")
    return parser.parse_args()

def get_if_index(devname):
    """Python2 fallback for socket.if_nametoindex"""
    SIOCGIFINDEX = 0x8933
    if len(devname) > 15:
        raise OSError("Interface name too long")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('256s', devname.encode())
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    finally:
        s.close()

def main():
    args = parse_args()

    # 处理 dev list
    def parse_dev_list(s):
        return [x.strip() for x in s.replace(',', ' ').split() if x.strip()]
    send_dev_list = parse_dev_list(args.send_dev)
    recv_dev_list = parse_dev_list(args.recv_dev)

    print("Send-devs:", send_dev_list)
    print("Recv-devs:", recv_dev_list)
    print("Ports:", args.ports)

    b = BPF(text=bpf_text)

    send_ifaces = b.get_table("send_ifaces")
    recv_ifaces = b.get_table("recv_ifaces")
    allowed_ports = b.get_table("allowed_ports")

    # 插入 send-dev ifindex
    for dev in send_dev_list:
        try:
            idx = get_if_index(dev)
            send_ifaces[ctypes.c_uint(idx)] = ctypes.c_ubyte(1)
            print("Added send-dev: %s (ifindex=%d)" % (dev, idx))
        except OSError as e:
            print("Warn:", str(e))

    # 插入 recv-dev ifindex
    for dev in recv_dev_list:
        try:
            idx = get_if_index(dev)
            recv_ifaces[ctypes.c_uint(idx)] = ctypes.c_ubyte(1)
            print("Added recv-dev: %s (ifindex=%d)" % (dev, idx))
        except OSError as e:
            print("Warn:", str(e))

    # 插入 allowed ports
    for p in args.ports:
        allowed_ports[ctypes.c_ushort(p)] = ctypes.c_ubyte(1)

    print("\nAttaching BPF. Listening for 'MAC_LAT' logs. Ctrl+C to stop.\n")

    # 输出 trace
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            #if "VM_PAIR_LAT" in msg:
            print("%.6f: %s" % (ts, msg))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

