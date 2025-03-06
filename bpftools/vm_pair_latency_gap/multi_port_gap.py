#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from bcc import BPF

# BPF 源码
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h> // ETH_P_IP
#include <uapi/linux/ip.h>       // struct iphdr
#include <uapi/linux/udp.h>      // struct udphdr
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// ------------------ 定义 key: 用于区分不同 UDP 流 -------------------
struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// 发送侧: 上一次包到达时刻(ns)
BPF_HASH(last_ts_snd, struct flow_key_t, u64);
// 接收侧: 上一次包到达时刻(ns)
BPF_HASH(last_ts_rcv, struct flow_key_t, u64);

// 阈值 100ms，单位为微秒
#define GAP_THRESHOLD_US 100000

// 我们关心的端口集合： {62108, 61969, 61967, 62109, 61970, 61968}
// 你可以根据需求增加/删除端口
static __always_inline bool is_target_port(u16 port)
{
    // ntohs
    port = (port << 8) | (port >> 8);

    return (port == 62108) ||
           (port == 61969) ||
           (port == 61967) ||
           (port == 62109) ||
           (port == 61970) ||
           (port == 61968);
}

static __always_inline int my_strncmp(const char *s1, const char *s2, int n)
{
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
        // 如果提前遇到字符串结尾也可以 break
        if (s1[i] == '\0')
            break;
    }
    return 0;
}

static __always_inline bool devname_is(const char *ifname, const char *prefix, int prefix_len) {
    #pragma unroll
    for (int i = 0; i < prefix_len; i++) {
        if (ifname[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

// ------------------ 发送侧 ------------------
// net_dev_xmit: 宿主机往 vnet45 发包 (宿主机视角)
TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    // 获取真实网卡名
    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    if (!devname_is(ifname, "vnet45", 6)) return 0;

    // 只处理 IPv4
    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("GAP_DBG xmit: non-IP protocol %x\\n", proto);
        return 0;
    }

    // 读取 IP 头
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    // 只处理 UDP
    if (iph.protocol != IPPROTO_UDP) {
        bpf_trace_printk("GAP_DBG xmit: non-UDP protocol %x\\n", iph.protocol);
        return 0;
    }

    // 读取 UDP 头
    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    // 判断端口是否在我们关心的集合
    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        bpf_trace_printk("GAP_DBG xmit: non-target port %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));
        return 0;
    }
    bpf_trace_printk("GAP_DBG xmit: target port %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));

    // 构造 flow_key
    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    // 计算与上一包的间隔
    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_snd.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        // 若大于 100 ms，则输出
        if (delta_us > GAP_THRESHOLD_US) {
            bpf_trace_printk("SEND gap>100ms: %llu us, port=%u, dev=%s\n", (u64)delta_us, (u32)ntohs(udph.dest), ifname);
        }
    }
    // 更新 last_ts
    last_ts_snd.update(&key, &now);

    return 0;
}

// ------------------ 接收侧 ------------------
// netif_receive_skb: 宿主机从 vnet48 收包 (宿主机视角, VM 发出的包)
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    if (!devname_is(ifname, "vnet48", 6)) return 0;

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("GAP_DBG xmit: non-IP protocol %x\\n", proto);
        return 0;
    }

    // 读 IP/UDP
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        bpf_trace_printk("GAP_DBG recv: non-UDP protocol %x\\n", iph.protocol);
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        bpf_trace_printk("GAP_DBG recv: non-target port %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));
        return 0;
    }
    bpf_trace_printk("GAP_DBG recv: target port %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_rcv.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        if (delta_us > GAP_THRESHOLD_US) {
            bpf_trace_printk("RECV gap>100ms: %llu us, port=%u, dev=%s\n", (u64)delta_us, (u32)ntohs(udph.dest), ifname);
        }
    }
    last_ts_rcv.update(&key, &now);

    return 0;
}
"""

def main():
    b = BPF(text=bpf_text)
    print("Tracing multiple ports {62108,61969,61967,62109,61970,61968} ...")
    print("On vnet48->vnet45 from host's perspective; threshold=100ms")
    print("Hit Ctrl+C to exit.\n")

    # 从 trace_pipe 中读取输出
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if "gap>100ms:" in msg:
                print("%-18.9f %s" % (ts, msg.decode()))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

