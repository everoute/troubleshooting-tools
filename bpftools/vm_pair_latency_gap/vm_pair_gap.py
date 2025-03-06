#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
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

// 发送侧: 上一次包到达时刻
BPF_HASH(last_ts_snd, struct flow_key_t, u64);
// 接收侧: 上一次包到达时刻
BPF_HASH(last_ts_rcv, struct flow_key_t, u64);

// 如果只需要比对某固定端口，可自己写一个 inline 函数
static __always_inline int is_target_port(u16 port)
{
    return ntohs(port) == 62109;
}

// 如果需要更通用的字符串比较函数，可以自己写一个 my_strncmp
// 这里为了演示简单，直接用 8 字节对齐或逐字比较也行。先示例一个最小版本:

static __always_inline bool devname_is_vnet45(const char *ifname)
{
    // 假设 vnet45 长度 5
    // 也可写成循环比较 ifname[i] != ...
    if (ifname[0] == 'v' && ifname[1] == 'n' &&
        ifname[2] == 'e' && ifname[3] == 't' &&
        ifname[4] == '4' && ifname[5] == '5' &&
        ifname[6] == 0 )
    {
        return true;
    }
    return false;
}

static __always_inline bool devname_is_vnet48(const char *ifname)
{
    if (ifname[0] == 'v' && ifname[1] == 'n' &&
        ifname[2] == 'e' && ifname[3] == 't' &&
        ifname[4] == '4' && ifname[5] == '8' &&
        ifname[6] == 0 )
    {
        return true;
    }
    return false;
}


// 发送侧: net_dev_xmit  (示例: "vnet45" 表示宿主机往 VM 发送)
TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    // 获取真实网卡名(在 skb->dev->name 里)
    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    // 如果不是 vnet45，就退出
    if (!devname_is_vnet45(ifname)) {
        return 0;
    }

    // 只处理 IPv4
    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    // 读取 IP 头
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    // 只处理 UDP
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    // 读取 UDP 头
    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        return 0;  // 非我们关心的端口
    }

    // 构造 flow_key
    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    // 计算与上一个包的间隔
    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_snd.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        // 输出 debug 信息: inter-packet gap in microseconds
        bpf_trace_printk("SND GAP: %llu us, flow = %x -> %x\\n", delta_us, iph.saddr, iph.daddr);
    }
    // 更新 last_ts_snd
    last_ts_snd.update(&key, &now);

    return 0;
}


// 接收侧: netif_receive_skb  (示例: "vnet48" 表示宿主机从 VM 收到)
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    if (!devname_is_vnet48(ifname)) {
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

    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        return 0;
    }

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    // 计算 inter-packet gap
    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_rcv.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        // 输出 debug
        bpf_trace_printk("RCV GAP: %llu us, flow = %x -> %x\\n", delta_us, iph.saddr, iph.daddr);
    }
    last_ts_rcv.update(&key, &now);

    return 0;
}
"""

def main():
    b = BPF(text=bpf_text)
    print("Tracing UDP port 62109 from vnet48->vnet45 (in host perspective)...")
    print("Hit Ctrl+C to exit.\n")

    # 读取 trace_pipe 中的 debug 信息
    # 也可用 b.trace_print() 之类方法，但这里示例更直观
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            # 过滤一下，看是否是我们感兴趣的
            if "SND GAP:" in msg or "RCV GAP:" in msg:
                print("%-18.9f %s" % (ts, msg.decode()))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

