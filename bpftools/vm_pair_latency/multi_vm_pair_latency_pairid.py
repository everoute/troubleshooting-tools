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
#include <uapi/linux/if_ether.h>  // ETH_P_IP
#include <uapi/linux/ip.h>        // struct iphdr
#include <uapi/linux/udp.h>       // struct udphdr
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>

// ---------- flow_key_t 定义 ----------
// 在这里，我们通过 pair_id + (saddr,daddr,sport,dport) 区分每条流
struct flow_key_t {
    u32 pair_id;  // 每对 vnet 网卡对应一个 pair_id
    u32 saddr;    
    u32 daddr;
    u16 sport;
    u16 dport;
};

// ---------- 全局 map ----------
// 1) send_pair_map : ifindex -> pair_id，用来把每个 send vnet 网卡映射到唯一 ID
BPF_HASH(send_pair_map, u32, u32);
// 2) recv_pair_map : ifindex -> pair_id，用来把每个 recv vnet 网卡映射到唯一 ID
BPF_HASH(recv_pair_map, u32, u32);

// 2) allowed_ports : 端口列表
BPF_HASH(allowed_ports, u16, u8);

// 3) send_ts : flow_key -> 发送时刻 (ns)
BPF_HASH(send_ts, struct flow_key_t, u64);

// ---------- 辅助函数 ----------

// 检查端口是否在 allowed_ports
static __always_inline int is_allowed_port(u16 port_be)
{
    // ntohs
    u16 port = (port_be >> 8) | (port_be << 8);
    u8 *flag = allowed_ports.lookup(&port);
    return flag ? 1 : 0;
}

/* netif_receive_skb : 宿主机接收从“发送 VM”发出的包 */
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff*)args->skbaddr;
    if (!skb) return 0;

    // 获取网卡 ifindex
    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) return 0;

    u32 ifidx = 0;
    bpf_probe_read_kernel(&ifidx, sizeof(ifidx), &dev_ptr->ifindex);

    // 查 recv_pair_map : ifindex -> pair_id
    u32 *p_pair_id = recv_pair_map.lookup(&ifidx);
    if (!p_pair_id) {
        // 说明此网卡不在我们关注的 vnet pair 里
        return 0;
    }

    // 仅处理 IPv4 
    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    // 读取 IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), (void *)(skb->head + skb->network_header));
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    // 读取 UDP header
    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), (void *)(skb->head + skb->transport_header));
    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest)) {
        return 0;
    }

    // 构造 flow_key
    struct flow_key_t fkey = {};
    fkey.pair_id = *p_pair_id;
    fkey.saddr   = iph.saddr;
    fkey.daddr   = iph.daddr;
    fkey.sport   = udph.source;
    fkey.dport   = udph.dest;

    // 存入 send_ts
    u64 now = bpf_ktime_get_ns();
    send_ts.update(&fkey, &now);

    return 0;
}

/* net_dev_xmit : 宿主机把包发往“接收 VM” */
TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff*)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev_ptr = 0;
    bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), &skb->dev);
    if (!dev_ptr) return 0;

    u32 ifidx = 0;
    bpf_probe_read_kernel(&ifidx, sizeof(ifidx), &dev_ptr->ifindex);

    // 同样查 pair_id
    u32 *p_pair_id = send_pair_map.lookup(&ifidx);
    if (!p_pair_id) {
        // 说明不是我们关注的 “接收 VM”网卡
        return 0;
    }

    // 同样仅处理 IPv4
    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), (void *)(skb->head + skb->network_header));
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), (void *)(skb->head + skb->transport_header));
    if (!is_allowed_port(udph.source) && !is_allowed_port(udph.dest)) {
        return 0;
    }

    struct flow_key_t fkey = {};
    fkey.pair_id = *p_pair_id;
    fkey.saddr   = iph.saddr;
    fkey.daddr   = iph.daddr;
    fkey.sport   = udph.source;
    fkey.dport   = udph.dest;

    // 查 send_ts
    u64 *p_t = send_ts.lookup(&fkey);
    if (p_t) {
        u64 now = bpf_ktime_get_ns();
        u64 delta_ns = now - *p_t;
        u64 delta_us = delta_ns / 1000;

        // bpf_trace_printk 限制 3 个占位符 => 拆成多行
        bpf_trace_printk("PAIR_LAT pair_id=%u lat=%llu us\n", fkey.pair_id, delta_us);
        // 你若想再打 IP/port，可拆分成多次输出

        // 删除
        send_ts.delete(&fkey);
    }
    return 0;
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Use pair_id to differentiate multiple vnet pairs for E2E UDP latency"
    )
    parser.add_argument("--pairs", type=str, default="",
        help=("Define vnet pairs and IDs, e.g. 'vnet48,vnet45=100;vnet36,vnet42=101' "
              "meaning (vnet48->100, vnet45->100), (vnet36->101, vnet42->101)."))
    parser.add_argument("--ports", type=int, nargs="+", default=[62109],
                        help="UDP ports to track. e.g. --ports 62109 61968 61969")
    return parser.parse_args()

def get_if_index(devname):
    """Python2 fallback for socket.if_nametoindex"""
    SIOCGIFINDEX = 0x8933
    if len(devname) > 15:
        raise OSError("Interface name too long: " + devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('256s', devname.encode())
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    finally:
        s.close()

def parse_pair_string(pair_str):
    """
    将形如 "vnet48,vnet45=100;vnet36,vnet42=101" 的字符串解析成:
    [
      ([vnet48, vnet45], 100),
      ([vnet36, vnet42], 101)
    ]
    """
    result = []
    if not pair_str.strip():
        return result
    # 按分号切分
    segments = pair_str.split(';')
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        # seg 类似 "vnet48,vnet45=100"
        if '=' not in seg:
            print("WARNING: invalid pair format: %s" % seg)
            continue
        left, right = seg.split('=', 1)
        pair_id = int(right.strip())
        dev_list_str = left.strip()
        devs = [d.strip() for d in dev_list_str.split(',') if d.strip()]
        if not devs:
            print("WARNING: no device found in seg: %s" % seg)
            continue
        result.append((devs, pair_id))
    return result

def main():
    args = parse_args()
    print("Parsed pairs string:", args.pairs)
    print("Ports:", args.ports)

    # 解析 pair 字符串
    pairs = parse_pair_string(args.pairs)
    # example result: [ (["vnet48", "vnet45"], 100), (["vnet36","vnet42"],101) ]

    # 编译 BPF
    b = BPF(text=bpf_text)

    send_pair_map = b.get_table("send_pair_map")
    recv_pair_map = b.get_table("recv_pair_map")
    allowed_ports = b.get_table("allowed_ports")

    # 往 send_pair_map 和 recv_pair_map 里插入 ifindex -> pair_id
    for devs, pid in pairs:
        try:
            # devs[0] 是接收 VM 网卡: vm -> host，devs[1] 是发送 VM 网卡: host -> vm
            idx_recv = get_if_index(devs[1])
            idx_send = get_if_index(devs[0])
            recv_pair_map[ctypes.c_uint(idx_recv)] = ctypes.c_uint(pid)
            send_pair_map[ctypes.c_uint(idx_send)] = ctypes.c_uint(pid)
            print("Mapping recv dev=%s (ifindex=%d) -> pair_id=%d" % (devs[1], idx_recv, pid))
            print("Mapping send dev=%s (ifindex=%d) -> pair_id=%d" % (devs[0], idx_send, pid))
        except Exception as e:
            print("WARNING: %s" % e)

    # 往 allowed_ports 里插入端口
    for p in args.ports:
        allowed_ports[ctypes.c_ushort(p)] = ctypes.c_ubyte(1)

    print("\nAttaching eBPF. We'll print out 'PAIR_LAT pair_id=xx lat=xxx us' lines.\nCtrl+C to exit.\n")

    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if "PAIR_LAT" in msg:
                print("%.6f: %s" % (ts, msg.decode()))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

