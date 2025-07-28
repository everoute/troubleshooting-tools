#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
VM RX Path Test - 测试正确的RX数据流
验证RX路径: __netif_receive_skb -> netdev_frame_hook -> ovs_dp_process_packet -> ovs_vport_send -> tun_net_xmit
"""

from __future__ import print_function
import argparse
import ctypes
import socket
import time
from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// 五元组流标识
struct flow_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
};

// RX路径追踪数据
struct rx_flow_t {
    u64 ts_netif_receive;        // Stage 0: __netif_receive_skb
    u64 ts_netdev_hook;          // Stage 1: netdev_frame_hook  
    u64 ts_ovs_process;          // Stage 2: ovs_dp_process_packet
    u64 ts_ovs_vport;            // Stage 5: ovs_vport_send
    u64 ts_tun_xmit;             // Stage 6: tun_net_xmit (终点)
    char phy_ifname[16];
    char vm_ifname[16];
    u8 stages_hit;               // 位掩码标记哪些阶段被命中
};

// 完成的RX事件
struct rx_event_t {
    struct flow_key_t key;
    struct rx_flow_t flow;
    u64 total_latency_ns;
};

BPF_HASH(rx_tracker, struct flow_key_t, struct rx_flow_t, 10240);
BPF_PERF_OUTPUT(rx_events);

// 解析数据包获取五元组
static __always_inline int parse_packet_key(struct sk_buff *skb, struct flow_key_t *key) {
    if (!skb) return 0;
    
    unsigned char *head;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) return 0;
    
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) return 0;
    
    // 读取IP头
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) return 0;
    
    if (ip.protocol != IPPROTO_TCP && ip.protocol != IPPROTO_UDP) return 0;
    
    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;
    
    // 计算传输层偏移
    u8 ip_header_len = (ip.ihl & 0x0F) * 4;
    if (ip_header_len < 20) return 0;
    
    // 读取端口信息
    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + network_header_offset + ip_header_len) < 0) return 0;
        key->src_port = tcp.source;
        key->dst_port = tcp.dest;
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + network_header_offset + ip_header_len) < 0) return 0;
        key->src_port = udp.source;
        key->dst_port = udp.dest;
    }
    
    return 1;
}

// 检查是否是vnet接口
static __always_inline int is_vnet_interface(struct sk_buff *skb) {
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev) return 0;
    
    char ifname[16] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);
    
    return (ifname[0] == 'v' && ifname[1] == 'n' && ifname[2] == 'e' && ifname[3] == 't');
}

// Stage 0: __netif_receive_skb - RX起点（物理网卡接收）
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct rx_flow_t flow = {};
    flow.ts_netif_receive = bpf_ktime_get_ns();
    flow.stages_hit |= (1 << 0);
    
    // 记录物理接口名
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) >= 0 && dev) {
        bpf_probe_read_kernel_str(flow.phy_ifname, sizeof(flow.phy_ifname), dev->name);
    }
    
    rx_tracker.update(&key, &flow);
    return 0;
}

// Stage 1: netdev_frame_hook - 网络设备帧处理钩子
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct rx_flow_t *flow = rx_tracker.lookup(&key);
    if (!flow) return 0;
    
    flow->ts_netdev_hook = bpf_ktime_get_ns();
    flow->stages_hit |= (1 << 1);
    return 0;
}

// Stage 2: ovs_dp_process_packet - OVS数据路径处理
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct rx_flow_t *flow = rx_tracker.lookup(&key);
    if (!flow) return 0;
    
    flow->ts_ovs_process = bpf_ktime_get_ns();
    flow->stages_hit |= (1 << 2);
    return 0;
}

// Stage 5: ovs_vport_send - OVS虚拟端口发送
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct rx_flow_t *flow = rx_tracker.lookup(&key);
    if (!flow) return 0;
    
    flow->ts_ovs_vport = bpf_ktime_get_ns();
    flow->stages_hit |= (1 << 5);
    return 0;
}

// Stage 6: tun_net_xmit - RX终点（发送到VM）
int kprobe__tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!is_vnet_interface(skb)) return 0;
    
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct rx_flow_t *flow = rx_tracker.lookup(&key);
    if (!flow) return 0;
    
    flow->ts_tun_xmit = bpf_ktime_get_ns();
    flow->stages_hit |= (1 << 6);
    
    // 记录VM接口名
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) >= 0 && dev) {
        bpf_probe_read_kernel_str(flow->vm_ifname, sizeof(flow->vm_ifname), dev->name);
    }
    
    // 发送完成事件
    struct rx_event_t event = {};
    event.key = key;
    event.flow = *flow;
    event.total_latency_ns = flow->ts_tun_xmit - flow->ts_netif_receive;
    
    rx_events.perf_submit(ctx, &event, sizeof(event));
    rx_tracker.delete(&key);
    
    return 0;
}
"""

# Python数据结构
class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
    ]

class RxFlow(ctypes.Structure):
    _fields_ = [
        ("ts_netif_receive", ctypes.c_uint64),
        ("ts_netdev_hook", ctypes.c_uint64),
        ("ts_ovs_process", ctypes.c_uint64),
        ("ts_ovs_vport", ctypes.c_uint64),
        ("ts_tun_xmit", ctypes.c_uint64),
        ("phy_ifname", ctypes.c_char * 16),
        ("vm_ifname", ctypes.c_char * 16),
        ("stages_hit", ctypes.c_uint8),
    ]

class RxEvent(ctypes.Structure):
    _fields_ = [
        ("key", FlowKey),
        ("flow", RxFlow),
        ("total_latency_ns", ctypes.c_uint64),
    ]

# RX路径阶段名称
RX_STAGE_NAMES = {
    0: "__netif_receive_skb",
    1: "netdev_frame_hook",
    2: "ovs_dp_process_packet",
    5: "ovs_vport_send",
    6: "tun_net_xmit"
}

def inet_ntoa(addr):
    return socket.inet_ntoa(ctypes.c_uint32(addr))

def print_rx_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(RxEvent)).contents
    
    protocol = "TCP" if event.key.protocol == 6 else "UDP"
    
    print("\n=== VM RX Path Trace: {} ===".format(time.strftime("%H:%M:%S")))
    print("Flow: {}:{} -> {}:{} ({})".format(
        inet_ntoa(event.key.src_ip),
        socket.ntohs(event.key.src_port),
        inet_ntoa(event.key.dst_ip),
        socket.ntohs(event.key.dst_port),
        protocol))
    
    print("Physical: {} → VM: {}".format(
        event.flow.phy_ifname.decode('utf-8', 'replace'),
        event.flow.vm_ifname.decode('utf-8', 'replace')))
    
    print("\nRX Path Latencies (us):")
    
    # 存储时间戳的映射
    timestamps = {}
    if event.flow.stages_hit & (1 << 0):
        timestamps[0] = event.flow.ts_netif_receive
    if event.flow.stages_hit & (1 << 1):
        timestamps[1] = event.flow.ts_netdev_hook
    if event.flow.stages_hit & (1 << 2):
        timestamps[2] = event.flow.ts_ovs_process
    if event.flow.stages_hit & (1 << 5):
        timestamps[5] = event.flow.ts_ovs_vport
    if event.flow.stages_hit & (1 << 6):
        timestamps[6] = event.flow.ts_tun_xmit
    
    # 按阶段顺序打印延迟
    stages = sorted(timestamps.keys())
    for i in range(len(stages) - 1):
        curr_stage = stages[i]
        next_stage = stages[i + 1]
        
        latency_ns = timestamps[next_stage] - timestamps[curr_stage]
        latency_us = latency_ns / 1000.0
        
        print("  [{}->{}] {} -> {}: {:.3f} us".format(
            curr_stage, next_stage,
            RX_STAGE_NAMES.get(curr_stage, "unknown"),
            RX_STAGE_NAMES.get(next_stage, "unknown"),
            latency_us))
        
        # 特殊说明
        if curr_stage == 2 and next_stage == 5:
            print("         (OVS Fast Path - No Upcall)")
    
    print("\nTotal RX Latency: {:.3f} us".format(event.total_latency_ns / 1000.0))
    
    # 显示命中的阶段
    hit_stages = [str(i) for i in range(7) if event.flow.stages_hit & (1 << i)]
    print("Stages Hit: {}".format(", ".join(hit_stages)))

def main():
    parser = argparse.ArgumentParser(
        description="VM RX Path Test - Validate correct RX data flow")
    
    args = parser.parse_args()
    
    print("Loading BPF program...")
    try:
        global b
        b = BPF(text=bpf_text)
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: {}".format(e))
        return 1
    
    print("\nTesting RX Path:")
    print("  Stage 0: __netif_receive_skb (Physical NIC receives)")
    print("  Stage 1: netdev_frame_hook (Network device frame hook)")
    print("  Stage 2: ovs_dp_process_packet (OVS datapath processing)")
    print("  Stage 5: ovs_vport_send (OVS virtual port send)")
    print("  Stage 6: tun_net_xmit (Send to VM - ENDPOINT)")
    
    b["rx_events"].open_perf_buffer(print_rx_event)
    print("\nTracing RX path... Hit Ctrl-C to end")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")

if __name__ == "__main__":
    main()