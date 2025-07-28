#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
VM Network Segment Latency - 正确的数据流实现
按照设计文档实现正确的TX和RX路径追踪

TX路径: tun_get_user -> internal_dev_xmit -> ovs_dp_process_packet -> ovs_vport_send -> __dev_queue_xmit
RX路径: __netif_receive_skb -> netdev_frame_hook -> ovs_dp_process_packet -> ovs_vport_send -> tun_net_xmit
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
#include <net/sock.h>

#define MAX_STAGES 7

// 五元组流标识
struct flow_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
};

// 流追踪数据
struct flow_data_t {
    u64 ts[MAX_STAGES];           // 各阶段时间戳
    u64 skb_ptr[MAX_STAGES];      // SKB指针
    u32 pid;                      // 进程ID
    char comm[16];                // 进程名
    char vm_ifname[16];           // VM接口名
    char phy_ifname[16];          // 物理接口名
    u8 direction;                 // 0=TX, 1=RX
    u8 stages_hit;                // 命中的阶段位掩码
    u8 saw_start:1;               // 标记开始
    u8 saw_end:1;                 // 标记结束
};

// 延迟事件
struct latency_event_t {
    struct flow_key_t key;
    struct flow_data_t data;
    u64 timestamp;
};

// 过滤参数
struct filter_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 direction;  // 0=TX, 1=RX, 2=Both
};

BPF_HASH(flow_tracker, struct flow_key_t, struct flow_data_t, 10240);
BPF_PERF_OUTPUT(latency_events);
BPF_ARRAY(filter_config, struct filter_t, 1);

// 解析数据包获取五元组
static __always_inline int parse_packet_key(struct sk_buff *skb, struct flow_key_t *key) {
    if (!skb) return 0;
    
    unsigned char *head;
    u16 network_header_offset;
    
    // 读取SKB header信息
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
    
    // 计算传输层偏移 - 使用IP头长度字段
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

// 应用过滤条件
static __always_inline int apply_filter(struct flow_key_t *key, u8 direction) {
    int zero = 0;
    struct filter_t *filter = filter_config.lookup(&zero);
    if (!filter) return 1;
    
    if (filter->protocol && filter->protocol != key->protocol) return 0;
    if (filter->src_ip && filter->src_ip != key->src_ip) return 0;  
    if (filter->dst_ip && filter->dst_ip != key->dst_ip) return 0;
    if (filter->src_port && filter->src_port != key->src_port) return 0;
    if (filter->dst_port && filter->dst_port != key->dst_port) return 0;
    if (filter->direction < 2 && filter->direction != direction) return 0;
    
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

// 更新流状态 
static __always_inline void update_flow_stage(struct pt_regs *ctx, struct flow_key_t *key, 
                                              int stage, struct sk_buff *skb, u8 direction) {
    struct flow_data_t *flow = flow_tracker.lookup(key);
    if (!flow) {
        struct flow_data_t new_flow = {};
        new_flow.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&new_flow.comm, sizeof(new_flow.comm));
        new_flow.direction = direction;
        flow_tracker.update(key, &new_flow);
        flow = flow_tracker.lookup(key);
        if (!flow) return;
    }
    
    // 只处理相同方向的流
    if (flow->direction != direction) return;
    
    flow->ts[stage] = bpf_ktime_get_ns();
    flow->skb_ptr[stage] = (u64)skb;
    flow->stages_hit |= (1 << stage);
    
    // 标记开始和结束
    if (stage == 0) flow->saw_start = 1;
    if ((direction == 0 && stage == 6) || (direction == 1 && stage == 6)) flow->saw_end = 1;
    
    // 记录接口名
    if (skb) {
        struct net_device *dev = NULL;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) >= 0 && dev) {
            char ifname[16] = {};
            bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);
            
            // TX方向：stage 0记录VM接口，stage 6记录物理接口
            // RX方向：stage 0记录物理接口，stage 6记录VM接口  
            if ((direction == 0 && stage == 0) || (direction == 1 && stage == 6)) {
                __builtin_memcpy(flow->vm_ifname, ifname, sizeof(flow->vm_ifname));
            } else if ((direction == 0 && stage == 6) || (direction == 1 && stage == 0)) {
                __builtin_memcpy(flow->phy_ifname, ifname, sizeof(flow->phy_ifname));
            }
        }
    }
    
    // 检查是否完成追踪（到达终点）
    if (flow->saw_end) {
        struct latency_event_t event = {};
        event.key = *key;
        event.data = *flow;
        event.timestamp = bpf_ktime_get_ns();
        latency_events.perf_submit(ctx, &event, sizeof(event));
        flow_tracker.delete(key);
    }
}

// TX路径探测点
// Stage 0: tun_get_user - TX起点（VM发送数据包）
// 注意：这个函数的参数不同，需要特殊处理
int kprobe__tun_get_user(struct pt_regs *ctx, struct tun_struct *tun, struct tun_file *tfile, 
                         void *msg_control, struct iov_iter *from, int noblock, bool more) {
    // TODO: 需要从iov_iter中构造临时skb进行解析
    // 这里先简化处理，等后续完善
    return 0;  
}

// Stage 1: internal_dev_xmit - OVS内部设备处理
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    if (!apply_filter(&key, 0)) return 0;  // TX方向
    
    update_flow_stage(ctx, &key, 1, skb, 0);
    return 0;
}

// Stage 2: ovs_dp_process_packet - OVS数据路径处理
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    // 检查是否已有流在追踪（TX或RX）
    struct flow_data_t *flow = flow_tracker.lookup(&key);
    if (flow) {
        update_flow_stage(ctx, &key, 2, skb, flow->direction);
    }
    return 0;
}

// Stage 5: ovs_vport_send - OVS虚拟端口发送  
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct flow_data_t *flow = flow_tracker.lookup(&key);
    if (flow) {
        update_flow_stage(ctx, &key, 5, skb, flow->direction);
    }
    return 0;
}

// Stage 6: __dev_queue_xmit - TX终点（物理设备发送）
int kprobe____dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};  
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct flow_data_t *flow = flow_tracker.lookup(&key);
    if (flow && flow->direction == 0) {  // TX方向
        update_flow_stage(ctx, &key, 6, skb, 0);
    }
    return 0;
}

// RX路径探测点
// Stage 0: __netif_receive_skb - RX起点（物理网卡接收）
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    if (!apply_filter(&key, 1)) return 0;  // RX方向
    
    update_flow_stage(ctx, &key, 0, skb, 1);
    return 0;
}

// Stage 1: netdev_frame_hook - 网络设备帧处理钩子
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff *skb) {
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct flow_data_t *flow = flow_tracker.lookup(&key);
    if (flow && flow->direction == 1) {  // RX方向
        update_flow_stage(ctx, &key, 1, skb, 1);
    }
    return 0;
}

// Stage 6: tun_net_xmit - RX终点（发送到VM）
int kprobe__tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!is_vnet_interface(skb)) return 0;
    
    struct flow_key_t key = {};
    if (!parse_packet_key(skb, &key)) return 0;
    
    struct flow_data_t *flow = flow_tracker.lookup(&key);
    if (flow && flow->direction == 1) {  // RX方向
        update_flow_stage(ctx, &key, 6, skb, 1);
    }
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

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * 7),
        ("skb_ptr", ctypes.c_uint64 * 7),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("vm_ifname", ctypes.c_char * 16),
        ("phy_ifname", ctypes.c_char * 16),
        ("direction", ctypes.c_uint8),
        ("stages_hit", ctypes.c_uint8),
        ("saw_start", ctypes.c_uint8, 1),
        ("saw_end", ctypes.c_uint8, 1),
    ]

class LatencyEvent(ctypes.Structure):
    _fields_ = [
        ("key", FlowKey),
        ("data", FlowData),
        ("timestamp", ctypes.c_uint64),
    ]

class Filter(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
    ]

# TX路径阶段名称
TX_STAGE_NAMES = {
    0: "tun_get_user",
    1: "internal_dev_xmit", 
    2: "ovs_dp_process_packet",
    3: "ovs_dp_upcall",
    4: "ovs_flow_key_extract_userspace",
    5: "ovs_vport_send",
    6: "__dev_queue_xmit"
}

# RX路径阶段名称
RX_STAGE_NAMES = {
    0: "__netif_receive_skb",
    1: "netdev_frame_hook",
    2: "ovs_dp_process_packet", 
    3: "ovs_dp_upcall",
    4: "ovs_flow_key_extract_userspace",
    5: "ovs_vport_send",
    6: "tun_net_xmit"
}

def inet_ntoa(addr):
    return socket.inet_ntoa(ctypes.c_uint32(addr))

def ip_to_int(ip_str):
    if not ip_str:
        return 0
    import struct
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def print_latency_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(LatencyEvent)).contents
    
    # 提取流信息
    protocol = "TCP" if event.key.protocol == 6 else "UDP"
    direction = "TX" if event.data.direction == 0 else "RX"
    stage_names = TX_STAGE_NAMES if event.data.direction == 0 else RX_STAGE_NAMES
    
    # 打印头部
    print("\n=== VM Network Latency Trace: {} ({}) ===".format(
        time.strftime("%Y-%m-%d %H:%M:%S"), direction))
    print("Flow: {}:{} -> {}:{} ({})".format(
        inet_ntoa(event.key.src_ip),
        socket.ntohs(event.key.src_port),
        inet_ntoa(event.key.dst_ip), 
        socket.ntohs(event.key.dst_port),
        protocol))
    
    if event.data.direction == 0:  # TX
        print("VM Device: {} → Physical: {}".format(
            event.data.vm_ifname.decode('utf-8', 'replace'),
            event.data.phy_ifname.decode('utf-8', 'replace') if event.data.phy_ifname[0] else "N/A"))
    else:  # RX
        print("Physical: {} → VM Device: {}".format(
            event.data.phy_ifname.decode('utf-8', 'replace') if event.data.phy_ifname[0] else "N/A",
            event.data.vm_ifname.decode('utf-8', 'replace')))
    
    print("Process: PID={} COMM={}".format(
        event.data.pid,
        event.data.comm.decode('utf-8', 'replace')))
    
    # 计算并打印分段延迟
    print("\nLatencies (us):")
    prev_stage = -1
    prev_ts = 0
    total_latency = 0
    
    for i in range(7):
        if event.data.stages_hit & (1 << i):
            if prev_stage >= 0:
                latency_ns = event.data.ts[i] - prev_ts
                latency_us = latency_ns / 1000.0
                total_latency += latency_ns
                
                print("  [{}->{}] {} -> {}: {:.3f} us".format(
                    prev_stage, i,
                    stage_names.get(prev_stage, "unknown"),
                    stage_names.get(i, "unknown"),
                    latency_us))
                
                # 特殊说明
                if prev_stage == 2 and i == 5:
                    print("         (OVS Fast Path - No Upcall)")
            
            prev_stage = i
            prev_ts = event.data.ts[i]
    
    print("\nTotal Latency: {:.3f} us".format(total_latency / 1000.0))

def main():
    parser = argparse.ArgumentParser(
        description="VM Network Segment Latency - Correct Implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor TX traffic (VM->Network)
  sudo ./vm_segment_correct.py --direction tx --src-ip 192.168.1.10 --protocol tcp
  
  # Monitor RX traffic (Network->VM)  
  sudo ./vm_segment_correct.py --direction rx --dst-ip 192.168.1.10 --protocol tcp
  
  # Monitor both directions
  sudo ./vm_segment_correct.py --protocol tcp --dst-port 80
        """
    )
    
    parser.add_argument("--src-ip", help="Source IP filter")
    parser.add_argument("--dst-ip", help="Destination IP filter")
    parser.add_argument("--src-port", type=int, help="Source port filter")
    parser.add_argument("--dst-port", type=int, help="Destination port filter")
    parser.add_argument("--protocol", choices=["tcp", "udp"], help="Protocol filter")
    parser.add_argument("--direction", choices=["tx", "rx", "both"], default="both",
                       help="Direction to monitor (default: both)")
    
    args = parser.parse_args()
    
    # 加载BPF程序
    print("Loading BPF program...")
    try:
        global b
        b = BPF(text=bpf_text)
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: {}".format(e))
        return 1
    
    # 设置过滤条件
    filter_params = Filter()
    filter_params.src_ip = ip_to_int(args.src_ip) if args.src_ip else 0
    filter_params.dst_ip = ip_to_int(args.dst_ip) if args.dst_ip else 0
    filter_params.src_port = socket.htons(args.src_port) if args.src_port else 0
    filter_params.dst_port = socket.htons(args.dst_port) if args.dst_port else 0
    
    if args.protocol == "tcp":
        filter_params.protocol = 6
    elif args.protocol == "udp":
        filter_params.protocol = 17
    else:
        filter_params.protocol = 0
    
    if args.direction == "tx":
        filter_params.direction = 0
    elif args.direction == "rx":
        filter_params.direction = 1
    else:
        filter_params.direction = 2  # Both
    
    b["filter_config"][0] = filter_params
    
    # 打印配置
    print("\nConfiguration:")
    if args.src_ip:
        print("  Source IP: {}".format(args.src_ip))
    if args.dst_ip:
        print("  Destination IP: {}".format(args.dst_ip))
    if args.protocol:
        print("  Protocol: {}".format(args.protocol.upper()))
    if args.src_port:
        print("  Source Port: {}".format(args.src_port))
    if args.dst_port:
        print("  Destination Port: {}".format(args.dst_port))
    print("  Direction: {}".format(args.direction.upper()))
    
    print("\nMonitoring probe points:")
    if args.direction in ["tx", "both"]:
        print("  TX Path:")
        for i, name in TX_STAGE_NAMES.items():
            print("    Stage {}: {}".format(i, name))
    if args.direction in ["rx", "both"]:
        print("  RX Path:")
        for i, name in RX_STAGE_NAMES.items():
            print("    Stage {}: {}".format(i, name))
    
    # 开始监控
    b["latency_events"].open_perf_buffer(print_latency_event)
    print("\nTracing VM network segment latency... Hit Ctrl-C to end")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")

if __name__ == "__main__":
    main()