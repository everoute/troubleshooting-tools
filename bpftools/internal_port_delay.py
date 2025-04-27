#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# for el7 
# curl -fLO http://192.168.24.6/tmp/bpftools/x86_64/bcc-0.21.0-1.el7.x86_64.rpm
# curl -fLO http://192.168.24.6/tmp/bpftools/noarch/python-bcc-0.21.0-1.el7.noarch.rpm 
# rpm -ivh bcc-0.21.0-1.el7.x86_64.rpm python-bcc-0.21.0-1.el7.noarch.rpm --force 
# Usage: sudo ./internal_port_delay.py [--src-ip x.x.x.x] [--dst-ip y.y.y.y] [--latency-ms L]
# --src-ip ： 源IP地址
# --dst-ip ： 目的IP地址
# --latency-ms ： 延迟阈值，单位为毫秒, 追踪物理网卡收包到协议栈处理完成整个过程延迟大于指定值的包 
#  显示分段延迟，共计算 6段，为 smtxos 数据路径量身定做，包含 ovs 处理关键路径延迟统计，

# sameple output :---                                                                                                                                                                          
# PKT: 10.255.0.104 -> 10.255.0.143 Proto=ICMP ICMP Type=8 ID=3657 Seq=1798                                                                                                    
#   Initial Context: PID=0      COMM=swapper/45   IF=ens2f1                                                                                                                    
#   Latencies (us): [0->1]:   N/A  [1->2]:   N/A  [2->3]:   N/A  [3->4]:   N/A  [4->5]:1620.309 | Total[0->5]:1720.494                                          
#   Kernel Stack Traces:                                                                                                                                                       
#     Stage 0 (NETIF_RECV): Stack ID 15153                                                                                                                                     
#       __netif_receive_skb+0x1                                                                                                                                                
#       netif_receive_skb_internal+0x3d                                                                                                                                        
#       napi_gro_receive+0xba                                                                                                                                                  
#       mlx5e_handle_rx_cqe+0xa3                                                                                                                                               
#       mlx5e_poll_rx_cq+0xb61                                                                                                                                                 
#       mlx5e_napi_poll+0xee                                                                                                                                                   
#       net_rx_action+0x149                                                                                                                                                    
#       __softirqentry_text_start+0xe3                                                                                                                                         
#       irq_exit+0x111                                                                                                                                                         
#       do_IRQ+0x7f                                                                                                                                                            
#       ret_from_intr+0x0                                                                                                                                                      
#     Stage 1 (NETDEV_FRAME): <Skipped>                                                                                                                                        
#     Stage 2 (DP_PROCESS): Stack ID 6447                                                                                                                                      
#       ovs_dp_process_packet+0x1                                                                                                                                              
#       ovs_vport_receive+0x6c                                                                                                                                                 
#       netdev_frame_hook+0xd5                                                                                                                                                 
#       __netif_receive_skb_core+0x6a3
#       __netif_receive_skb_one_core+0x3c
#       netif_receive_skb_internal+0x3d
#       napi_gro_receive+0xba         
#       mlx5e_handle_rx_cqe+0xa3
#       mlx5e_poll_rx_cq+0xb61      
#       mlx5e_napi_poll+0xee        
#       net_rx_action+0x149              
#       __softirqentry_text_start+0xe3   
#       irq_exit+0x111                   
#       do_IRQ+0x7f             
#       ret_from_intr+0x0         
#     Stage 3 (DP_UPCALL): <Skipped>
#     Stage 4 (VPORT_SEND): Stack ID 1072
#       ovs_vport_send+0x1               
#       do_execute_actions+0x401         
#       ovs_execute_actions+0x48         
#       ovs_dp_process_packet+0x7d     
#       ovs_vport_receive+0x6c  
#       netdev_frame_hook+0xd5  
#       __netif_receive_skb_core+0x6a3
#       __netif_receive_skb_one_core+0x3c
#       netif_receive_skb_internal+0x3d
#       napi_gro_receive+0xba
#       mlx5e_handle_rx_cqe+0xa3
#       mlx5e_poll_rx_cq+0xb61
#       mlx5e_napi_poll+0xee
#       net_rx_action+0x149
#       __softirqentry_text_start+0xe3
#       irq_exit+0x111
#       do_IRQ+0x7f
#       ret_from_intr+0x0
#     Stage 5 (ICMP_RCV): Stack ID 14796
#       icmp_rcv+0x1
#       ip_local_deliver_finish+0x60


from bcc import BPF, PerfType, PerfSWConfig
# for oe kernel, using python3
#from bpfcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define LATENCY_THRESHOLD_NS %d

#define STAGE_NETIF_RECV_SKB      0
#define STAGE_NETDEV_FRAME_HOOK   1
#define STAGE_DP_PROCESS_PACKET 2
#define STAGE_DP_UPCALL           3
#define STAGE_EXEC_ACTIONS        4
#define STAGE_VPORT_SEND          5
#define STAGE_ICMP_RCV            6 

struct packet_key_t {
    __be32 sip;
    __be32 dip;
    u8  proto;
    u8  icmp_type;
    __be16 id;
    __be16 seq;
};

struct flow_ts_value_t {
    u64 ts_stage0;
    u64 ts_stage1;
    u64 ts_stage2;
    u64 ts_stage3;
    u64 ts_stage4;
    u64 ts_stage5;
    u64 ts_stage6;
    int kstack_id0; 
    int kstack_id1;
    int kstack_id2;
    int kstack_id3;
    int kstack_id4;
    int kstack_id5;
    int kstack_id6;
    u32 first_pid;
    char first_comm[TASK_COMM_LEN];
    char first_ifname[IFNAMSIZ];
};

struct latency_event_data_t {
    struct packet_key_t key;
    struct flow_ts_value_t timestamps; 
    u32 final_pid;
    char final_comm[TASK_COMM_LEN];
    char final_ifname[IFNAMSIZ];
};

BPF_TABLE("lru_hash", struct packet_key_t, struct flow_ts_value_t, flow_timestamps, 20480);

BPF_STACK_TRACE(stack_traces, 10240); 

BPF_PERF_OUTPUT(latency_events);

static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key)
{
    if (skb == NULL) return 0;

    unsigned char *head;
    u16 network_header;
    u16 transport_header;
    u32 len;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) return 0;
    void *data_end = head + len;

    u16 mac_header;
    bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header);
    if (mac_header != (u16)~0U && (void *)(head + mac_header + sizeof(struct ethhdr)) <= data_end) {
        void *eth_ptr = head + mac_header;
        struct ethhdr eth;
        if (bpf_probe_read_kernel(&eth, sizeof(eth), eth_ptr) == 0) {
             if (eth.h_proto != bpf_htons(ETH_P_IP)) return 0;
        }
    }

    if (network_header == (u16)~0U || (void *)(head + network_header + sizeof(struct iphdr)) > data_end) return 0;
    void *ip_ptr = head + network_header;
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_ptr) < 0) return 0;

    if (!((SRC_IP_FILTER == 0 || ip.saddr == SRC_IP_FILTER) &&
          (DST_IP_FILTER == 0 || ip.daddr == DST_IP_FILTER))) {
        return 0;
    }

    if (ip.protocol != IPPROTO_ICMP) return 0;

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) return 0;

    void *icmp_ptr;
    if (transport_header != (u16)~0U && (void *)(head + transport_header + sizeof(struct icmphdr)) <= data_end) {
        icmp_ptr = head + transport_header;
    } else {
        void *calculated_icmp_ptr = ip_ptr + (ip_ihl * 4);
        if ((calculated_icmp_ptr + sizeof(struct icmphdr)) > data_end) return 0;
        icmp_ptr = calculated_icmp_ptr;
    }

    struct icmphdr ic;
    if (bpf_probe_read_kernel(&ic, sizeof(ic), icmp_ptr) < 0) return 0;
    if (ic.type != ICMP_ECHO && ic.type != ICMP_ECHOREPLY) return 0;

    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    key->icmp_type = ic.type;
    key->id  = ic.un.echo.id;
    key->seq = ic.un.echo.sequence;

    return 1;
}

static __always_inline void handle_event(struct pt_regs *ctx, struct sk_buff *skb, u64 stage_id) {
    if (skb == NULL) return;

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key)) {
        return; 
    }

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    struct flow_ts_value_t *value_ptr, zero = {};

    value_ptr = flow_timestamps.lookup_or_try_init(&key, &zero);
    if (!value_ptr) {
        return;
    }

    switch (stage_id) {
        case STAGE_NETIF_RECV_SKB:
            if (value_ptr->ts_stage0 == 0) {
                value_ptr->ts_stage0 = current_ts;
                value_ptr->kstack_id0 = stack_id;
                value_ptr->first_pid = bpf_get_current_pid_tgid() >> 32;
                bpf_get_current_comm(&value_ptr->first_comm, sizeof(value_ptr->first_comm));
                struct net_device *dev;
                bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
                if (dev != NULL) bpf_probe_read_kernel_str(&value_ptr->first_ifname, IFNAMSIZ, dev->name);
                else { char unk[] = "unknown"; __builtin_memcpy(value_ptr->first_ifname, unk, sizeof(unk));}
            }
            break;
        case STAGE_NETDEV_FRAME_HOOK: if (value_ptr->ts_stage1 == 0) { value_ptr->ts_stage1 = current_ts; value_ptr->kstack_id1 = stack_id; } break;
        case STAGE_DP_PROCESS_PACKET: if (value_ptr->ts_stage2 == 0) { value_ptr->ts_stage2 = current_ts; value_ptr->kstack_id2 = stack_id; } break;
        case STAGE_DP_UPCALL:         if (value_ptr->ts_stage3 == 0) { value_ptr->ts_stage3 = current_ts; value_ptr->kstack_id3 = stack_id; } break;
        case STAGE_EXEC_ACTIONS:      if (value_ptr->ts_stage4 == 0) { value_ptr->ts_stage4 = current_ts; value_ptr->kstack_id4 = stack_id; } break;
        case STAGE_VPORT_SEND:        if (value_ptr->ts_stage5 == 0) { value_ptr->ts_stage5 = current_ts; value_ptr->kstack_id5 = stack_id; } break;
    }
}


int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_event(ctx, skb, STAGE_NETIF_RECV_SKB);
    return 0;
}
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_event(ctx, skb, STAGE_NETDEV_FRAME_HOOK);
    return 0;
}
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb, void *item) {
    handle_event(ctx, (struct sk_buff *)skb, STAGE_DP_PROCESS_PACKET);
    return 0;
}
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb, const void *upcall_info) {
    handle_event(ctx, (struct sk_buff *)skb, STAGE_DP_UPCALL);
    return 0;
}
int kprobe__ovs_execute_actions(struct pt_regs *ctx, void *dp, struct sk_buff *skb) {
    handle_event(ctx, skb, STAGE_EXEC_ACTIONS);
    return 0;
}
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    handle_event(ctx, skb, STAGE_VPORT_SEND);
    return 0;
}

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (skb == NULL) return 0;

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key)) {
        return 0;
    }

    u64 final_ts = bpf_ktime_get_ns();
    int final_stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    struct flow_ts_value_t *value_ptr = flow_timestamps.lookup(&key);

    if (!value_ptr) {
        return 0;
    }

    value_ptr->ts_stage6 = final_ts;
    value_ptr->kstack_id6 = final_stack_id;

    if (LATENCY_THRESHOLD_NS > 0 && value_ptr->ts_stage0 > 0) {
        u64 total_latency = final_ts - value_ptr->ts_stage0;
        if (total_latency < LATENCY_THRESHOLD_NS) {
            return 0;
        }
    }

    struct latency_event_data_t event_data = {};
    event_data.key = key;
    event_data.timestamps = *value_ptr; 
    event_data.final_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event_data.final_comm, sizeof(event_data.final_comm));

    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev != NULL) bpf_probe_read_kernel_str(&event_data.final_ifname, IFNAMSIZ, dev->name);
    else { char unk[] = "unknown"; __builtin_memcpy(event_data.final_ifname, unk, sizeof(unk));}

    latency_events.perf_submit(ctx, &event_data, sizeof(event_data));

    return 0;
}

"""


IFNAMSIZ = 16
TASK_COMM_LEN = 16

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
        ("icmp_type", ctypes.c_uint8),
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16)
    ]

class FlowTsValue(ctypes.Structure):
     _fields_ = [
        ("ts_stage0", ctypes.c_uint64), ("ts_stage1", ctypes.c_uint64),
        ("ts_stage2", ctypes.c_uint64), ("ts_stage3", ctypes.c_uint64),
        ("ts_stage4", ctypes.c_uint64), ("ts_stage5", ctypes.c_uint64),
        ("ts_stage6", ctypes.c_uint64),
        ("kstack_id0", ctypes.c_int), ("kstack_id1", ctypes.c_int),
        ("kstack_id2", ctypes.c_int), ("kstack_id3", ctypes.c_int),
        ("kstack_id4", ctypes.c_int), ("kstack_id5", ctypes.c_int),
        ("kstack_id6", ctypes.c_int),
        ("first_pid", ctypes.c_uint32),
        ("first_comm", ctypes.c_char * TASK_COMM_LEN),
        ("first_ifname", ctypes.c_char * IFNAMSIZ),
    ]

class LatencyEventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("timestamps", FlowTsValue),
        ("final_pid", ctypes.c_uint32),
        ("final_comm", ctypes.c_char * TASK_COMM_LEN),
        ("final_ifname", ctypes.c_char * IFNAMSIZ),
    ]

stage_names = {
    0: "NETIF_RECV",
    1: "NETDEV_FRAME",
    2: "DP_PROCESS",
    3: "DP_UPCALL",
    4: "EXEC_ACTIONS",
    5: "VPORT_SEND",
    6: "ICMP_RCV",
}

def ip_to_hex(ip_str):
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '{}'".format(ip_str))
        sys.exit(1)

def format_ip(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

proto_names = {socket.IPPROTO_ICMP: "ICMP"}

def format_latency(ts_start, ts_end):
    if ts_start == 0 or ts_end == 0 or ts_end < ts_start:
        return " N/A ".rjust(7)
    delta_us = (ts_end - ts_start) / 1000.0
    return ("%.3f" % delta_us).rjust(7)

def print_latency_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(LatencyEventData)).contents
    ts = event.timestamps
    key = event.key

    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    pkt_info = "%s -> %s Proto=%s ICMP Type=%d ID=%d Seq=%d" % (
        format_ip(key.sip), format_ip(key.dip),
        proto_names.get(key.proto, str(key.proto)),
        key.icmp_type, socket.ntohs(key.id), socket.ntohs(key.seq)
    )
    initial_ctx = "PID=%-6d COMM=%-12s IF=%-10s" % (
          ts.first_pid, ts.first_comm.decode('utf-8', 'replace'),
          ts.first_ifname.decode('utf-8', 'replace'))

    stage_ts = [ts.ts_stage0, ts.ts_stage1, ts.ts_stage2, ts.ts_stage3,
                ts.ts_stage4, ts.ts_stage5, ts.ts_stage6]

    latency_strs = []
    latency_strs.append("[0->1]:%s" % format_latency(stage_ts[0], stage_ts[1]))
    latency_strs.append("[1->2]:%s" % format_latency(stage_ts[1], stage_ts[2]))

    if ts.ts_stage3 > 0:
        latency_strs.append("[2->3]:%s" % format_latency(stage_ts[2], stage_ts[3]))
        latency_strs.append("[3->4]:%s" % format_latency(stage_ts[3], stage_ts[4]))
    else:
        latency_strs.append("[2->4]:%s" % format_latency(stage_ts[2], stage_ts[4]))

    latency_strs.append("[4->5]:%s" % format_latency(stage_ts[4], stage_ts[5]))
    latency_strs.append("[5->6]:%s" % format_latency(stage_ts[5], stage_ts[6]))

    lat_total = format_latency(stage_ts[0], stage_ts[6])

    print("--- %s ---" % time_str)
    print("PKT: %s" % pkt_info)
    print("  Initial Context: %s" % initial_ctx)
    print("  Latencies (us): %s | Total[0->6]:%s" % (" ".join(latency_strs), lat_total))
    if ts.ts_stage3 > 0:
        print("  (Path: Flow Miss / Upcall)")
    else:
        print("  (Path: Flow Hit)")

    print("  Kernel Stack Traces:")
    stack_ids = [ts.kstack_id0, ts.kstack_id1, ts.kstack_id2, ts.kstack_id3,
                 ts.kstack_id4, ts.kstack_id5, ts.kstack_id6]
    for i, stack_id in enumerate(stack_ids):
        stage_name = stage_names.get(i, "?")
        if i == 3 and ts.ts_stage3 == 0:
            print("    Stage 3 (DP_UPCALL): <Skipped - Flow Hit>")
            continue

        if stack_id < 0:
            print("    Stage %d (%s): <Stack Capture Failed Error: %d>" % (i, stage_name, stack_id))
            continue
        if stack_id == 0 and stage_ts[i] == 0:
             if i == 3 and ts.ts_stage3 != 0:
                  print("    Stage %d (%s): <Stack ID is 0>" % (i, stage_name))
             else:
                  print("    Stage %d (%s): <Skipped>" % (i, stage_name))
             continue
        if stack_id == 0:
             print("    Stage %d (%s): <Stack ID is 0>" % (i, stage_name))
             continue

        print("    Stage %d (%s): Stack ID %d" % (i, stage_name, stack_id))
        try:
            for addr in b.get_table("stack_traces").walk(stack_id):
                 sym = b.ksym(addr, show_offset=True)
                 print("      %s" % sym)
        except NameError:
             print("      <Error: BPF object 'b' not accessible in print_latency_event>")
        except KeyError:
             print("      <Stack ID %d not found in table>" % stack_id)
        except Exception as e:
             print("      <Error walking/resolving stack ID %d: %s>" % (stack_id, e))
    print("") 

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Requires root privileges")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace ICMP packet latency through kernel stages, including OVS actions.")
    parser.add_argument('--src-ip', type=str, help='Filter by source IP')
    parser.add_argument('--dst-ip', type=str, help='Filter by destination IP')
    parser.add_argument('--latency-ms', type=float, default=0,
                        help='Minimum total latency (Stage 0->6) in milliseconds to report (default: 0, report all)')
    args = parser.parse_args()

    src_ip_filter_hex = ip_to_hex(args.src_ip)
    dst_ip_filter_hex = ip_to_hex(args.dst_ip)
    latency_threshold_ns = int(args.latency_ms * 1000000)

    print("Starting latency trace...")
    if args.src_ip: print("Filtering for Source IP: %s (0x%x)" % (args.src_ip, src_ip_filter_hex))
    if args.dst_ip: print("Filtering for Destination IP: %s (0x%x)" % (args.dst_ip, dst_ip_filter_hex))
    if latency_threshold_ns > 0: print("Reporting only if total latency >= %.3f ms" % args.latency_ms)

    if os.system("lsmod | grep openvswitch > /dev/null") != 0:
         print("Warning: Open vSwitch kernel module does not appear to be loaded.")

    cflags = []
    try:
        global b
        b = BPF(text=bpf_text % (src_ip_filter_hex, dst_ip_filter_hex, latency_threshold_ns),
                cflags=cflags)
    except Exception as e:
        print("Error compiling or loading BPF program:")
        print(e)
        sys.exit(1)

    probe_points = [
        "__netif_receive_skb", 
        "netdev_frame_hook",
        "ovs_dp_process_packet",
        "ovs_dp_upcall",
        "ovs_execute_actions",
        "ovs_vport_send",
        "icmp_rcv",
    ]
    probe_map = {
        "__netif_receive_skb": "kprobe____netif_receive_skb",
        "netdev_frame_hook": "kprobe__netdev_frame_hook",
        "ovs_dp_process_packet": "kprobe__ovs_dp_process_packet",
        "ovs_dp_upcall": "kprobe__ovs_dp_upcall",
        "ovs_execute_actions": "kprobe__ovs_execute_actions",
        "ovs_vport_send": "kprobe__ovs_vport_send",
        "icmp_rcv": "kprobe__icmp_rcv",
    }
    attached_probes = 0

    for func in probe_points:
        bpf_func_name = probe_map.get(func)
        if not bpf_func_name: continue
        try:
            b.attach_kprobe(event=func, fn_name=bpf_func_name)
            print("Attached kprobe to %s" % func)
            attached_probes += 1
        except Exception as e:
             print("Failed to attach kprobe to %s: %s" % (func, e))

    if attached_probes < 2:
        print("\nError: Failed to attach sufficient kprobes. Minimum needed: __netif_receive_skb, ovs_execute_actions, icmp_rcv. Exiting.")
        sys.exit(1)
    elif attached_probes < len(probe_points):
        print("\nWarning: Not all probes could be attached.")

    print("\nTracing packet latencies... Hit Ctrl-C to end.")
    print("(Output appears when packets complete icmp_rcv and exceed threshold if set)")

    b["latency_events"].open_perf_buffer(print_latency_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching probes and exiting...")
            exit()
        except Exception as e:
            print("Error in main loop: %s" % e)
            sleep(1)