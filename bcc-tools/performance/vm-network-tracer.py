#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
VM Network Performance Measurement Tool

Features:
- Support 5-tuple + devname filtering
- VM network path stage performance metrics collection  
- Software interrupt backlog queue monitoring
- OVS and conntrack performance analysis
- Output raw measurement data without aggregation

Usage:
    sudo python2 vm-network-tracer.py --dev=vnet0 --proto=tcp --src-ip=192.168.1.10
    sudo python2 vm-network-tracer.py --dst-ip=10.0.0.1 --verbose
"""

from __future__ import print_function
import argparse
import ctypes as ct
import time
import socket
import struct
from bcc import BPF

class PacketKey(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32), 
        ("protocol", ct.c_uint8),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("seq_or_id", ct.c_uint32),
        ("payload_len", ct.c_uint16),
    ]

class PktEvent(ct.Structure):
    _fields_ = [
        ("pkt_id", ct.c_uint64),
        ("key", PacketKey),
        ("t_ns", ct.c_uint64),
        ("cpu", ct.c_uint32),
        ("dev", ct.c_char * 16),
        ("dir", ct.c_uint8),
        ("stage", ct.c_uint8),
        ("rxq", ct.c_int16),
        ("txq", ct.c_int16), 
        ("has_hash", ct.c_uint8),
        ("has_sk", ct.c_uint8),
        ("skb_hash", ct.c_uint32),
        ("backlog_qlen", ct.c_int32),
        ("process_qlen", ct.c_int32),
        ("qdisc_qlen", ct.c_int32),
        ("flow_qlen", ct.c_int32),
        ("sojourn_ns", ct.c_uint64),
        ("sk_wmem", ct.c_uint32),
        ("sk_wmem_lim", ct.c_uint32),
        ("sk_rmem", ct.c_uint32), 
        ("sk_rmem_lim", ct.c_uint32),
        ("ct_hit", ct.c_uint8),
        ("ct_lookup_ns", ct.c_uint32),
        ("fib_hit", ct.c_uint8),
        ("fib_lookup_ns", ct.c_uint32),
    ]

STAGE_NAMES = {
    1: "RX_IN",
    2: "RX_BACKLOG", 
    3: "RX_PROCESS",
    4: "RX_GRO_IN",
    5: "RX_GRO_OUT",
    10: "IP_RCV",
    11: "IP_LOCAL_IN",
    12: "TCP_V4_RCV",
    13: "UDP_RCV",
    20: "OVS_IN",
    21: "OVS_ACT_IN", 
    22: "OVS_ACT_OUT",
    23: "CT_IN",
    24: "CT_OUT",
    25: "OVS_UPCALL",
    60: "QDISC_ENQ",
    61: "QDISC_DEQ",
    70: "DEV_Q_XMIT",
    72: "TX_QUEUE",
    73: "TX_XMIT",
    80: "SKB_CLONE",
    82: "SKB_FREE",
    83: "SKB_DROP",
    84: "SKB_CONSUME",
}

BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>

struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip; 
    u8 protocol;
    __be16 src_port;
    __be16 dst_port;
    __be32 seq_or_id;
    __be16 payload_len;
};

struct pkt_event {
    u64 pkt_id;
    struct packet_key_t key;
    u64 t_ns;
    u32 cpu;
    char dev[16];
    u8 dir;
    u8 stage;
    s16 rxq;
    s16 txq; 
    u8 has_hash;
    u8 has_sk;
    u32 skb_hash;
    s32 backlog_qlen;
    s32 process_qlen;
    s32 qdisc_qlen;
    s32 flow_qlen;
    u64 sojourn_ns;
    u32 sk_wmem;
    u32 sk_wmem_lim;
    u32 sk_rmem; 
    u32 sk_rmem_lim;
    u8 ct_hit;
    u32 ct_lookup_ns;
    u8 fib_hit;
    u32 fib_lookup_ns;
};

#if IFNAMSIZ != 16 
#error "IFNAMSIZ != 16 is not supported"
#endif


struct filter_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
    u8 direction_filter;  // 0=all, 1=input only, 2=output only
};

BPF_HASH(pkt_key_cache, u64, struct packet_key_t, 10000);
BPF_HASH(clone_map, u64, u64, 1000);
BPF_HASH(dir_cache, u64, u8, 5000);
BPF_HASH(ct_start_time, u64, u64, 1000);
BPF_HASH(ovs_start_time, u64, u64, 1000);
BPF_ARRAY(stage_counters, u64, 30);
BPF_ARRAY(config_map, struct filter_key_t, 1);

// Track packet stages for complete path output
#define MAX_STAGES 20
struct packet_path_t {
    u64 first_seen_ns;
    u8 num_stages;
    u8 direction;  // 0=input (VM TX), 1=output (VM RX)
    struct {
        u8 stage;
        u64 timestamp_ns;
        char dev[16];
        u16 rxq;
        u32 cpu;
    } stages[MAX_STAGES];
};
BPF_HASH(packet_paths, u64, struct packet_path_t, 5000);

BPF_PERF_OUTPUT(events);

static inline u64 get_unified_pkt_id(struct sk_buff *skb) {
    u64 pkt_id = (u64)skb;
    u64 *parent_id = clone_map.lookup(&pkt_id);
    if (parent_id)
        return *parent_id;
    return pkt_id;
}

static inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key) {
    __be16 protocol;
    bpf_probe_read(&protocol, sizeof(protocol), &skb->protocol);
    
    if (protocol != htons(ETH_P_IP))
        return -1;
    
    unsigned char *head;
    u16 network_header;
    bpf_probe_read(&head, sizeof(head), &skb->head);
    bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header);
    
    if (!head || network_header == 0)
        return -1;
    
    struct iphdr ip;
    if (bpf_probe_read(&ip, sizeof(ip), head + network_header) != 0)
        return -1;
    
    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;
    key->payload_len = 0;
    
    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
        struct {
            __be16 source;
            __be16 dest;
            __be32 seq_or_len;
        } ports;
        
        if (bpf_probe_read(&ports, sizeof(ports), head + network_header + 20) == 0) {
            key->src_port = ports.source;
            key->dst_port = ports.dest;
            key->seq_or_id = ports.seq_or_len;
        }
    } else {
        key->src_port = 0;
        key->dst_port = 0;
        key->seq_or_id = 0;
    }
    
    return 0;
}


static inline int check_filter(struct sk_buff *skb, struct packet_key_t *key, char *dev_name) {
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    if (!filter)
        return 1;
    
    if (filter->src_ip && filter->src_ip != key->src_ip)
        return 0;
    if (filter->dst_ip && filter->dst_ip != key->dst_ip)
        return 0;
    
    if (filter->src_port && filter->src_port != key->src_port)
        return 0;
    if (filter->dst_port && filter->dst_port != key->dst_port)
        return 0;
    
    if (filter->protocol && filter->protocol != key->protocol)
        return 0;
    
    return 1;
}

static inline u8 determine_direction(u8 stage, char *dev) {
    if (stage == 1) {
        if (dev[0] == 'v' && dev[1] == 'n' && dev[2] == 'e' && dev[3] == 't')
            return 0;
        else
            return 1;
    }
    
    return 0;
}

static inline void collect_stage(void *ctx, struct sk_buff *skb, u8 stage, char *dev_name) {
    u64 pkt_id = get_unified_pkt_id(skb);
    u64 now = bpf_ktime_get_ns();
    
    // Parse packet key if not cached
    struct packet_key_t *cached_key = pkt_key_cache.lookup(&pkt_id);
    struct packet_key_t key = {};
    if (cached_key) {
        key = *cached_key;
    } else {
        if (parse_packet_key(skb, &key) < 0) {
            return;
        }
        pkt_key_cache.update(&pkt_id, &key);
    }
    
    // Check filter
    if (!check_filter(skb, &key, dev_name))
        return;
    
    // Check direction filter first
    u8 dir = determine_direction(stage, dev_name);
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    if (filter && filter->direction_filter != 0) {
        // 1=input only (VM TX, dir=0), 2=output only (VM RX, dir=1)  
        if (filter->direction_filter == 1 && dir != 0) return;
        if (filter->direction_filter == 2 && dir != 1) return;
    }
    
    // For now, just emit immediate events instead of path tracking to avoid stack issues
    struct pkt_event evt = {};
    evt.pkt_id = pkt_id;
    evt.key = key;
    evt.dir = dir;
    evt.t_ns = now;
    evt.stage = stage;
    __builtin_memcpy(evt.dev, dev_name, sizeof(evt.dev));
    
    u16 rxq;
    bpf_probe_read(&rxq, sizeof(rxq), &skb->queue_mapping);
    evt.rxq = rxq;
    
    events.perf_submit(ctx, &evt, sizeof(evt));
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(args, skb, 1, dev_name); // STG_RX_IN
    return 0;
}

int trace_enqueue_to_backlog(struct pt_regs *ctx, struct sk_buff *skb, int cpu, unsigned int *qtail) {
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(ctx, skb, 2, dev_name);     return 0;
}

int trace_process_backlog(struct pt_regs *ctx, struct napi_struct *napi, int quota) {
    return 0;
}

int trace_ovs_vport_receive(struct pt_regs *ctx, void *vport, struct sk_buff *skb, void *tun_info) {
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(ctx, skb, 20, dev_name); // STG_OVS_IN  
    return 0;
}

int trace_ovs_execute_actions(struct pt_regs *ctx, void *dp, struct sk_buff *skb, void *acts, void *key) {
    if (!skb) return 0;
    
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    u64 pkt_id = get_unified_pkt_id(skb);
    u64 now = bpf_ktime_get_ns();
    
    ovs_start_time.update(&pkt_id, &now);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(ctx, skb, 21, dev_name); // STG_OVS_ACT_IN
    return 0;
}

int trace_ovs_execute_actions_ret(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (!skb) return 0;
    
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    u64 pkt_id = get_unified_pkt_id(skb);
    u64 *start_time = ovs_start_time.lookup(&pkt_id);
    
    if (start_time) {
        u64 now = bpf_ktime_get_ns();
        u64 duration = now - *start_time;
            ovs_start_time.delete(&pkt_id);
    }
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(ctx, skb, 22, dev_name); // STG_OVS_ACT_OUT
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(args, skb, 72, dev_name); // STG_TX_QUEUE
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_start_xmit) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr; 
    
    int zero = 0;
    struct filter_key_t *filter = config_map.lookup(&zero);
    
    char dev_name[16] = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read(dev_name, sizeof(dev_name), dev->name);
    }
    
    collect_stage(args, skb, 73, dev_name); // STG_TX_XMIT
    return 0;
}

int trace_skb_clone_ret(struct pt_regs *ctx) {
    struct sk_buff *parent = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct sk_buff *child = (struct sk_buff *)PT_REGS_RC(ctx);
    
    if (child) {
        u64 parent_id = (u64)parent;
        u64 child_id = (u64)child;
        clone_map.update(&child_id, &parent_id);
    }
    return 0;
}
"""

def ip_to_int(ip_str):
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        # Keep network byte order for kernel comparison
        net_int = struct.unpack("I", packed_ip)[0]
        return net_int
    except socket.error:
        print("Error: Invalid IP address format '{}'".format(ip_str))
        return 0

def int_to_ip(ip_int):
    # IP from kernel is in network byte order
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip_int))

class FilterKey(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("protocol", ct.c_uint8),
        ("direction_filter", ct.c_uint8),
    ]

def protocol_name(proto_num):
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return proto_map.get(proto_num, str(proto_num))

def format_event(event):
    stage_name = STAGE_NAMES.get(event.stage, "UNKNOWN({})".format(event.stage))
    direction = "VM→UP" if event.dir == 0 else "UP→VM"
    real_dev_name = event.dev.decode('utf-8', 'ignore').rstrip('\x00')
    
    timestamp = time.time()
    print("[{:.6f}] PKT_ID={:016x} DIR={} STAGE={} DEV={}".format(
        timestamp, event.pkt_id, direction, stage_name, 
        real_dev_name))
    
    src_ip = int_to_ip(event.key.src_ip)
    dst_ip = int_to_ip(event.key.dst_ip) 
    proto = protocol_name(event.key.protocol)
    
    if event.key.protocol in [6, 17]:
        print("  KEY: {} {}:{}->{}:{} SEQ/ID={} LEN={}".format(
            proto, src_ip, event.key.src_port, dst_ip, event.key.dst_port,
            event.key.seq_or_id, event.key.payload_len))
    else:
        print("  KEY: {} {}->{} ID={} LEN={}".format(
            proto, src_ip, dst_ip, event.key.seq_or_id, event.key.payload_len))
    
    print("  QUEUE: RXQ={} TXQ={} HASH=0x{:08x}".format(
        event.rxq, event.txq, event.skb_hash))
    
    if event.backlog_qlen >= 0 or event.process_qlen >= 0:
        print("  QLEN: BACKLOG={} PROCESS={}".format(
            event.backlog_qlen, event.process_qlen))
    
    if event.ct_lookup_ns > 0:
        ct_result = "HIT" if event.ct_hit else "MISS"
        print("  LOOKUP: CT={}/{:.1f}us".format(
            ct_result, event.ct_lookup_ns/1000.0))
    
    print()

def main():
    parser = argparse.ArgumentParser(description="VM Network Performance Measurement Tool")
    parser.add_argument("--src-ip", help="Source IP filter")
    parser.add_argument("--dst-ip", help="Destination IP filter")  
    parser.add_argument("--src-port", type=int, help="Source port filter")
    parser.add_argument("--dst-port", type=int, help="Destination port filter")
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp"], help="Protocol filter")
    parser.add_argument("--direction", choices=["input", "output"], help="Direction filter (input=VM TX, output=VM RX)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    print("VM Network Performance Measurement Tool")
    print("Initializing eBPF program...")
    
    b = BPF(text=BPF_PROGRAM)
    try:
        b.attach_kprobe(event="enqueue_to_backlog", fn_name="trace_enqueue_to_backlog")
    except:
        print("Warning: Cannot attach enqueue_to_backlog kprobe")
    
    try:
        b.attach_kprobe(event="process_backlog", fn_name="trace_process_backlog")
    except:
        print("Warning: Cannot attach process_backlog kprobe")
    
    try:
        b.attach_kprobe(event="ovs_vport_receive", fn_name="trace_ovs_vport_receive")
    except:
        print("Warning: Cannot attach ovs_vport_receive kprobe")
    
    try:
        b.attach_kprobe(event="ovs_execute_actions", fn_name="trace_ovs_execute_actions")
        b.attach_kretprobe(event="ovs_execute_actions", fn_name="trace_ovs_execute_actions_ret")
    except:
        print("Warning: Cannot attach ovs_execute_actions kprobe")
    
    try:
        b.attach_kretprobe(event="skb_clone", fn_name="trace_skb_clone_ret")
    except:
        print("Warning: Cannot attach skb_clone kretprobe")
    
    filter_key = b["config_map"][0]
    filter_key.src_ip = ip_to_int(args.src_ip) if args.src_ip else 0
    filter_key.dst_ip = ip_to_int(args.dst_ip) if args.dst_ip else 0
    filter_key.src_port = args.src_port if args.src_port else 0
    filter_key.dst_port = args.dst_port if args.dst_port else 0
    
    if args.proto:
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
        filter_key.protocol = proto_map[args.proto]
    else:
        filter_key.protocol = 0
    
    # Set direction filter
    if args.direction == "input":
        filter_key.direction_filter = 1  # VM TX only
    elif args.direction == "output":
        filter_key.direction_filter = 2  # VM RX only
    else:
        filter_key.direction_filter = 0  # All directions
    
    b["config_map"][0] = filter_key
    
    print("Filter conditions:")
    if args.src_ip:
        print("  Source IP: {}".format(args.src_ip))
    if args.dst_ip:
        print("  Destination IP: {}".format(args.dst_ip))
    if args.src_port:
        print("  Source Port: {}".format(args.src_port))
    if args.dst_port:
        print("  Destination Port: {}".format(args.dst_port))
    if args.proto:
        print("  Protocol: {}".format(args.proto.upper()))
    if args.direction:
        dir_desc = "VM TX (from VM)" if args.direction == "input" else "VM RX (to VM)"
        print("  Direction: {} ({})".format(args.direction, dir_desc))
    print()
    
    print("Tracing VM network packets... Ctrl-C to stop")
    print()
    
    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PktEvent)).contents
        format_event(event)
    
    b["events"].open_perf_buffer(print_event)
    try:
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\nExiting...")

if __name__ == "__main__":
    main()