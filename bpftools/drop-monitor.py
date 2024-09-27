#!/usr/bin/python3

#from bcc import BPF
#from bcc.utils import printb
from bpfcc import BPF
from bpfcc.utils import printb
import ctypes as ct
from socket import inet_ntop, AF_INET, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import os
import socket
import struct
import argparse

def ip_to_hex(ip):
    return htonl(unpack("!I", inet_aton(ip))[0])

parser = argparse.ArgumentParser(description='Monitor ICMP packets for specific IP addresses')
parser.add_argument('--src', type=str, help='Source IP address to monitor (in dotted decimal notation)')
parser.add_argument('--dst', type=str, help='Destination IP address to monitor (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, help='protocol (TODO) just support icmp tracing now)')
args = parser.parse_args()

src_ip = args.src if args.src else "10.4.124.76"
dst_ip = args.dst if args.dst else "10.4.124.74"

print(f"Monitoring source IP: {src_ip}")
print(f"Monitoring destination IP: {dst_ip}")

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

print(f"Monitoring source IP hex: 0x{src_ip_hex:08X}")
print(f"Monitoring destination IP hex: 0x{dst_ip_hex:08X}")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

BPF_HASH(ipv4_count, u32, u64);
BPF_STACK_TRACE(stack_traces, 8192);  
#define SRC_IP 0x%x
#define DST_IP 0x%x

struct tun_xmit_icmp_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(tun_xmit_icmp);

//int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb)
int trace_tun_net_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb == NULL)
        return 0;

    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol != htons(ETH_P_IP))
        return 0;

    // Read head pointer
    unsigned char *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);

    // Extract IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;

    // Safely read network_header and transport_header
    //u16 network_header;
    //u16 transport_header;
    //bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    //bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    if (iph.protocol != IPPROTO_ICMP)
        return 0;

    struct icmphdr icmph;
    bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    // Filter for 10.200.0.87 (in network byte order)
    // 0x5700C80A  10.200.0.87 reversed for network byte order
    // 10.4.124.74 0x4A7C040A
    // 10.4.124.66 0x427C040A
    // 10.4.250.4 0x04FA040A
    // 10.4.250.16 0x10FA040A
    //u32 target_ip = 0x5700C80A;  
    if ((saddr == SRC_IP && daddr == DST_IP) || (saddr == DST_IP && daddr == SRC_IP))
    {
        struct tun_xmit_icmp_data_t data = {};
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.icmp_type = icmph.type;
        data.icmp_code = icmph.code;
        data.stack_id = stack_traces.get_stackid(ctx, 0);
        data.raw_stack_id = data.stack_id; 
        if (data.stack_id < 0) {
            data.stack_id = -data.stack_id; 
        }
        bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        tun_xmit_icmp.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

struct dropped_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(kfree_drops);

int trace_kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    // 检查是否为 IPv4 数据包
    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol != htons(ETH_P_IP))
        return 0;

    // Read head pointer
    unsigned char *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);

    // Extract IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;

    // Safely read network_header and transport_header
    //u16 network_header;
    //u16 transport_header;
    //bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    //bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    if (iph.protocol != IPPROTO_ICMP)
        return 0;

    struct icmphdr icmph;
    bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    // Filter for 10.200.0.87 (in network byte order)
    // 10.200.0.87 in hex, reversed for network byte order
    //u32 target_ip = 0x5700C80A;  
    if ((saddr == SRC_IP && daddr == DST_IP) || (saddr == DST_IP && daddr == SRC_IP))
    {
        struct dropped_skb_data_t data = {};
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.icmp_type = icmph.type;
        data.icmp_code = icmph.code;
        data.stack_id = stack_traces.get_stackid(ctx, 0);
        data.raw_stack_id = data.stack_id; 
        if (data.stack_id < 0) {
            data.stack_id = -data.stack_id; 
        }
        bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        kfree_drops.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

struct netif_receive_skb_icmp_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(netif_receive_skb_data);

int trace_netif_receive_skb_icmp(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    // 检查是否为 IPv4 数据包
    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol != htons(ETH_P_IP))
        return 0;

    // Read head pointer
    unsigned char *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);

    // Extract IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;

    // Safely read network_header and transport_header
    //u16 network_header;
    //u16 transport_header;
    //bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    //bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    if (iph.protocol != IPPROTO_ICMP)
        return 0;

    struct icmphdr icmph;
    bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    // Filter for 10.200.0.87 (in network byte order)
    // 10.200.0.87 in hex, reversed for network byte order
    //u32 target_ip = 0x5700C80A;  
    if ((saddr == SRC_IP && daddr == DST_IP) || (saddr == DST_IP && daddr == SRC_IP))
    {
        struct netif_receive_skb_icmp_data_t data = {};
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.icmp_type = icmph.type;
        data.icmp_code = icmph.code;
        data.stack_id = stack_traces.get_stackid(ctx, 0);
        data.raw_stack_id = data.stack_id; 
        if (data.stack_id < 0) {
            data.stack_id = -data.stack_id; 
        }
        bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        netif_receive_skb_data.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

struct net_dev_start_xmit_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_dev_start_xmit_data);

int trace_net_dev_start_xmit_icmp(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    // 检查是否为 IPv4 数据包
    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol != htons(ETH_P_IP))
        return 0;

    // Read head pointer
    unsigned char *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);

    // Extract IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;

    // Safely read network_header and transport_header
    //u16 network_header;
    //u16 transport_header;
    //bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    //bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    if (iph.protocol != IPPROTO_ICMP)
        return 0;

    struct icmphdr icmph;
    bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    // Filter for 10.200.0.87 (in network byte order)
    // 10.200.0.87 in hex, reversed for network byte order
    //u32 target_ip = 0x5700C80A;  
    //if (saddr == target_ip || daddr == target_ip)
    if ((saddr == SRC_IP && daddr == DST_IP) || (saddr == DST_IP && daddr == SRC_IP))
    {
        struct net_dev_start_xmit_data_t data = {};
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.icmp_type = icmph.type;
        data.icmp_code = icmph.code;
        data.stack_id = stack_traces.get_stackid(ctx, 0);
        data.raw_stack_id = data.stack_id; 
        if (data.stack_id < 0) {
            data.stack_id = -data.stack_id; 
        }
        bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        net_dev_start_xmit_data.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""
#b = BPF(text=bpf_text)
b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex))

#EBPF_FILE = "multi-probe.c"
#b = BPF(src_file = EBPF_FILE)

b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
b.attach_kprobe(event="netif_receive_skb", fn_name="trace_netif_receive_skb_icmp")
b.attach_kprobe(event="dev_hard_start_xmit", fn_name="trace_net_dev_start_xmit_icmp")

def print_tun_xmit_icmp_event(cpu, data, size):
    event = b["tun_xmit_icmp"].event(data)
    print("%-9s %-6d %-12s -> %-12s %-16s Type: %-2d Code: %-2d Dev: %-16s" % (
        strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.icmp_type, event.icmp_code,
        event.ifname.decode('utf-8')))

    print("Stack ID: %d, Raw Stack ID: %d" % (event.stack_id, event.raw_stack_id))
    
    #for addr in b.get_table("stack_traces").walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)
    if event.stack_id > 0:
        try:
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("\t%s" % sym)
        except KeyError:
            print("\tFailed to retrieve stack trace (ID: %d)" % event.stack_id)
    else:
        print("\tFailed to capture stack trace (Error code: %d)" % event.stack_id)

    print("")

b["tun_xmit_icmp"].open_perf_buffer(print_tun_xmit_icmp_event)

def print_netif_receive_skb_icmp_event(cpu, data, size):
    event = b["netif_receive_skb_data"].event(data)
    print("%-9s %-6d %-12s -> %-12s %-16s Type: %-2d Code: %-2d Dev: %-16s" % (
        strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.icmp_type, event.icmp_code,
        event.ifname.decode('utf-8')))

    print("Stack ID: %d, Raw Stack ID: %d" % (event.stack_id, event.raw_stack_id))
    
    #for addr in b.get_table("stack_traces").walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)
    if event.stack_id > 0:
        try:
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("\t%s" % sym)
        except KeyError:
            print("\tFailed to retrieve stack trace (ID: %d)" % event.stack_id)
    else:
        print("\tFailed to capture stack trace (Error code: %d)" % event.stack_id)

    print("")

b["netif_receive_skb_data"].open_perf_buffer(print_netif_receive_skb_icmp_event)


def print_net_dev_start_xmit_icmp_event(cpu, data, size):
    event = b["net_dev_start_xmit_data"].event(data)
    print("%-9s %-6d %-12s -> %-12s %-16s Type: %-2d Code: %-2d Dev: %-16s" % (
        strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.icmp_type, event.icmp_code,
        event.ifname.decode('utf-8')))

    print("Stack ID: %d, Raw Stack ID: %d" % (event.stack_id, event.raw_stack_id))
    
    #for addr in b.get_table("stack_traces").walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)
    if event.stack_id > 0:
        try:
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("\t%s" % sym)
        except KeyError:
            print("\tFailed to retrieve stack trace (ID: %d)" % event.stack_id)
    else:
        print("\tFailed to capture stack trace (Error code: %d)" % event.stack_id)

    print("")

b["net_dev_start_xmit_data"].open_perf_buffer(print_net_dev_start_xmit_icmp_event)

def print_kfree_drop_event(cpu, data, size):
    event = b["kfree_drops"].event(data)
    print("%-9s %-6d %-12s -> %-12s %-16s Type: %-2d Code: %-2d Dev: %-16s" % (
        strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.icmp_type, event.icmp_code,
        event.ifname.decode('utf-8')))

    print("Stack ID: %d, Raw Stack ID: %d" % (event.stack_id, event.raw_stack_id))
    
    #for addr in b.get_table("stack_traces").walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)
    if event.stack_id > 0:
        try:
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("\t%s" % sym)
        except KeyError:
            print("\tFailed to retrieve stack trace (ID: %d)" % event.stack_id)
    else:
        print("\tFailed to capture stack trace (Error code: %d)" % event.stack_id)

    print("")

b["kfree_drops"].open_perf_buffer(print_kfree_drop_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
