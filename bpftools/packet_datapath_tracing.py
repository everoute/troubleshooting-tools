#!/usr/bin/python3

#from bcc import BPF
from bpfcc import BPF
from socket import inet_ntop, AF_INET, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import socket
import argparse

def ip_to_hex(ip):
    return htonl(unpack("!I", inet_aton(ip))[0])

parser = argparse.ArgumentParser(description='Tracing network packets for specific IP addresses and ports')
parser.add_argument('--src', type=str, help='Source IP address to tracing (in dotted decimal notation)')
parser.add_argument('--dst', type=str, help='Destination IP address to tracing (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp'], default='all', help='Protocol to tracing')
parser.add_argument('--src-port', type=int, help='Source port to tracing (for TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port to tracing (for TCP/UDP)')
args = parser.parse_args()

src_ip = args.src if args.src else "0.0.0.0"
dst_ip = args.dst if args.dst else "0.0.0.0"
src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0

print(f"Monitoring source IP: {src_ip}")
print(f"Monitoring destination IP: {dst_ip}")
print(f"Protocol: {args.protocol}")
if args.protocol in ['tcp', 'udp']:
    print(f"Source port: {src_port}")
    print(f"Destination port: {dst_port}")

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

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
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d

struct tun_xmit_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    // other tun_net_xmit related struct/metadata
};
BPF_PERF_OUTPUT(tun_xmit);

//int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb)
int trace_tun_net_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
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

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct tun_xmit_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.raw_stack_id = data.stack_id; 
    if (data.stack_id < 0) {
        data.stack_id = -data.stack_id; 
    }
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Check IP addresses
    if ((SRC_IP == 0 || saddr == SRC_IP) && (DST_IP == 0 || daddr == DST_IP)) {
        // Check protocol
        if (PROTOCOL == 0 || iph.protocol == PROTOCOL) {
            if (iph.protocol == IPPROTO_ICMP) {
                struct icmphdr icmph;
                bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);
                data.icmp_type = icmph.type;
                data.icmp_code = icmph.code;
                tun_xmit.perf_submit(ctx, &data, sizeof(data));
            } else if (iph.protocol == IPPROTO_TCP) {
                struct tcphdr tcph;
                bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header);
                data.sport = ntohs(tcph.source);
                data.dport = ntohs(tcph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    tun_xmit.perf_submit(ctx, &data, sizeof(data));
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                struct udphdr udph;
                bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);
                data.sport = ntohs(udph.source);
                data.dport = ntohs(udph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    tun_xmit.perf_submit(ctx, &data, sizeof(data));
                }
            } else {
                // For other protocols, submit without port information
                tun_xmit.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }
    // other func parameter struct/metadata

    return 0;
}

struct dropped_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
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
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
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

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct dropped_skb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.raw_stack_id = data.stack_id; 
    if (data.stack_id < 0) {
        data.stack_id = -data.stack_id; 
    }
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Check IP addresses
    if ((SRC_IP == 0 || saddr == SRC_IP) && (DST_IP == 0 || daddr == DST_IP)) {
        // Check protocol
        if (PROTOCOL == 0 || iph.protocol == PROTOCOL) {
            if (iph.protocol == IPPROTO_ICMP) {
                struct icmphdr icmph;
                bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);
                data.icmp_type = icmph.type;
                data.icmp_code = icmph.code;
                kfree_drops.perf_submit(ctx, &data, sizeof(data));
            } else if (iph.protocol == IPPROTO_TCP) {
                struct tcphdr tcph;
                bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header);
                data.sport = ntohs(tcph.source);
                data.dport = ntohs(tcph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                struct udphdr udph;
                bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);
                data.sport = ntohs(udph.source);
                data.dport = ntohs(udph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                }
            } else {
                // For other protocols, submit without port information
                kfree_drops.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }

    return 0;
}

struct netif_receive_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(netif_receive_skb_data);

int trace_netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
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

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct netif_receive_skb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.raw_stack_id = data.stack_id; 
    if (data.stack_id < 0) {
        data.stack_id = -data.stack_id; 
    }
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Check IP addresses
    if ((SRC_IP == 0 || saddr == SRC_IP) && (DST_IP == 0 || daddr == DST_IP)) {
        // Check protocol
        if (PROTOCOL == 0 || iph.protocol == PROTOCOL) {
            if (iph.protocol == IPPROTO_ICMP) {
                struct icmphdr icmph;
                bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);
                data.icmp_type = icmph.type;
                data.icmp_code = icmph.code;
                netif_receive_skb_data.perf_submit(ctx, &data, sizeof(data));
            } else if (iph.protocol == IPPROTO_TCP) {
                struct tcphdr tcph;
                bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header);
                data.sport = ntohs(tcph.source);
                data.dport = ntohs(tcph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    netif_receive_skb_data.perf_submit(ctx, &data, sizeof(data));
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                struct udphdr udph;
                bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);
                data.sport = ntohs(udph.source);
                data.dport = ntohs(udph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    netif_receive_skb_data.perf_submit(ctx, &data, sizeof(data));
                }
            } else {
                // For other protocols, submit without port information
                netif_receive_skb_data.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }
    // other func parameter struct/metadata

    return 0;
}

struct net_dev_start_xmit_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_dev_start_xmit_data);

int trace_net_dev_start_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
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

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct net_dev_start_xmit_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.raw_stack_id = data.stack_id; 
    if (data.stack_id < 0) {
        data.stack_id = -data.stack_id; 
    }
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Check IP addresses
    if ((SRC_IP == 0 || saddr == SRC_IP) && (DST_IP == 0 || daddr == DST_IP)) {
        // Check protocol
        if (PROTOCOL == 0 || iph.protocol == PROTOCOL) {
            if (iph.protocol == IPPROTO_ICMP) {
                struct icmphdr icmph;
                bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);
                data.icmp_type = icmph.type;
                data.icmp_code = icmph.code;
                net_dev_start_xmit_data.perf_submit(ctx, &data, sizeof(data));
            } else if (iph.protocol == IPPROTO_TCP) {
                struct tcphdr tcph;
                bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header);
                data.sport = ntohs(tcph.source);
                data.dport = ntohs(tcph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    net_dev_start_xmit_data.perf_submit(ctx, &data, sizeof(data));
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                struct udphdr udph;
                bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);
                data.sport = ntohs(udph.source);
                data.dport = ntohs(udph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    net_dev_start_xmit_data.perf_submit(ctx, &data, sizeof(data));
                }
            } else {
                // For other protocols, submit without port information
                net_dev_start_xmit_data.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }
    // other func parameter struct/metadata

    return 0;
}
"""
#b = BPF(text=bpf_text)
protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP}
protocol_num = protocol_map[args.protocol]
b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num))
# if use xxx.c as bpf program which is not embeded in python code as text. 
#EBPF_FILE = "multi-probe.c"
#b = BPF(src_file = EBPF_FILE)

b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
b.attach_kprobe(event="netif_receive_skb", fn_name="trace_netif_receive_skb_icmp")
b.attach_kprobe(event="dev_hard_start_xmit", fn_name="trace_net_dev_start_xmit_icmp")

def print_basic_skb_data(cpu, data, size, perf_event=""):
    event = b[perf_event].event(data)
    protocol_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.protocol, str(event.protocol))
    print("%-9s %-6d %-12s -> %-12s %-16s Protocol: %-4s" % (
        strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        protocol_str))
    
    if event.protocol == socket.IPPROTO_ICMP:
        print("ICMP Type: %-2d Code: %-2d" % (event.icmp_type, event.icmp_code))
    elif event.protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
        print("Source Port: %-5d Destination Port: %-5d" % (event.sport, event.dport))
    
    print("Device: %-16s" % event.ifname.decode('utf-8'))
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

def print_tun_xmit_event(cpu, data, size):
    print_basic_skb_data(cpu, data, size, perf_event="tun_xmit")

b["tun_xmit"].open_perf_buffer(print_tun_xmit_event)

def print_netif_receive_skb_event(cpu, data, size):
    print_basic_skb_data(cpu, data, size, perf_event="netif_receive_skb_data")

b["netif_receive_skb_data"].open_perf_buffer(print_netif_receive_skb_event)

def print_net_dev_start_xmit_event(cpu, data, size):
    print_basic_skb_data(cpu, data, size, perf_event="net_dev_start_xmit_data")

b["net_dev_start_xmit_data"].open_perf_buffer(print_net_dev_start_xmit_event)

def print_kfree_drop_event(cpu, data, size):
    print_basic_skb_data(cpu, data, size, perf_event="kfree_drops")

b["kfree_drops"].open_perf_buffer(print_kfree_drop_event)


while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
