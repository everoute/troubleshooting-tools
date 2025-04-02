#!/usr/bin/python2

#from bpfcc import BPF
#from bpfcc.utils import printb
from bcc import BPF
from bcc.utils import printb
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

parser = argparse.ArgumentParser(description='Monitor network packets for specific IP addresses and ports')
parser.add_argument('--src', type=str, help='Source IP address to monitor (in dotted decimal notation)')
parser.add_argument('--dst', type=str, help='Destination IP address to monitor (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp'], default='all', help='Protocol to monitor')
parser.add_argument('--src-port', type=int, help='Source port to monitor (for TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port to monitor (for TCP/UDP)')
parser.add_argument('--log-file', type=str, help='Path to log file (if specified, output will be written to this file)')
args = parser.parse_args()

src_ip = args.src if args.src else "0.0.0.0"
dst_ip = args.dst if args.dst else "0.0.0.0"
src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0

print("Monitoring source IP: {}".format(src_ip))
print("Monitoring destination IP: {}".format(dst_ip))
print("Protocol: {}".format(args.protocol))
if args.protocol in ['tcp', 'udp']:
    print("Source port: {}".format(src_port))
    print("Destination port: {}".format(dst_port))

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

# Set up log file handling
log_file = None
if args.log_file:
    try:
        log_file = open(args.log_file, 'a')
        log_file.write("=== Monitoring started at {} ===\n\n".format(strftime('%Y-%m-%d %H:%M:%S')))
    except Exception as e:
        print("Error opening log file: {}".format(e))
        print("Continuing without logging to file")
        log_file = None

# Helper function to handle output
def log_output(message):
    if log_file:
        log_file.write(message + '\n')
        log_file.flush()  # Ensure log is written immediately, not buffered
    else:
        print(message)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>

BPF_HASH(ipv4_count, u32, u64);
BPF_STACK_TRACE(stack_traces, 8192);  
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d

struct dropped_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 vlan_id;
    u16 ip_id;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    int kernel_stack_id;
    int user_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    u32 drop_reason;
};
BPF_PERF_OUTPUT(kfree_drops);

int trace_kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u32 drop_reason = (u32)PT_REGS_PARM2(ctx);
    
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
    data.vlan_id = 0;
    data.ip_id = ntohs(iph.id);

    // Read vlan_tci and extract VLAN ID
    unsigned short vlan_tci = 0;
    vlan_tci = skb->vlan_tci;
    data.vlan_id = vlan_tci & 0x0FFF;

    // Use only BPF_F_FAST_STACK_CMP to minimize stack depth issues
    // The stack will be compared by hash only, which avoids the BPF_MAX_STACK_DEPTH exceeded error
    data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    
    // If that still fails, try with both FAST_STACK_CMP and REUSE_STACKID
    if (data.kernel_stack_id < 0) {
        data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    
    // Get user stack with the same optimizations
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
    if (data.user_stack_id < 0) {
        data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    }

    data.drop_reason = drop_reason;
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
"""

protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP}
protocol_num = protocol_map[args.protocol]

b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num))

b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")


# Process events from perf buffer
def print_kfree_drop_event(cpu, data, size):
    event = b["kfree_drops"].event(data)
    protocol_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.protocol, str(event.protocol))
    
    # Stack trace with better filtering
    stack_id = event.kernel_stack_id
    
    if stack_id >= 0:
        stack_trace = []
        stack_syms = []
        try:
            stack_trace = list(b.get_table("stack_traces").walk(stack_id))
            for addr in stack_trace:
                sym = b.ksym(addr, show_offset=True)
                stack_syms.append(sym)
        except KeyError:
            log_output("  Failed to retrieve stack trace (ID: %d)" % stack_id)

        if stack_trace:
            if is_normal_packet_release(stack_syms, event.protocol):
                return
                
            # Now print the actual stack trace
            log_output("Time: %s  PID: %-6d  Comm: %s" % (
                strftime("%Y-%m-%d %H:%M:%S"), event.pid, event.comm.decode('utf-8')))
            log_output("Source IP: %-15s  Destination IP: %-15s  Protocol: %s%s" % (
                inet_ntop(AF_INET, pack("I", event.saddr)),
                inet_ntop(AF_INET, pack("I", event.daddr)),
                protocol_str,
                "  VLAN: %d" % event.vlan_id,
                "  IP ID: %d" % event.ip_id
            ))
            
            # Protocol specific info
            if event.protocol == socket.IPPROTO_ICMP:
                log_output("ICMP Type: %-2d  Code: %-2d" % (event.icmp_type, event.icmp_code))
            elif event.protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
                log_output("Source Port: %-5d  Destination Port: %-5d" % (event.sport, event.dport))
            
            log_output("Device: %s" % event.ifname.decode('utf-8'))
    
            log_output("Stack Trace:")
            for sym in stack_syms:
                log_output("  %s" % sym)

            # After displaying the kernel stack trace, add user stack trace display
            log_output("User Stack Trace:")
            user_stack_id = event.user_stack_id
            
            if user_stack_id >= 0:
                user_stack = []
                try:
                    user_stack = list(b.get_table("stack_traces").walk(user_stack_id))
                except KeyError:
                    log_output("  Failed to retrieve user stack trace (ID: %d)" % user_stack_id)
                
                if user_stack:
                    for addr in user_stack:
                        # For user-space, we use sym() instead of ksym()
                        symbol = b.sym(addr, event.pid, show_offset=True)
                        if symbol:
                            log_output("  %s" % symbol)
                        else:
                            log_output("  0x%x" % addr)
                else:
                    log_output("  No user stack frames found")
            else:
                error_code = abs(user_stack_id)
                error_msg = "Unknown error"
                if error_code == 1:
                    error_msg = "EFAULT: Bad address"
                elif error_code == 2:
                    error_msg = "ENOENT: No such entry"
                elif error_code == 12:
                    error_msg = "ENOMEM: Out of memory"
                elif error_code == 22:
                    error_msg = "EINVAL: Invalid argument"
                elif error_code == 14:
                    error_msg = "BPF_MAX_STACK_DEPTH exceeded"
                elif error_code == 16:
                    error_msg = "Resource temporarily unavailable"
                elif error_code == 524:
                    error_msg = "Uprobe not found"
                
                log_output("  Failed to capture user stack trace (Error: %s, code: %d)" % 
                    (error_msg, error_code))
    else:
        error_code = abs(event.kernel_stack_id)
        error_msg = "Unknown error"
        if error_code == 1:
            error_msg = "EFAULT: Bad address"
        elif error_code == 2:
            error_msg = "ENOENT: No such entry"
        elif error_code == 12:
            error_msg = "ENOMEM: Out of memory"
        elif error_code == 22:
            error_msg = "EINVAL: Invalid argument"
        elif error_code == 14:
            error_msg = "BPF_MAX_STACK_DEPTH exceeded"
            return
        elif error_code == 16:
            error_msg = "Resource temporarily unavailable"
        elif error_code == 524:
            error_msg = "Uprobe not found"
        
        log_output("  Failed to capture stack trace (Error: %s, code: %d)" % 
              (error_msg, error_code))


normal_patterns = {
    'icmp_rcv': ['icmp_rcv'],
    'tcp_v4_rcv': ['tcp_v4_rcv'],
    'skb_release_data': ['skb_release_data', '__kfree_skb', 'tcp_recvmsg']
}

def is_normal_packet_release(stack_syms, protocol):
    stack_str = ' '.join([sym.lower() for sym in stack_syms])
    
    if protocol == socket.IPPROTO_ICMP:
        return 'icmp_rcv' in stack_str
    if protocol == socket.IPPROTO_TCP:
        return 'tcp_v4_rcv' in stack_str or ('skb_release_data' in stack_str and 'tcp_recvmsg' in stack_str)
    
    return False

b["kfree_drops"].open_perf_buffer(print_kfree_drop_event)

log_output("Tracing... Hit Ctrl-C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        if log_file:
            log_file.write("\n=== Monitoring ended at {} ===\n".format(strftime('%Y-%m-%d %H:%M:%S')))
            log_file.close()
        exit()

