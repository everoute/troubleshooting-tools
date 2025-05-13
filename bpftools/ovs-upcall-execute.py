#!/usr/bin/python2
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct
import argparse
import time
import socket
import struct
import sys

# Parse command line arguments
parser = argparse.ArgumentParser(description='Trace OVS upcall processing time for ICMP packets')
parser.add_argument('--src-ip', help='Source IP address filter')
parser.add_argument('--dst-ip', help='Destination IP address filter')
args = parser.parse_args()

# Convert IP address to hex format for BPF program
def ip_to_hex(ip_str):
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

src_ip_filter = ip_to_hex(args.src_ip)
dst_ip_filter = ip_to_hex(args.dst_ip)

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

// Define probe IDs
#define PROBE_OVS_DP_UPCALL 1
#define PROBE_OVS_FLOW_KEY_EXTRACT 2

// Ethernet header constants
#define ETH_HLEN 14          // Ethernet header length
#define ETH_ALEN 6           // Length of Ethernet MAC address
#define VLAN_HLEN 4          // VLAN header length
#define ETH_P_IP 0x0800      // IPv4 protocol
#define ETH_P_IPV6 0x86DD    // IPv6 protocol
#define ETH_P_8021Q 0x8100   // 802.1Q VLAN protocol
#define ETH_P_8021AD 0x88A8  // 802.1ad VLAN protocol

// Packet key structure - identifies a unique packet flow
struct packet_key_t {
    u32 src_ip;
    u32 dst_ip;
    u8 ip_proto;
    u8 icmp_type;
    u16 icmp_id;
    u16 icmp_seq;
};

// Timestamps structure - stores timestamps at different probe points
struct flow_ts_t {
    u64 ts_upcall;       // Timestamp when ovs_dp_upcall is called
    u64 ts_key_extract;  // Timestamp when ovs_flow_key_extract_userspace is called
    u64 upcall_stack_id; // Stack ID from ovs_dp_upcall
};

// Map to store timestamps for each flow
BPF_HASH(flow_timestamps, struct packet_key_t, struct flow_ts_t, 1024);

// Stack trace storage
BPF_STACK_TRACE(stack_traces, 10240);

// Define data structure for perf output
struct data_t {
    struct packet_key_t key;
    u64 ts_upcall;
    u64 ts_key_extract;
    u64 delta_ns;
    u64 upcall_stack_id;
    u64 key_extract_stack_id;
};

// Define perf output
BPF_PERF_OUTPUT(events_map);

// Function to manually parse skb data and extract headers similar to key_extract
static bool parse_packet_key_userspace(struct sk_buff *skb, struct packet_key_t *key) {
    if (skb == NULL) {
        return false;
    }

    unsigned char *skb_head = skb->head;
    if (!skb_head) {
        return false;
    }
    
    // skb_reset_mac_header
    unsigned int data_offset = skb->data - skb_head;
    
    // Calculate MAC header position - at the start of the packet data
    unsigned int mac_offset = data_offset;
    
    // Debug info
    
    // Read Ethernet header
    struct ethhdr eth;
    bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset);
    
    // Calculate network header position - start after Ethernet header
    unsigned int net_offset = mac_offset + ETH_HLEN;
    
    // Check for VLAN tags
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN if present
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        // Skip VLAN header (4 bytes)
        net_offset += VLAN_HLEN;
        
        // Read the real ethertype from after the VLAN header
        bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2);
    }
    
    // If not IPv4, we don't support it
    if (h_proto != htons(ETH_P_IP)) {
        return false;
    }
    
    // Read IPv4 header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb_head + net_offset);
    
    // Apply IP address filters
    if (SRC_IP_FILTER != 0 && iph.saddr != SRC_IP_FILTER) {
        return false;
    }
    
    if (DST_IP_FILTER != 0 && iph.daddr != DST_IP_FILTER) {
        return false;
    }
    
    // Store IP info in the key
    key->src_ip = iph.saddr;
    key->dst_ip = iph.daddr;
    key->ip_proto = iph.protocol;
    
    // Calculate IP header length and transport header position
    unsigned int ihl = (iph.ihl & 0x0F);
    if (ihl < 5) {
        return false;
    }
    
    unsigned int trans_offset = net_offset + (ihl * 4);
    
    // Check if it's ICMP
    if (iph.protocol == IPPROTO_ICMP) {
        // Read ICMP header
        bpf_trace_printk("EXTRACT_USER: head=%%p, data=%%p, offset=%%u\\n", skb_head, skb->data, data_offset);
        bpf_trace_printk("EXTRACT_USER: EtherType=0x%%x, net_offset=%%u\\n", ntohs(h_proto), net_offset);
        bpf_trace_printk("EXTRACT_USER: network_header=%%u, transport_header=%%u\\n", skb->network_header, skb->transport_header);
        bpf_trace_printk("EXTRACT_USER: transport offset=%%u\\n", trans_offset);
        // Debug IP header
        bpf_trace_printk("EXTRACT_USER: IP header - ihl=%%u, proto=%%u\\n", iph.ihl & 0x0F, iph.protocol);
        bpf_trace_printk("EXTRACT_USER: IP header - saddr=%%x, daddr=%%x\\n", iph.saddr, iph.daddr);
    
        struct icmphdr icmph;
        bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset);
        
        key->icmp_type = icmph.type;
        
        // For echo request/reply, get ID and sequence
        if (icmph.type == ICMP_ECHO || icmph.type == ICMP_ECHOREPLY) {
            // Print raw values first (before any byte order conversion)
            __u32 word0, word1;   // 各读 4 byte
            bpf_probe_read_kernel(&word0, 4, skb_head + trans_offset);          // type~csum
            bpf_probe_read_kernel(&word1, 4, skb_head + trans_offset + 4);      // id + seq
            bpf_trace_printk("EXTRACT_USER: ICMP hdr 0x%%x 0x%%x\\n", word0, word1);
            
            key->icmp_id = icmph.un.echo.id;
            key->icmp_seq = icmph.un.echo.sequence;
            
            // Further debug logging with network byte order values
            // Get host byte order for display
            u16 id_host = __builtin_bswap16(key->icmp_id);
            u16 seq_host = __builtin_bswap16(key->icmp_seq);
            
            bpf_trace_printk("EXTRACT_USER: ICMP type=%%d, id=%%d, seq=%%d\\n", 
                           icmph.type, key->icmp_id, key->icmp_seq);
            bpf_trace_printk("EXTRACT_USER: ICMP (host order) id=%%u, seq=%%u\\n", id_host, seq_host);
        } else {
            key->icmp_id = 0;
            key->icmp_seq = 0;
            //bpf_trace_printk("EXTRACT_USER: non-echo ICMP type=%%d\\n", icmph.type);
        }
        
        return true;
    }
    
    return false;
}

// Function to parse IPv4 header and ICMP header and apply filters for normal skb
static bool parse_packet_key(struct sk_buff *skb, struct packet_key_t *key, u8 probe_id) {
    if (skb == NULL) {
        return false;
    }

    unsigned char *skb_head = skb->head;
    
    // Verify if skb and skb->head are valid pointers
    if (!skb || !skb_head) {
        return false;
    }
    
    // Calculate data offset and log headers
    unsigned int data_offset = skb->data - skb->head;
    
    // Calculate MAC header position - at the start of the packet data
    unsigned int mac_offset = data_offset;
    
    // Read Ethernet header
    struct ethhdr eth;
    bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset);
    
    // Calculate network header position - start after Ethernet header
    unsigned int net_offset = mac_offset + ETH_HLEN;
    
    // Check for VLAN tags
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN if present
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        // Skip VLAN header (4 bytes)
        net_offset += VLAN_HLEN;
        
        // Read the real ethertype from after the VLAN header
        bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2);
    }
    
    // If not IPv4, we don't support it
    if (h_proto != htons(ETH_P_IP)) {
        return false;
    }
    
    // Read IP header using our calculated net_offset
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb_head + net_offset);
    
    // Apply IP address filters
    
    if (SRC_IP_FILTER != 0 && iph.saddr != SRC_IP_FILTER) {
        return false;
    }
    
    if (DST_IP_FILTER != 0 && iph.daddr != DST_IP_FILTER) {
        return false;
    }
    
    // Store IP info
    key->src_ip = iph.saddr;
    key->dst_ip = iph.daddr;
    key->ip_proto = iph.protocol;
    
    // Check if it's ICMP
    if (iph.protocol == IPPROTO_ICMP) {
        bpf_trace_printk("EXTRACT: skb_head=%%p, skb_data=%%p, data_offset=%%u\\n", skb->head, skb->data, data_offset);
        bpf_trace_printk("EXTRACT: network_header=%%u, transport_header=%%u\\n", skb->network_header, skb->transport_header);
        bpf_trace_printk("EXTRACT: EtherType=0x%%x, net_offset=%%u\\n", ntohs(h_proto), net_offset);
        bpf_trace_printk("EXTRACT: Not IPv4 packet. EtherType: 0x%%x\\n", ntohs(h_proto));
        bpf_trace_printk("EXTRACT: IP header - ihl=%%u, proto=%%u\\n", iph.ihl & 0x0F, iph.protocol);
        bpf_trace_printk("EXTRACT: IP header - saddr=%%x, daddr=%%x\\n", iph.saddr, iph.daddr);

        // Calculate transport header position from IP header length
        unsigned int ihl = (iph.ihl & 0x0F);
        if (ihl < 5) {
            return false;
        }
        
        unsigned int trans_offset = net_offset + (ihl * 4);
        bpf_trace_printk("EXTRACT: transport offset=%%u\\n", trans_offset);
        
        // Read ICMP header from calculated transport offset
        struct icmphdr icmph;
        bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset);
        
        key->icmp_type = icmph.type;
        
        // For ICMP echo request/reply, get ID and sequence
        if (icmph.type == ICMP_ECHO || icmph.type == ICMP_ECHOREPLY) {
            // Print raw values first (before any byte order conversion)
            __u32 word0, word1;   // 各读 4 byte
            bpf_probe_read_kernel(&word0, 4, skb_head + trans_offset);          // type~csum
            bpf_probe_read_kernel(&word1, 4, skb_head + trans_offset + 4);      // id + seq
            bpf_trace_printk("EXTRACT: ICMP hdr 0x%%x 0x%%x\\n", word0, word1);
            
            key->icmp_id = icmph.un.echo.id;
            key->icmp_seq = icmph.un.echo.sequence;
            
            // Further debug logging with network byte order values
            // Get host byte order for display
            u16 id_host = __builtin_bswap16(key->icmp_id);
            u16 seq_host = __builtin_bswap16(key->icmp_seq);
            
            bpf_trace_printk("EXTRACT: probe_id=%%d\\n", probe_id);
            bpf_trace_printk("EXTRACT: ICMP type=%%d, id=%%d, seq=%%d\\n", icmph.type, key->icmp_id, key->icmp_seq);
            bpf_trace_printk("EXTRACT: ICMP (host order) id=%%u, seq=%%u\\n", id_host, seq_host);
        } else {
            key->icmp_id = 0;
            key->icmp_seq = 0;
            //bpf_trace_printk("EXTRACT: non-echo ICMP type=%%d\\n", icmph.type);
        }
        
        return true;
    }
    
    return false;
}

// Record timestamp when ovs_dp_upcall is called (kprobe)
int trace_ovs_dp_upcall(struct pt_regs *ctx) {
    // Get skb pointer (second parameter of ovs_dp_upcall)
    // int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb, ...)
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (!skb)
        return 0;

    
    struct packet_key_t key = {};
    // Apply filter to determine if we should record this packet
    if (!parse_packet_key(skb, &key, PROBE_OVS_DP_UPCALL)) {
        return 0;
    }
    
    // Get current timestamp
    u64 ts = bpf_ktime_get_ns();
    
    // Capture stack trace - using BPF_F_FAST_STACK_CMP for better performance
    u64 stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    
    // Get or create flow timestamp entry
    struct flow_ts_t *flow_ts, zero = {};
    flow_ts = flow_timestamps.lookup_or_try_init(&key, &zero);
    if (flow_ts) {
        // Store timestamp for this probe point
        flow_ts->ts_upcall = ts;
        flow_ts->upcall_stack_id = stack_id;  // Store stack ID
        
        // Limit format specifiers to 3 (BPF limitation)
        u16 seq_host = __builtin_bswap16(key.icmp_seq); // Display in host byte order
        u16 id_host = __builtin_bswap16(key.icmp_id);   // Display in host byte order
    }
    
    return 0;
}

// Extract packet info and calculate time difference in ovs_flow_key_extract_userspace
int trace_ovs_flow_key_extract_userspace(struct pt_regs *ctx) {
    // Get skb (3rd parameter of ovs_flow_key_extract_userspace)
    // int ovs_flow_key_extract_userspace(struct net *net, const struct nlattr *attr, struct sk_buff *skb, ...)
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    if (!skb) {
        return 0;
    }
    
    
    struct packet_key_t key = {};
    // Use our specialized function to parse packet in userspace context
    if (!parse_packet_key_userspace(skb, &key)) {
        return 0;
    }
    
    // Get current timestamp
    u64 ts = bpf_ktime_get_ns();
    
    // Capture stack trace with better performance flag
    u64 stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    
    // Look up existing flow timestamps
    struct flow_ts_t *flow_ts = flow_timestamps.lookup(&key);
    if (!flow_ts) {
        bpf_trace_printk("EXECUTE: no timestamps for key=0x%%x:0x%%x\\n", key.src_ip, key.dst_ip);
        return 0;  // No timestamp at upcall stage
    }

    if (flow_ts->ts_upcall == 0) {
        bpf_trace_printk("EXECUTE: upcall ts is 0 key=0x%%x:0x%%x\\n", key.src_ip, key.dst_ip);
        flow_timestamps.delete(&key);
        return 0;  // ts upcall is 0 
    }
    
    // Display in host byte order for consistency with userspace
    u16 seq_host = __builtin_bswap16(key.icmp_seq);
    u16 id_host = __builtin_bswap16(key.icmp_id);
    
    // Store timestamp for key_extract stage
    flow_ts->ts_key_extract = ts;
    
    // Calculate delay
    u64 delta = ts - flow_ts->ts_upcall;
    
    // Prepare event data
    struct data_t event = {};
    event.key = key;
    event.ts_upcall = flow_ts->ts_upcall;
    event.ts_key_extract = ts;
    event.delta_ns = delta;
    event.upcall_stack_id = flow_ts->upcall_stack_id;  // Get stack ID from stored data
    event.key_extract_stack_id = stack_id;
    
    // Output event
    events_map.perf_submit(ctx, &event, sizeof(event));
    
    // Delete the entry once processed
    flow_timestamps.delete(&key);
    
    return 0;
}
"""

b = BPF(text=bpf_text % (src_ip_filter, dst_ip_filter))

# Attach kprobes
b.attach_kprobe(event="ovs_dp_upcall", fn_name="trace_ovs_dp_upcall")
b.attach_kprobe(event="ovs_flow_key_extract_userspace", fn_name="trace_ovs_flow_key_extract_userspace")

# Define packet key structure
class PacketKey(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("ip_proto", ct.c_uint8),
        ("icmp_type", ct.c_uint8),
        ("icmp_id", ct.c_uint16),
        ("icmp_seq", ct.c_uint16)
    ]

# Define event structure
class Data(ct.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("ts_upcall", ct.c_uint64),
        ("ts_key_extract", ct.c_uint64),
        ("delta_ns", ct.c_uint64),
        ("upcall_stack_id", ct.c_uint64),
        ("key_extract_stack_id", ct.c_uint64)
    ]

def format_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(addr)))

# Process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    key = event.key
    
    src_ip = format_ip(key.src_ip)
    dst_ip = format_ip(key.dst_ip)
    
    if key.icmp_type == 0:
        icmp_type_str = "Echo Reply"
    elif key.icmp_type == 8:
        icmp_type_str = "Echo Request"
    else:
        icmp_type_str = str(key.icmp_type)
    
    print("Time: %s" % time.strftime('%H:%M:%S'))
    print("  Src IP: %s, Dst IP: %s" % (src_ip, dst_ip))
    print("  IP Proto: %d, ICMP Type: %s" % (key.ip_proto, icmp_type_str))
    print("  ICMP ID: %d, ICMP Seq: %d" % (socket.ntohs(key.icmp_id), socket.ntohs(key.icmp_seq)))
    print("  Timestamps (ns): upcall=%d, key_extract=%d" % (event.ts_upcall, event.ts_key_extract))
    print("  OVS Upcall Processing Time: %.3f ms" % (event.delta_ns / 1000000.0))
    
    # Print stack traces if available
    if event.upcall_stack_id > 0:
        print("\n  ovs_dp_upcall kernel stack:")
        try:
            for addr in b.get_table("stack_traces").walk(event.upcall_stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("    %s" % sym)
        except KeyError:
            print("    <Stack ID %d not found in table>" % event.upcall_stack_id)
        except Exception as e:
            print("    <Error walking/resolving stack ID %d: %s>" % (event.upcall_stack_id, e))
    elif event.upcall_stack_id < 0:
        print("\n  ovs_dp_upcall kernel stack: <Failed to capture: error %d>" % event.upcall_stack_id)
    else:
        print("\n  ovs_dp_upcall kernel stack: <Stack ID is 0>")
            
    if event.key_extract_stack_id > 0:
        print("\n  ovs_flow_key_extract_userspace kernel stack:")
        try:
            for addr in b.get_table("stack_traces").walk(event.key_extract_stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("    %s" % sym)
        except KeyError:
            print("    <Stack ID %d not found in table>" % event.key_extract_stack_id)
        except Exception as e:
            print("    <Error walking/resolving stack ID %d: %s>" % (event.key_extract_stack_id, e))
    elif event.key_extract_stack_id < 0:
        print("\n  ovs_flow_key_extract_userspace kernel stack: <Failed to capture: error %d>" % event.key_extract_stack_id)
    else:
        print("\n  ovs_flow_key_extract_userspace kernel stack: <Stack ID is 0>")
            
    print("")

# Set up event callback
b["events_map"].open_perf_buffer(print_event)

print("Tracing OVS upcall processing... Hit Ctrl-C to end.")
print("Filters: SRC_IP=%s, DST_IP=%s" % (args.src_ip, args.dst_ip))

print("To see debug output, run in another terminal:")
print("  cat /sys/kernel/debug/tracing/trace_pipe | grep EXTRACT")

# Poll events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break