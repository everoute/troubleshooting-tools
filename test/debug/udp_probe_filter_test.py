#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UDP Probe Filter Test Tool

This tool monitors UDP packets at both transport layer (udp_send_skb.isra.54) and
IP layer (ip_output) probe points, outputting all packets that match the filter criteria.
No correlation is performed - simply filters and outputs all matching events.

Probe points:
- Transport layer: udp_send_skb.isra.54 (has sock but SKB headers not ready)
- IP layer: ip_output (complete SKB headers available)
"""

from bcc import BPF
import argparse
import socket
import struct
import ctypes
import sys
from time import strftime

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <net/flow.h>

// Filter parameters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

// Debug framework - stage and code point definitions
#define STAGE_UDP_SEND_SKB          0
#define STAGE_IP_OUTPUT             1

// Code point definitions
#define CODE_PROBE_ENTRY            1   // Probe function entry
#define CODE_SKB_CHECK              2   // SKB validity check
#define CODE_SOCK_CHECK             3   // Socket validity check
#define CODE_SOCK_FILTER_PASS       4   // Socket filter passed
#define CODE_SOCK_FILTER_FAIL       5   // Socket filter failed
#define CODE_SKB_PARSE_SUCCESS      6   // SKB parsing success
#define CODE_SKB_PARSE_FAIL         7   // SKB parsing failed
#define CODE_IP_FILTER_PASS         8   // IP filter passed
#define CODE_IP_FILTER_FAIL         9   // IP filter failed
#define CODE_UDP_EXTRACT_SUCCESS   10   // UDP header extraction success
#define CODE_UDP_EXTRACT_FAIL      11   // UDP header extraction failed
#define CODE_EVENT_SUBMIT          12   // Event submitted to userspace
#define CODE_SRC_IP_FILTER_FAIL    13   // Source IP filter failed
#define CODE_DST_IP_FILTER_FAIL    14   // Destination IP filter failed
#define CODE_SOCK_IP_READ          15   // Socket IP addresses read

// Debug statistics using BPF histogram
BPF_HISTOGRAM(debug_stage_stats, u32);  // Key: (stage_id << 8) | code_point

// Debug increment function
static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}

// Event structure for output
struct event_t {
    u64 timestamp;
    char probe_name[32];

    // Packet info
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;

    // UDP specific
    __be16 ip_id;
    __be16 udp_len;
    __be16 frag_off;

    // Additional debug info
    u64 skb_ptr;
    u64 sock_ptr;

    // SKB info
    u32 skb_len;
    u32 skb_data_len;
    u16 skb_network_header;
    u16 skb_transport_header;

    // Sock info (if available)
    __be32 sock_saddr;
    __be32 sock_daddr;
    __be16 sock_sport;
    __be16 sock_dport;

    u8 extraction_success;
    char error_msg[64];
};

BPF_PERF_OUTPUT(events);

// Helper to read IP header from SKB
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip) {
    unsigned char *head;
    u16 network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return -1;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return -1;

    if (network_header == (u16)~0U || network_header > 2048)
        return -1;

    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_header) < 0)
        return -1;

    return 0;
}

// Helper to read transport header from SKB
static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size) {
    unsigned char *head;
    u16 transport_header, network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return -1;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0)
        return -1;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return -1;

    // If transport header not set, calculate from IP header
    if (transport_header == 0 || transport_header == (u16)~0U || transport_header == network_header) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
            return -1;
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return -1;
        transport_header = network_header + (ip_ihl * 4);
    }

    if (bpf_probe_read_kernel(hdr, hdr_size, head + transport_header) < 0)
        return -1;

    return 0;
}

// UDP: udp_send_skb.isra.54 - actual signature: udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
int udp_send_skb_handler(struct pt_regs *ctx, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork) {
    debug_inc(STAGE_UDP_SEND_SKB, CODE_PROBE_ENTRY);

    struct event_t event = {};
    __builtin_memcpy(event.probe_name, "udp_send_skb.isra.54", 21);
    event.timestamp = bpf_ktime_get_ns();
    event.skb_ptr = (u64)skb;
    event.protocol = IPPROTO_UDP;

    // Check SKB validity
    if (!skb) {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_SKB_CHECK);
        return 0;
    }

    // Get SKB info
    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_data_len, sizeof(event.skb_data_len), &skb->data_len);
    bpf_probe_read_kernel(&event.skb_network_header, sizeof(event.skb_network_header), &skb->network_header);
    bpf_probe_read_kernel(&event.skb_transport_header, sizeof(event.skb_transport_header), &skb->transport_header);

    // Get socket from SKB
    struct sock *sk = NULL;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk) == 0 && sk) {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_SOCK_CHECK);
        event.sock_ptr = (u64)sk;

        struct inet_sock *inet = (struct inet_sock *)sk;
        bpf_probe_read_kernel(&event.sock_saddr, sizeof(event.sock_saddr), &inet->inet_saddr);
        bpf_probe_read_kernel(&event.sock_daddr, sizeof(event.sock_daddr), &inet->inet_daddr);
        bpf_probe_read_kernel(&event.sock_sport, sizeof(event.sock_sport), &inet->inet_sport);
        bpf_probe_read_kernel(&event.sock_dport, sizeof(event.sock_dport), &inet->inet_dport);

        debug_inc(STAGE_UDP_SEND_SKB, CODE_SOCK_IP_READ);
    }

    // Get correct addresses from flow structure (fl4)
    if (fl4) {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_SOCK_FILTER_PASS);

        // Read from flowi4 structure - the reliable source for UDP
        bpf_probe_read_kernel(&event.src_ip, sizeof(event.src_ip), &fl4->saddr);
        bpf_probe_read_kernel(&event.dst_ip, sizeof(event.dst_ip), &fl4->daddr);
        bpf_probe_read_kernel(&event.src_port, sizeof(event.src_port), &fl4->fl4_sport);
        bpf_probe_read_kernel(&event.dst_port, sizeof(event.dst_port), &fl4->fl4_dport);
        event.extraction_success = 1;

        // Apply IP filtering using reliable flow info
        if (SRC_IP_FILTER != 0 && event.src_ip != SRC_IP_FILTER && event.dst_ip != SRC_IP_FILTER) {
            debug_inc(STAGE_UDP_SEND_SKB, CODE_SRC_IP_FILTER_FAIL);
            return 0;
        }
        if (DST_IP_FILTER != 0 && event.src_ip != DST_IP_FILTER && event.dst_ip != DST_IP_FILTER) {
            debug_inc(STAGE_UDP_SEND_SKB, CODE_DST_IP_FILTER_FAIL);
            return 0;
        }
    }

    // Try to get from SKB headers (UDP header should be ready, IP may not be)
    struct iphdr ip = {};
    struct udphdr udp = {};
    int ip_ret = get_ip_header(skb, &ip);
    int udp_ret = get_transport_header(skb, &udp, sizeof(udp));

    // UDP length can be calculated from SKB length
    u32 skb_len = 0;
    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);
    if (skb_len > 0) {
        // UDP length = SKB length - IP header length (typically 20) - Ethernet header etc
        // For now, try to extract from UDP header directly
        if (udp_ret == 0) {
            debug_inc(STAGE_UDP_SEND_SKB, CODE_SKB_PARSE_SUCCESS);
            event.udp_len = udp.len;
            __builtin_memcpy(event.error_msg, "UDP header available", 21);
        } else {
            // Calculate approximate UDP length from SKB
            u16 net_hdr = 0, trans_hdr = 0;
            bpf_probe_read_kernel(&net_hdr, sizeof(net_hdr), &skb->network_header);
            bpf_probe_read_kernel(&trans_hdr, sizeof(trans_hdr), &skb->transport_header);
            if (trans_hdr > net_hdr && trans_hdr != (u16)~0U) {
                u16 udp_total_len = skb_len - trans_hdr;
                event.udp_len = htons(udp_total_len);
                __builtin_memcpy(event.error_msg, "UDP len calculated", 19);
            } else {
                __builtin_memcpy(event.error_msg, "UDP len unavailable", 20);
            }
        }
    }

    // IP header might not be ready yet at UDP layer
    if (ip_ret == 0) {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_SKB_PARSE_SUCCESS);
        event.ip_id = ip.id;
        u16 frag_off = ntohs(ip.frag_off);
        event.frag_off = frag_off & 0x1FFF;

        // Verify consistency with flow info
        if (event.extraction_success) {
            if (event.src_ip != ip.saddr || event.dst_ip != ip.daddr) {
                __builtin_memcpy(event.error_msg, "IP mismatch: flow vs skb", 26);
            }
            if (udp_ret == 0 && (event.src_port != udp.source || event.dst_port != udp.dest)) {
                __builtin_memcpy(event.error_msg, "Port mismatch: flow vs skb", 28);
            }
        }
    } else {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_SKB_PARSE_FAIL);
        // IP header not ready - this is expected at UDP layer
        event.ip_id = 0;
        if (event.error_msg[0] == 0) {
            __builtin_memcpy(event.error_msg, "IP header not ready", 20);
        }
    }

    // Only output if we got some packet info
    if (event.extraction_success) {
        debug_inc(STAGE_UDP_SEND_SKB, CODE_EVENT_SUBMIT);
        events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}

// IP: ip_output - common for UDP
int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    debug_inc(STAGE_IP_OUTPUT, CODE_PROBE_ENTRY);

    struct event_t event = {};
    __builtin_memcpy(event.probe_name, "ip_output", 10);
    event.timestamp = bpf_ktime_get_ns();
    event.skb_ptr = (u64)skb;
    event.sock_ptr = (u64)sk;

    // Check SKB validity
    if (!skb) {
        debug_inc(STAGE_IP_OUTPUT, CODE_SKB_CHECK);
        return 0;
    }

    // Get SKB info
    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_data_len, sizeof(event.skb_data_len), &skb->data_len);
    bpf_probe_read_kernel(&event.skb_network_header, sizeof(event.skb_network_header), &skb->network_header);
    bpf_probe_read_kernel(&event.skb_transport_header, sizeof(event.skb_transport_header), &skb->transport_header);

    // Get IP header
    struct iphdr ip = {};
    if (get_ip_header(skb, &ip) == 0) {
        debug_inc(STAGE_IP_OUTPUT, CODE_SKB_PARSE_SUCCESS);

        // Apply filter
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
            debug_inc(STAGE_IP_OUTPUT, CODE_IP_FILTER_FAIL);
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
            debug_inc(STAGE_IP_OUTPUT, CODE_IP_FILTER_FAIL);
            return 0;
        }

        debug_inc(STAGE_IP_OUTPUT, CODE_IP_FILTER_PASS);

        event.src_ip = ip.saddr;
        event.dst_ip = ip.daddr;
        event.protocol = ip.protocol;

        // Get sock info if available
        if (sk) {
            debug_inc(STAGE_IP_OUTPUT, CODE_SOCK_CHECK);
            struct inet_sock *inet = (struct inet_sock *)sk;
            bpf_probe_read_kernel(&event.sock_saddr, sizeof(event.sock_saddr), &inet->inet_saddr);
            bpf_probe_read_kernel(&event.sock_daddr, sizeof(event.sock_daddr), &inet->inet_daddr);
            bpf_probe_read_kernel(&event.sock_sport, sizeof(event.sock_sport), &inet->inet_sport);
            bpf_probe_read_kernel(&event.sock_dport, sizeof(event.sock_dport), &inet->inet_dport);
        }

        // Only handle UDP packets
        if (ip.protocol == IPPROTO_UDP) {
            event.ip_id = ip.id;
            u16 frag_off = ntohs(ip.frag_off);
            event.frag_off = frag_off & 0x1FFF;

            struct udphdr udp = {};
            if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
                debug_inc(STAGE_IP_OUTPUT, CODE_UDP_EXTRACT_SUCCESS);
                event.src_port = udp.source;
                event.dst_port = udp.dest;
                event.udp_len = udp.len;
                event.extraction_success = 1;
                __builtin_memcpy(event.error_msg, "UDP headers extracted", 22);
            } else {
                debug_inc(STAGE_IP_OUTPUT, CODE_UDP_EXTRACT_FAIL);
                __builtin_memcpy(event.error_msg, "UDP header extract failed", 27);
            }

            // Output UDP packets
            debug_inc(STAGE_IP_OUTPUT, CODE_EVENT_SUBMIT);
            events.perf_submit(ctx, &event, sizeof(event));
        }
    } else {
        debug_inc(STAGE_IP_OUTPUT, CODE_SKB_PARSE_FAIL);
        __builtin_memcpy(event.error_msg, "IP header extract failed", 26);
    }

    return 0;
}
"""

# Event structure in Python
class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("probe_name", ctypes.c_char * 32),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("ip_id", ctypes.c_uint16),
        ("udp_len", ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16),
        ("skb_ptr", ctypes.c_uint64),
        ("sock_ptr", ctypes.c_uint64),
        ("skb_len", ctypes.c_uint32),
        ("skb_data_len", ctypes.c_uint32),
        ("skb_network_header", ctypes.c_uint16),
        ("skb_transport_header", ctypes.c_uint16),
        ("sock_saddr", ctypes.c_uint32),
        ("sock_daddr", ctypes.c_uint32),
        ("sock_sport", ctypes.c_uint16),
        ("sock_dport", ctypes.c_uint16),
        ("extraction_success", ctypes.c_uint8),
        ("error_msg", ctypes.c_char * 64)
    ]

def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    packed_ip = socket.inet_aton(ip_str)
    host_int = struct.unpack("!I", packed_ip)[0]
    return socket.htonl(host_int)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def print_debug_statistics(b):
    """Print debugging statistics to identify probe issues"""
    # Define stage names
    stage_names = {
        0: "UDP_SEND_SKB",
        1: "IP_OUTPUT"
    }

    # Define code point names
    code_names = {
        1: "PROBE_ENTRY",
        2: "SKB_CHECK",
        3: "SOCK_CHECK",
        4: "SOCK_FILTER_PASS",
        5: "SOCK_FILTER_FAIL",
        6: "SKB_PARSE_SUCCESS",
        7: "SKB_PARSE_FAIL",
        8: "IP_FILTER_PASS",
        9: "IP_FILTER_FAIL",
        10: "UDP_EXTRACT_SUCCESS",
        11: "UDP_EXTRACT_FAIL",
        12: "EVENT_SUBMIT",
        13: "SRC_IP_FILTER_FAIL",
        14: "DST_IP_FILTER_FAIL",
        15: "SOCK_IP_READ"
    }

    print("\n" + "="*80)
    print("🔍 DEBUG STATISTICS")
    print("="*80)

    stage_stats = b["debug_stage_stats"]
    found_stats = False
    for k, v in sorted(stage_stats.items(), key=lambda x: x[0].value):
        if v.value > 0:
            found_stats = True
            stage_id = k.value >> 8
            code_point = k.value & 0xFF
            stage_name = stage_names.get(stage_id, f"UNKNOWN_{stage_id}")
            code_name = code_names.get(code_point, f"CODE_{code_point}")
            print(f"  {stage_name}.{code_name}: {v.value}")

    if not found_stats:
        print("  No debug statistics recorded - possible probe attachment issues")

    print("="*80)

def print_event(cpu, data, size):
    """Print all UDP events from both probe points"""
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    ts = event.timestamp / 1e9
    probe = event.probe_name.decode('utf-8', 'replace').strip()

    try:
        error_msg = event.error_msg.decode('utf-8', 'replace') if event.error_msg[0] else ""
    except (IndexError, UnicodeDecodeError):
        error_msg = ""

    print(f"\n{'='*80}")
    print(f"📡 UDP PACKET EVENT - {strftime('%H:%M:%S.%f')[:-3]} - {probe}")
    print(f"   Flow: {format_ip(event.src_ip)}:{socket.ntohs(event.src_port)} -> "
          f"{format_ip(event.dst_ip)}:{socket.ntohs(event.dst_port)}")

    if probe == "udp_send_skb.isra.54":
        print(f"   🔧 Probe: Transport Layer (udp_send_skb.isra.54)")
        print(f"   📊 Data Source: Flow + Socket structures")
        # Show UDP length if available from UDP header
        if event.udp_len > 0:
            udp_len_str = f"UDP Len: {socket.ntohs(event.udp_len)}"
        else:
            udp_len_str = "UDP Len: N/A"
        # Show IP ID if available (usually not at UDP layer)
        if event.ip_id > 0:
            ip_id_str = f"IP ID: {socket.ntohs(event.ip_id)}"
        else:
            ip_id_str = "IP ID: N/A"
        print(f"   {ip_id_str} | {udp_len_str} | Frag: {socket.ntohs(event.frag_off)}")
        if event.sock_ptr:
            print(f"   Sock IPs: {format_ip(event.sock_saddr)} -> {format_ip(event.sock_daddr)}")
            print(f"   Sock Ports: {socket.ntohs(event.sock_sport)} -> {socket.ntohs(event.sock_dport)}")
    elif probe == "ip_output":
        print(f"   🔧 Probe: IP Layer (ip_output)")
        print(f"   📊 Data Source: SKB headers (IP + UDP)")
        print(f"   IP ID: {socket.ntohs(event.ip_id)} | UDP Len: {socket.ntohs(event.udp_len)} | Frag: {socket.ntohs(event.frag_off)}")
        if event.sock_ptr:
            print(f"   Sock IPs: {format_ip(event.sock_saddr)} -> {format_ip(event.sock_daddr)}")
            print(f"   Sock Ports: {socket.ntohs(event.sock_sport)} -> {socket.ntohs(event.sock_dport)}")

    print(f"   Timestamp: {ts:.9f}")
    print(f"   SKB: 0x{event.skb_ptr:016x} | Sock: 0x{event.sock_ptr:016x}")
    print(f"   SKB State: len={event.skb_len} data_len={event.skb_data_len} "
          f"net_hdr={event.skb_network_header} trans_hdr={event.skb_transport_header}")

    if error_msg:
        print(f"   📝 Status: {error_msg}")
    else:
        print(f"   ✅ Extraction: {'Success' if event.extraction_success else 'Failed'}")

    print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Filter and output UDP packets at transport and IP layers"
    )
    parser.add_argument("--src-ip", help="Source IP filter")
    parser.add_argument("--dst-ip", help="Destination IP filter")
    parser.add_argument("--interface", help="Interface name (for reference)")

    args = parser.parse_args()

    # Convert IPs to hex
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0

    print("🔍 === UDP Probe Filter Test ===")
    print(f"Source IP filter: {args.src_ip or 'None'}")
    print(f"Destination IP filter: {args.dst_ip or 'None'}")
    print(f"Interface: {args.interface or 'All'}")
    print("")
    print("🎯 Monitoring UDP probe points:")
    print("  📤 Transport: udp_send_skb.isra.54 (has sock, SKB headers not ready)")
    print("  📦 IP Layer: ip_output (complete SKB headers available)")
    print("")
    print("📊 Will output all UDP packets matching filter criteria...")
    print("")

    # Load BPF program
    b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex), debug=0, cflags=["-w"])

    # Manually attach probes
    # UDP transmit
    try:
        b.attach_kprobe(event="udp_send_skb.isra.54", fn_name="udp_send_skb_handler")
        print("✓ Attached udp_send_skb.isra.54")
    except:
        print("✗ Failed to attach udp_send_skb.isra.54 (may not exist on this kernel)")

    # IP output
    try:
        b.attach_kprobe(event="ip_output", fn_name="kprobe__ip_output")
        print("✓ Attached ip_output")
    except:
        print("✗ Failed to attach ip_output")

    print("")

    # Open perf buffer
    b["events"].open_perf_buffer(print_event)

    print("Tracing... Hit Ctrl-C to end")
    print("-" * 60)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")

    # Print debug statistics to identify probe issues
    print_debug_statistics(b)

    print("\n=== Summary ===")
    print("UDP probe filter test completed.")
    print("All UDP packets matching the filter criteria were displayed.")

if __name__ == "__main__":
    main()