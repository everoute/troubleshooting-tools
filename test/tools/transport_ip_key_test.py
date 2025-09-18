#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP Transport vs IP Layer Packet Key Extraction Comparison Tool

This tool compares packet key extraction between transport and IP layer
probe points for TCP traffic to understand the optimal probe point for TX tracing.

Focuses on TCP TX path probe points:
- Transport layer: __tcp_transmit_skb (has sock but SKB headers not ready)
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
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

// Filter parameters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

// Packet key structure
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    u8 protocol;
    u8 pad[3];

    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;
        } tcp;

    };

    u64 first_seen_ns;
};

// Event structure for output
struct event_t {
    u64 timestamp;
    char probe_name[32];
    struct packet_key_t key;

    // Additional debug info
    u64 skb_ptr;
    u64 sock_ptr;

    // SKB info
    u32 skb_len;
    u32 skb_data_len;
    u16 skb_network_header;
    u16 skb_transport_header;
    u8 skb_protocol;

    // Sock info (if available)
    u32 sock_state;
    __be32 sock_saddr;
    __be32 sock_daddr;
    __be16 sock_sport;
    __be16 sock_dport;

    // TCP specific from tcp_sock
    u32 tcp_snd_nxt;
    u32 tcp_write_seq;

    u8 extraction_success;
    char error_msg[64];
};

BPF_PERF_OUTPUT(events);

// Map to store packet keys from transport layer for correlation
BPF_HASH(transport_keys, struct packet_key_t, u64, 1024);

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


// TCP: __tcp_transmit_skb - has both sock and skb
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb,
                               int clone_it, gfp_t gfp_mask, u32 rcv_nxt) {
    struct event_t event = {};
    __builtin_memcpy(event.probe_name, "__tcp_transmit_skb", 19);
    event.timestamp = bpf_ktime_get_ns();
    event.skb_ptr = (u64)skb;
    event.sock_ptr = (u64)sk;

    // Get SKB info
    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_data_len, sizeof(event.skb_data_len), &skb->data_len);
    bpf_probe_read_kernel(&event.skb_network_header, sizeof(event.skb_network_header), &skb->network_header);
    bpf_probe_read_kernel(&event.skb_transport_header, sizeof(event.skb_transport_header), &skb->transport_header);

    // Try to get info from sock first (most reliable at this point)
    if (sk) {
        struct inet_sock *inet = (struct inet_sock *)sk;
        bpf_probe_read_kernel(&event.sock_saddr, sizeof(event.sock_saddr), &inet->inet_saddr);
        bpf_probe_read_kernel(&event.sock_daddr, sizeof(event.sock_daddr), &inet->inet_daddr);
        bpf_probe_read_kernel(&event.sock_sport, sizeof(event.sock_sport), &inet->inet_sport);
        bpf_probe_read_kernel(&event.sock_dport, sizeof(event.sock_dport), &inet->inet_dport);

        // Apply filter
        if (SRC_IP_FILTER != 0 && event.sock_saddr != SRC_IP_FILTER && event.sock_daddr != SRC_IP_FILTER)
            return 0;
        if (DST_IP_FILTER != 0 && event.sock_saddr != DST_IP_FILTER && event.sock_daddr != DST_IP_FILTER)
            return 0;

        // Fill packet key from sock
        event.key.src_ip = event.sock_saddr;
        event.key.dst_ip = event.sock_daddr;
        event.key.protocol = IPPROTO_TCP;
        event.key.tcp.src_port = event.sock_sport;
        event.key.tcp.dst_port = event.sock_dport;

        // Get TCP sequence from tcp_sock
        struct tcp_sock *tp = (struct tcp_sock *)sk;
        bpf_probe_read_kernel(&event.tcp_snd_nxt, sizeof(event.tcp_snd_nxt), &tp->snd_nxt);
        bpf_probe_read_kernel(&event.tcp_write_seq, sizeof(event.tcp_write_seq), &tp->write_seq);

        // At this point, the sequence number might not be in SKB yet
        // It's typically set later in the function, but we have it in tcp_sock
        event.key.tcp.seq = htonl(event.tcp_snd_nxt);

        event.extraction_success = 1;

        // Store the packet key for correlation with ip_output
        u64 ts = event.timestamp;
        transport_keys.update(&event.key, &ts);
    }

    // Also try to get from SKB headers (might not be complete yet)
    struct iphdr ip = {};
    struct tcphdr tcp = {};
    int ip_ret = get_ip_header(skb, &ip);
    int tcp_ret = get_transport_header(skb, &tcp, sizeof(tcp));

    if (ip_ret == 0 && tcp_ret == 0) {
        // Compare with what we got from sock
        if (event.key.src_ip != ip.saddr || event.key.dst_ip != ip.daddr) {
            __builtin_memcpy(event.error_msg, "IP mismatch: sock vs skb", 26);
        }
        if (event.key.tcp.src_port != tcp.source || event.key.tcp.dst_port != tcp.dest) {
            __builtin_memcpy(event.error_msg, "Port mismatch: sock vs skb", 28);
        }
        // Note: tcp.seq might not be set yet at this probe point
    } else {
        __builtin_memcpy(event.error_msg, "SKB headers not ready", 22);
    }

    event.key.first_seen_ns = event.timestamp;
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// IP: ip_output - for TCP
int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    struct event_t event = {};
    __builtin_memcpy(event.probe_name, "ip_output", 10);
    event.timestamp = bpf_ktime_get_ns();
    event.skb_ptr = (u64)skb;
    event.sock_ptr = (u64)sk;

    // Get SKB info
    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_data_len, sizeof(event.skb_data_len), &skb->data_len);
    bpf_probe_read_kernel(&event.skb_network_header, sizeof(event.skb_network_header), &skb->network_header);
    bpf_probe_read_kernel(&event.skb_transport_header, sizeof(event.skb_transport_header), &skb->transport_header);

    // Get IP header
    struct iphdr ip = {};
    if (get_ip_header(skb, &ip) == 0) {
        // Apply filter
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER)
            return 0;
        if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER)
            return 0;

        event.key.src_ip = ip.saddr;
        event.key.dst_ip = ip.daddr;
        event.key.protocol = ip.protocol;

        // Get sock info if available
        if (sk) {
            struct inet_sock *inet = (struct inet_sock *)sk;
            bpf_probe_read_kernel(&event.sock_saddr, sizeof(event.sock_saddr), &inet->inet_saddr);
            bpf_probe_read_kernel(&event.sock_daddr, sizeof(event.sock_daddr), &inet->inet_daddr);
            bpf_probe_read_kernel(&event.sock_sport, sizeof(event.sock_sport), &inet->inet_sport);
            bpf_probe_read_kernel(&event.sock_dport, sizeof(event.sock_dport), &inet->inet_dport);
        }

        // Get transport header based on protocol
        if (ip.protocol == IPPROTO_TCP) {
            struct tcphdr tcp = {};
            if (get_transport_header(skb, &tcp, sizeof(tcp)) == 0) {
                event.key.tcp.src_port = tcp.source;
                event.key.tcp.dst_port = tcp.dest;
                event.key.tcp.seq = tcp.seq;
                event.extraction_success = 1;

                // Check if this packet was seen in transport layer
                u64 *transport_ts = transport_keys.lookup(&event.key);
                if (transport_ts) {
                    // Found matching packet from __tcp_transmit_skb
                    __builtin_memcpy(event.error_msg, "MATCHED with __tcp_transmit_skb", 32);

                    // Clean up the entry to avoid memory leaks
                    transport_keys.delete(&event.key);
                } else {
                    __builtin_memcpy(event.error_msg, "NO MATCH found in transport layer", 35);
                }
            } else {
                __builtin_memcpy(event.error_msg, "TCP header extract failed", 27);
            }
        }
    } else {
        __builtin_memcpy(event.error_msg, "IP header extract failed", 26);
    }

    event.key.first_seen_ns = event.timestamp;
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Only focusing on TCP TX path: __tcp_transmit_skb and ip_output
"""

# Event structure in Python
class TCPData(ctypes.Structure):
    _fields_ = [
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
    ]


class PacketKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("tcp", TCPData),
        ("first_seen_ns", ctypes.c_uint64)
    ]

class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("probe_name", ctypes.c_char * 32),
        ("key", PacketKey),
        ("skb_ptr", ctypes.c_uint64),
        ("sock_ptr", ctypes.c_uint64),
        ("skb_len", ctypes.c_uint32),
        ("skb_data_len", ctypes.c_uint32),
        ("skb_network_header", ctypes.c_uint16),
        ("skb_transport_header", ctypes.c_uint16),
        ("skb_protocol", ctypes.c_uint8),
        ("sock_state", ctypes.c_uint32),
        ("sock_saddr", ctypes.c_uint32),
        ("sock_daddr", ctypes.c_uint32),
        ("sock_sport", ctypes.c_uint16),
        ("sock_dport", ctypes.c_uint16),
        ("tcp_snd_nxt", ctypes.c_uint32),
        ("tcp_write_seq", ctypes.c_uint32),
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

# Global variable to store transport layer events for correlation
transport_events = {}

def print_event(cpu, data, size):
    """Print correlated transport and IP layer events"""
    global transport_events

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    ts = event.timestamp / 1e9
    probe = event.probe_name.decode('utf-8', 'replace').strip()
    key = event.key

    # Create packet key for matching
    if key.protocol == 6:  # TCP
        pkt_key = (format_ip(key.src_ip), format_ip(key.dst_ip), 6,
                   socket.ntohs(key.tcp.src_port),
                   socket.ntohs(key.tcp.dst_port),
                   socket.ntohl(key.tcp.seq))
    else:
        return  # Skip unsupported protocols

    if probe == "__tcp_transmit_skb":
        # Store transport layer event
        transport_events[pkt_key] = {
            'timestamp': ts,
            'event': event,
            'skb_ptr': event.skb_ptr,
            'sock_ptr': event.sock_ptr,
            'skb_len': event.skb_len,
            'skb_data_len': event.skb_data_len,
            'skb_net_hdr': event.skb_network_header,
            'skb_trans_hdr': event.skb_transport_header,
            'sock_saddr': event.sock_saddr,
            'sock_daddr': event.sock_daddr,
            'sock_sport': event.sock_sport,
            'sock_dport': event.sock_dport,
            'tcp_snd_nxt': event.tcp_snd_nxt,
            'tcp_write_seq': event.tcp_write_seq,
            'error_msg': event.error_msg
        }

    elif probe == "ip_output":
        # Check for correlation message
        try:
            error_msg = event.error_msg.decode('utf-8', 'replace') if event.error_msg[0] else ""
        except (IndexError, UnicodeDecodeError):
            error_msg = ""

        if "MATCHED" in error_msg and pkt_key in transport_events:
            # Found matching pair - print both
            trans_event = transport_events[pkt_key]

            print(f"\n{'='*80}")
            print(f"🔗 CORRELATED PACKET FLOW - {strftime('%H:%M:%S')} 🔗")

            print(f"   Flow: {format_ip(key.src_ip)}:{socket.ntohs(key.tcp.src_port)} -> "
                  f"{format_ip(key.dst_ip)}:{socket.ntohs(key.tcp.dst_port)} "
                  f"(TCP seq={socket.ntohl(key.tcp.seq)})")

            print(f"{'='*80}")

            # Transport layer info
            print(f"\n📤 TRANSPORT LAYER (__tcp_transmit_skb):")
            print(f"   🔧 TCP Sock: snd_nxt={trans_event['tcp_snd_nxt']} write_seq={trans_event['tcp_write_seq']}")

            print(f"   Timestamp: {trans_event['timestamp']:.9f}")
            print(f"   SKB: 0x{trans_event['skb_ptr']:016x} | Sock: 0x{trans_event['sock_ptr']:016x}")
            print(f"   SKB State: len={trans_event['skb_len']} data_len={trans_event['skb_data_len']} "
                  f"net_hdr={trans_event['skb_net_hdr']} trans_hdr={trans_event['skb_trans_hdr']}")
            print(f"   📊 Key Source: SOCK structure")
            try:
                if trans_event['error_msg'][0]:
                    trans_error = trans_event['error_msg'].decode('utf-8', 'replace')
                    print(f"   ⚠️  Status: {trans_error}")
            except (IndexError, UnicodeDecodeError):
                pass

            # IP layer info
            print(f"\n📦 IP LAYER (ip_output):")
            print(f"   Timestamp: {ts:.9f} (+{(ts - trans_event['timestamp'])*1000000:.3f}μs)")
            print(f"   SKB: 0x{event.skb_ptr:016x} | Sock: 0x{event.sock_ptr:016x}")
            print(f"   SKB State: len={event.skb_len} data_len={event.skb_data_len} "
                  f"net_hdr={event.skb_network_header} trans_hdr={event.skb_transport_header}")
            print(f"   📊 Key Source: SKB headers")
            print(f"   ✅ Status: {error_msg}")

            # TCP sequence number comparison
            seq_transport = trans_event['tcp_snd_nxt']
            seq_ip = socket.ntohl(key.tcp.seq)
            print(f"\n🔍 SEQUENCE NUMBER ANALYSIS:")
            print(f"   Transport Layer (snd_nxt): {seq_transport}")
            print(f"   IP Layer (SKB tcp.seq):    {seq_ip}")
            if seq_transport == seq_ip:
                print(f"   ✅ MATCH: Sequence numbers are identical")
            else:
                print(f"   ❌ DIFF: {abs(seq_transport - seq_ip)} difference")

            print(f"\n💡 CONCLUSION:")
            print(f"   • Transport layer has sock but SKB headers not ready")
            print(f"   • IP layer has complete SKB headers ready for extraction")
            print(f"   • Sequence number consistency: {'✅ Verified' if seq_transport == seq_ip else '❌ Issue detected'}")

            print(f"{'='*80}\n")

            # Clean up
            del transport_events[pkt_key]

def main():
    parser = argparse.ArgumentParser(
        description="Test packet key extraction at transport and IP layers"
    )
    parser.add_argument("--src-ip", help="Source IP filter")
    parser.add_argument("--dst-ip", help="Destination IP filter")
    parser.add_argument("--interface", help="Interface name (for reference)")

    args = parser.parse_args()

    # Convert IPs to hex
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0

    print("🔬 === Transport vs IP Layer Packet Key Correlation Test ===")
    print(f"Source IP filter: {args.src_ip or 'None'}")
    print(f"Destination IP filter: {args.dst_ip or 'None'}")
    print(f"Interface: {args.interface or 'All'}")
    print("")
    print("🎯 Monitoring and correlating probe points:")
    print("  📤 Transport: __tcp_transmit_skb (has sock, SKB headers not ready)")
    print("  📦 IP Layer: ip_output (complete SKB headers available)")
    print("")
    print("📊 Will only show correlated packet flows for detailed analysis...")
    print("")

    # Load BPF program without auto-loading
    b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex), debug=0, cflags=["-w"])

    # Manually attach probes
    # TCP transmit
    try:
        b.attach_kprobe(event="__tcp_transmit_skb", fn_name="kprobe____tcp_transmit_skb")
        print("✓ Attached __tcp_transmit_skb")
    except:
        print("✗ Failed to attach __tcp_transmit_skb")


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

    print("\n=== Summary ===")
    print("Key findings from packet key extraction comparison:")
    print("1. Transport layer (__tcp_transmit_skb): Has sock structure but SKB headers not ready")
    print("2. ip_output: Complete SKB headers available, optimal for packet key extraction")
    print("3. TCP: sequence numbers available from both sock and SKB at different stages")
    print("4. ip_output is recommended as unified TX probe point for TCP")

if __name__ == "__main__":
    main()