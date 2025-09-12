#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Qdisc Packet Order Tracking Tool - Final Version

Extracted directly from vm_network_performance_metrics.py, focusing only on qdisc enqueue/dequeue stages.
Uses the exact same packet parsing and filtering logic that works in the VM network tool.
"""

try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        sys.exit(1)

from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl

# BPF Program - extracted from vm_network_performance_metrics.py
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>

// User-defined filters (same as vm_network_performance_metrics.py)
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define DEV_IFINDEX %d
#define DIRECTION_FILTER 0  // Always both directions for qdisc

// Stage definitions - only qdisc related
#define STG_QDISC_ENQ       8   // qdisc_enqueue
#define STG_QDISC_DEQ       9   // qdisc_dequeue

#define MAX_STAGES          22
#define IFNAMSIZ            16
#define TASK_COMM_LEN       16

// Debug framework (same as vm_network_performance_metrics.py)
#define CODE_PROBE_ENTRY            1
#define CODE_INTERFACE_FILTER       2
#define CODE_DIRECTION_FILTER       3
#define CODE_HANDLE_CALLED          4
#define CODE_HANDLE_ENTRY           5
#define CODE_PARSE_ENTRY            6
#define CODE_PARSE_SUCCESS          7
#define CODE_PARSE_IP_FILTER        8
#define CODE_PARSE_PROTO_FILTER     9
#define CODE_PARSE_PORT_FILTER     10
#define CODE_FLOW_CREATE           14
#define CODE_FLOW_LOOKUP           15
#define CODE_FLOW_FOUND            16
#define CODE_FLOW_NOT_FOUND        17
#define CODE_PERF_SUBMIT           19
#define CODE_IP_HEADER_FAIL        20
#define CODE_TRANSPORT_FAIL        21
#define CODE_PROTOCOL_FILTER_FAIL  22
#define CODE_IP_FILTER_FAIL        23
#define CODE_PORT_FILTER_FAIL      24
#define CODE_SRC_IP_MISMATCH        25
#define CODE_DST_IP_MISMATCH        26

// Packet key structure (same as vm_network_performance_metrics.py)
struct packet_key_t {
    __be32 sip;         // Canonical source IP
    __be32 dip;         // Canonical destination IP
    u8 proto;           // Protocol type
    u8 pad[3];          // Alignment padding
    
    union {
        // TCP packet identification
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be32 seq;           // TCP sequence number (main identifier)
        } tcp;
        
        // UDP packet identification
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be16 id;            // IP identification (main identifier)
            __be16 len;           // UDP length
        } udp;
        
        // ICMP packet identification
        struct {
            __be16 id;            // ICMP ID
            __be16 sequence;      // ICMP sequence number
            u8 type;              // ICMP type
            u8 code;              // ICMP code
            u8 pad[2];            // Padding
        } icmp;
    };
};

// Simplified flow data for qdisc tracking
struct qdisc_flow_data_t {
    u64 enqueue_time;
    u64 dequeue_time;
    char devname[IFNAMSIZ];
};

// Output event
struct qdisc_event {
    struct packet_key_t key;
    u64 enqueue_time;
    u64 dequeue_time;
    u64 delay_ns;
    char devname[IFNAMSIZ];
};

BPF_TABLE("lru_hash", struct packet_key_t, struct qdisc_flow_data_t, qdisc_sessions, 10240);
BPF_PERF_OUTPUT(events);

// Debug statistics
BPF_HISTOGRAM(debug_stage_stats, u32);
BPF_HISTOGRAM(ifindex_seen, u32);  // Track interface indices seen
BPF_HISTOGRAM(src_ips_seen, u32);  // Track source IPs seen
BPF_HISTOGRAM(dst_ips_seen, u32);  // Track destination IPs seen

static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}

// Device filtering with debug info
static __always_inline bool is_target_interface(const struct sk_buff *skb) {
    if (DEV_IFINDEX == 0) return true;  // No filter
    
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    // Record interface index seen for debugging
    u32 idx = (u32)ifindex;
    ifindex_seen.increment(idx);
    
    return (ifindex == DEV_IFINDEX);
}

// Packet parsing functions with fallback for dequeue stage
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip) {
    unsigned char *head;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }
    
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        // Fallback: try data pointer for dequeue stage
        unsigned char *data;
        if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) < 0) {
            return -1;
        }
        // Assume Ethernet header (14 bytes) + IP header
        if (bpf_probe_read_kernel(ip, sizeof(*ip), data + 14) < 0) {
            return -1;
        }
        return 0;
    }
    
    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_header_offset) < 0) {
        return -1;
    }
    
    return 0;
}

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size) {
    unsigned char *head;
    u16 transport_header_offset;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }
    
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        // Calculate transport header offset from IP header
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
            return -1;
        }
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return -1;
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }
    
    if (bpf_probe_read_kernel(hdr, hdr_size, head + transport_header_offset) < 0) {
        return -1;
    }
    
    return 0;
}

// Packet parsing with detailed debug info 
static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key,
    u8 stage_id  // For stage-specific debug
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip) != 0) {
        debug_inc(stage_id, CODE_IP_HEADER_FAIL);
        return 0;  // IP header extraction failed
    }
    
    // Apply filters first
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        debug_inc(stage_id, CODE_PROTOCOL_FILTER_FAIL);
        return 0;
    }
    
    // Record IPs seen for debugging
    src_ips_seen.increment(ip.saddr);
    dst_ips_seen.increment(ip.daddr);
    
    // IP filtering (simplified for qdisc - just check if either matches)
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
        debug_inc(stage_id, CODE_SRC_IP_MISMATCH);
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
        debug_inc(stage_id, CODE_DST_IP_MISMATCH);
        return 0;
    }
    
    // Set canonical source/destination for consistent packet identification
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
    // Parse transport layer based on protocol
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp)) != 0) {
                debug_inc(stage_id, CODE_TRANSPORT_FAIL);
                return 0;
            }
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && key->tcp.source != htons(SRC_PORT_FILTER) && key->tcp.dest != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PORT_FILTER_FAIL);
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.source != htons(DST_PORT_FILTER) && key->tcp.dest != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PORT_FILTER_FAIL);
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;  // Use IP ID as main identifier
            
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
                key->udp.source = udp.source;
                key->udp.dest = udp.dest;
                key->udp.len = udp.len;
            } else {
                debug_inc(stage_id, CODE_TRANSPORT_FAIL);
                // Still continue for UDP since we have IP ID
            }
            
            if (SRC_PORT_FILTER != 0 && key->udp.source != htons(SRC_PORT_FILTER) && key->udp.dest != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PORT_FILTER_FAIL);
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->udp.source != htons(DST_PORT_FILTER) && key->udp.dest != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PORT_FILTER_FAIL);
                return 0;
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (get_transport_header(skb, &icmp, sizeof(icmp)) != 0) {
                debug_inc(stage_id, CODE_TRANSPORT_FAIL);
                return 0;
            }
            
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            break;
        }
        default:
            return 0;
    }
    
    return 1;
}

// Qdisc enqueue using tracepoint (exact copy from vm_network_performance_metrics.py)
RAW_TRACEPOINT_PROBE(net_dev_queue) {
    // args: struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    
    debug_inc(STG_QDISC_ENQ, CODE_PROBE_ENTRY);
    
    if (!is_target_interface(skb)) {
        return 0;
    }
    
    debug_inc(STG_QDISC_ENQ, CODE_INTERFACE_FILTER);
    
    // Parse packet key - use simplified key for more reliable matching
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STG_QDISC_ENQ)) {
        return 0;
    }
    
    debug_inc(STG_QDISC_ENQ, CODE_PARSE_SUCCESS);
    
    // Store enqueue data
    struct qdisc_flow_data_t data = {};
    data.enqueue_time = bpf_ktime_get_ns();
    data.dequeue_time = 0;
    
    // Get device name
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        bpf_probe_read_kernel_str(data.devname, IFNAMSIZ, dev->name);
    }
    
    qdisc_sessions.update(&key, &data);
    debug_inc(STG_QDISC_ENQ, CODE_FLOW_CREATE);
    
    return 0;
}

// Qdisc dequeue with comprehensive debug tracking
RAW_TRACEPOINT_PROBE(qdisc_dequeue) {
    // args: struct Qdisc *qdisc, const struct netdev_queue *txq, int packets, struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb) return 0;
    
    debug_inc(STG_QDISC_DEQ, CODE_PROBE_ENTRY);
    
    // Parse packet key with detailed debug tracking
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STG_QDISC_DEQ)) {
        // Debug info already recorded in parse_packet_key
        return 0;
    }
    
    debug_inc(STG_QDISC_DEQ, CODE_PARSE_SUCCESS);
    
    // Look up enqueue data
    debug_inc(STG_QDISC_DEQ, CODE_FLOW_LOOKUP);
    struct qdisc_flow_data_t *data = qdisc_sessions.lookup(&key);
    if (!data || data->enqueue_time == 0) {
        debug_inc(STG_QDISC_DEQ, CODE_FLOW_NOT_FOUND);
        return 0;
    }
    
    debug_inc(STG_QDISC_DEQ, CODE_FLOW_FOUND);
    
    // Calculate timing
    u64 dequeue_time = bpf_ktime_get_ns();
    u64 delay = dequeue_time - data->enqueue_time;
    
    // Submit complete event
    struct qdisc_event event = {};
    event.key = key;
    event.enqueue_time = data->enqueue_time;
    event.dequeue_time = dequeue_time;
    event.delay_ns = delay;
    
    // Copy device name from enqueue
    #pragma unroll
    for (int i = 0; i < IFNAMSIZ; i++) {
        event.devname[i] = data->devname[i];
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    debug_inc(STG_QDISC_DEQ, CODE_PERF_SUBMIT);
    
    // Clean up
    qdisc_sessions.delete(&key);
    
    return 0;
}
"""

# Event structures
IFNAMSIZ = 16

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("data", ctypes.c_uint8 * 8)  # Union data
    ]

class QdiscEvent(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("enqueue_time", ctypes.c_uint64),
        ("dequeue_time", ctypes.c_uint64),
        ("delay_ns", ctypes.c_uint64),
        ("devname", ctypes.c_char * IFNAMSIZ)
    ]

# Helper functions (same as vm_network_performance_metrics.py)
def get_if_index(devname):
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()

def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value (same as vm_network_performance_metrics.py)"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def get_protocol_identifier(key, protocol):
    """Get protocol-specific packet identifier (same as vm_network_performance_metrics.py)"""
    data = ctypes.string_at(ctypes.addressof(key.data), 8)
    
    if protocol == 6:  # TCP
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        seq = struct.unpack("!I", data[4:8])[0]
        return "TCP %d->%d seq=%u" % (source, dest, seq)
    elif protocol == 17:  # UDP
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        ip_id = struct.unpack("!H", data[4:6])[0]
        return "UDP %d->%d id=%u" % (source, dest, ip_id)
    elif protocol == 1:  # ICMP
        icmp_id = struct.unpack("!H", data[0:2])[0]
        seq = struct.unpack("!H", data[2:4])[0]
        icmp_type = ord(data[4]) if len(data) > 4 else 0
        return "ICMP id=%u seq=%u type=%u" % (icmp_id, seq, icmp_type)
    else:
        return "Proto%d" % protocol

def print_debug_statistics(b):
    """Print debug statistics (same format as vm_network_performance_metrics.py)"""
    stage_names = {
        8: "QDISC_ENQ",
        9: "QDISC_DEQ"
    }
    
    code_names = {
        1: "PROBE_ENTRY", 2: "INTERFACE_FILTER", 3: "DIRECTION_FILTER", 4: "HANDLE_CALLED", 5: "HANDLE_ENTRY",
        6: "PARSE_ENTRY", 7: "PARSE_SUCCESS", 8: "PARSE_IP_FILTER", 9: "PARSE_PROTO_FILTER", 10: "PARSE_PORT_FILTER",
        14: "FLOW_CREATE", 15: "FLOW_LOOKUP", 16: "FLOW_FOUND", 17: "FLOW_NOT_FOUND", 19: "PERF_SUBMIT", 
        20: "IP_HEADER_FAIL", 21: "TRANSPORT_FAIL", 22: "PROTOCOL_FILTER_FAIL", 23: "IP_FILTER_FAIL", 24: "PORT_FILTER_FAIL",
        25: "SRC_IP_MISMATCH", 26: "DST_IP_MISMATCH"
    }
    
    print("\n=== Debug Statistics ===")
    stage_stats = b["debug_stage_stats"]
    for k, v in sorted(stage_stats.items(), key=lambda x: x[0].value):
        if v.value > 0:
            stage_id = k.value >> 8
            code_point = k.value & 0xFF
            stage_name = stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)
            code_name = code_names.get(code_point, "CODE_%d" % code_point)
            print("  %s.%s: %d" % (stage_name, code_name, v.value))
    
    # Show actual IPs seen for debugging
    print("\n=== IPs Seen (Top 10) ===")
    src_ips = b["src_ips_seen"]
    print("Source IPs:")
    for k, v in sorted(src_ips.items(), key=lambda x: x[1].value, reverse=True)[:10]:
        ip_str = format_ip(k.value)
        print("  %s: %d packets" % (ip_str, v.value))
    
    dst_ips = b["dst_ips_seen"] 
    print("Destination IPs:")
    for k, v in sorted(dst_ips.items(), key=lambda x: x[1].value, reverse=True)[:10]:
        ip_str = format_ip(k.value)
        print("  %s: %d packets" % (ip_str, v.value))

def print_event(cpu, data, size):
    """Print qdisc event"""
    event = ctypes.cast(data, ctypes.POINTER(QdiscEvent)).contents
    
    # Format timestamp
    current_time = datetime.datetime.now()
    timestamp_str = current_time.strftime("%H:%M:%S.%f")[:-3]
    
    # Format IPs and protocol info
    src_ip = format_ip(event.key.sip)
    dst_ip = format_ip(event.key.dip)
    pkt_id = get_protocol_identifier(event.key, event.key.proto)
    
    # Get device name
    devname = event.devname.decode('utf-8', 'replace').rstrip('\x00')
    
    # Print event based on whether it's complete or enqueue-only
    print("[%s] %s -> %s %s dev=%s" % (timestamp_str, src_ip, dst_ip, pkt_id, devname))
    print("  Enqueue: %luns" % event.enqueue_time)
    
    if event.dequeue_time > 0:
        # Complete enqueue+dequeue event
        delay_us = event.delay_ns / 1000.0
        print("  Dequeue: %luns" % event.dequeue_time)
        print("  Qdisc delay: %.3fus" % delay_us)
    else:
        # Enqueue-only event (dequeue parsing failed)
        print("  Dequeue: [pending] (dequeue parsing limitation)")
        print("  Status: Packet entered qdisc")
    
    print("")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Qdisc Packet Order Tracker - Final Version (based on vm_network_performance_metrics.py)"
    )
    parser.add_argument('--dev', type=str, help='Network device to monitor')
    parser.add_argument('--src-ip', type=str, help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, help='Source port filter')
    parser.add_argument('--dst-port', type=int, help='Destination port filter')
    parser.add_argument('--proto', choices=['tcp', 'udp', 'icmp', 'all'], default='all')
    
    args = parser.parse_args()
    
    # Convert parameters (same as vm_network_performance_metrics.py)
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    
    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.proto]
    
    dev_ifindex = 0
    if args.dev:
        try:
            dev_ifindex = get_if_index(args.dev)
        except OSError as e:
            print("Error getting interface index: %s" % e)
            sys.exit(1)
    
    print("=== Qdisc Packet Order Tracker - Final Version ===")
    if args.dev:
        print("Device filter: %s (ifindex %d)" % (args.dev, dev_ifindex))
    print("Protocol filter: %s" % args.proto.upper())
    if args.src_ip:
        print("Source IP filter: %s (0x%x)" % (args.src_ip, src_ip_hex))
    if args.dst_ip:
        print("Destination IP filter: %s (0x%x)" % (args.dst_ip, dst_ip_hex))
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    
    # Load BPF program
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, dev_ifindex
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event)
    
    print("\nTracing qdisc packet order... Hit Ctrl-C to end.")
    print("Using exact packet parsing from vm_network_performance_metrics.py")
    print("Note: Dequeue parsing may be limited on some network configurations")
    print("")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
        print_debug_statistics(b)
    finally:
        print("Exiting.")