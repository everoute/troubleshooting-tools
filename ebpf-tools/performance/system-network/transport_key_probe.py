#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Transport/IP key inspection helper.

Attaches lightweight probes to transport-layer TX functions and the shared
`ip_output` path so we can compare the packet key information available at each
stage. Useful for validating how to build consistent keys when tracing.
"""

import argparse
import ctypes
import datetime
import socket
import struct
import sys
from typing import Iterable, List, Optional, Tuple

try:
    from bcc import BPF
except ImportError as exc:  # pragma: no cover - handled at runtime
    print("Error: BCC python module not found (install python3-bcc)")
    raise SystemExit(1) from exc


def ip_to_be32(ip_str: str) -> int:
    if not ip_str:
        return 0
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def ip_to_host_u32(ip_str: str) -> int:
    if not ip_str:
        return 0
    return socket.ntohl(ip_to_be32(ip_str))


BPF_PROGRAM_TEMPLATE = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/inet_sock.h>

#define SRC_IP_FILTER %u
#define DST_IP_FILTER %u
#define PROTOCOL_FILTER %d

#define STAGE_TCP_TRANSPORT 0
#define STAGE_UDP_TRANSPORT 1
#define STAGE_IP_OUTPUT     2

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
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;
            __be16 udp_len;
            __be16 frag_off;
        } udp;
    };
    u64 first_seen_ns;
};

struct tcp_skb_cb_min {
    __u32 seq;
    __u32 end_seq;
};

struct event_t {
    u64 ts_ns;
    u32 stage;
    u32 cpu;

    struct packet_key_t key;

    u64 skb_ptr;
    u64 sk_ptr;
    u64 arg0;
    u64 arg1;
    u64 arg2;

    u32 cb_seq;
    u32 cb_end_seq;
    u32 hdr_seq;
    u32 hdr_ack;

    u16 ip_id;
    u16 frag_off;
    u16 udp_len;
    u16 udp_check;
};

BPF_PERF_OUTPUT(events);

static __always_inline int read_tcp_skb_cb(struct sk_buff *skb, struct tcp_skb_cb_min *out) {
    return bpf_probe_read_kernel(out, sizeof(*out), (const void *)skb->cb);
}

static __always_inline int get_head_and_offsets(struct sk_buff *skb, unsigned char **head,
                                                u16 *network_offset, u16 *transport_offset) {
    if (bpf_probe_read_kernel(head, sizeof(*head), &skb->head) < 0)
        return -1;
    if (!*head)
        return -1;

    if (bpf_probe_read_kernel(network_offset, sizeof(*network_offset), &skb->network_header) < 0)
        return -1;

    if (transport_offset &&
        bpf_probe_read_kernel(transport_offset, sizeof(*transport_offset), &skb->transport_header) < 0)
        *transport_offset = 0;

    return 0;
}

static __always_inline int read_iphdr(struct sk_buff *skb, struct iphdr *ip) {
    unsigned char *head;
    u16 network_offset;

    if (get_head_and_offsets(skb, &head, &network_offset, NULL) < 0)
        return -1;

    if (network_offset == (u16)~0U)
        return -1;

    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_offset) < 0)
        return -1;

    return 0;
}

static __always_inline int read_tcphdr(struct sk_buff *skb, struct tcphdr *tcp) {
    unsigned char *head;
    u16 network_offset;
    u16 transport_offset;

    if (get_head_and_offsets(skb, &head, &network_offset, &transport_offset) < 0)
        return -1;

    if (transport_offset == 0 || transport_offset == (u16)~0U || transport_offset == network_offset) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_offset) < 0)
            return -1;
        u8 ihl = ip.ihl & 0x0F;
        if (ihl < 5)
            return -1;
        transport_offset = network_offset + ihl * 4;
    }

    if (bpf_probe_read_kernel(tcp, sizeof(*tcp), head + transport_offset) < 0)
        return -1;

    return 0;
}

static __always_inline int read_udphdr(struct sk_buff *skb, struct udphdr *udp) {
    unsigned char *head;
    u16 network_offset;
    u16 transport_offset;

    if (get_head_and_offsets(skb, &head, &network_offset, &transport_offset) < 0)
        return -1;

    if (transport_offset == 0 || transport_offset == (u16)~0U || transport_offset == network_offset) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_offset) < 0)
            return -1;
        u8 ihl = ip.ihl & 0x0F;
        if (ihl < 5)
            return -1;
        transport_offset = network_offset + ihl * 4;
    }

    if (bpf_probe_read_kernel(udp, sizeof(*udp), head + transport_offset) < 0)
        return -1;

    return 0;
}

static __always_inline int apply_filters(struct packet_key_t *key) {
    if (SRC_IP_FILTER) {
        if (key->src_ip != (__be32)SRC_IP_FILTER && key->dst_ip != (__be32)SRC_IP_FILTER)
            return 0;
    }
    if (DST_IP_FILTER) {
        if (key->src_ip != (__be32)DST_IP_FILTER && key->dst_ip != (__be32)DST_IP_FILTER)
            return 0;
    }
    if (PROTOCOL_FILTER && key->protocol != PROTOCOL_FILTER)
        return 0;
    return 1;
}

static __always_inline void emit_event(void *ctx, struct event_t *evt) {
    events.perf_submit(ctx, evt, sizeof(*evt));
}

int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb,
                               int clone_it, gfp_t gfp_mask, u32 rcv_nxt) {
    if (!sk || !skb)
        return 0;

    struct event_t evt = {};
    evt.stage = STAGE_TCP_TRANSPORT;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.cpu = bpf_get_smp_processor_id();
    evt.skb_ptr = (u64)skb;
    evt.sk_ptr = (u64)sk;
    evt.arg0 = clone_it;
    evt.arg1 = (__u64)gfp_mask;
    evt.arg2 = rcv_nxt;

    evt.key.protocol = IPPROTO_TCP;
    evt.key.first_seen_ns = evt.ts_ns;

    struct inet_sock *inet = inet_sk(sk);
    if (inet) {
        bpf_probe_read_kernel(&evt.key.src_ip, sizeof(evt.key.src_ip), &inet->inet_saddr);
        bpf_probe_read_kernel(&evt.key.dst_ip, sizeof(evt.key.dst_ip), &inet->inet_daddr);
        bpf_probe_read_kernel(&evt.key.tcp.src_port, sizeof(evt.key.tcp.src_port), &inet->inet_sport);
        bpf_probe_read_kernel(&evt.key.tcp.dst_port, sizeof(evt.key.tcp.dst_port), &inet->inet_dport);
    }

    struct tcp_skb_cb_min tcb = {};
    if (read_tcp_skb_cb(skb, &tcb) == 0) {
        evt.cb_seq = tcb.seq;
        evt.cb_end_seq = tcb.end_seq;
        if (tcb.seq)
            evt.key.tcp.seq = (__be32)bpf_htonl(tcb.seq);
    }

    struct iphdr ip = {};
    if (evt.key.src_ip == 0 || evt.key.dst_ip == 0 || evt.key.tcp.src_port == 0 || evt.key.tcp.dst_port == 0) {
        if (read_iphdr(skb, &ip) == 0) {
            evt.key.src_ip = ip.saddr;
            evt.key.dst_ip = ip.daddr;
        }
        struct tcphdr tcp = {};
        if (read_tcphdr(skb, &tcp) == 0) {
            evt.key.tcp.src_port = tcp.source;
            evt.key.tcp.dst_port = tcp.dest;
            evt.hdr_seq = (__u32)bpf_ntohl(tcp.seq);
            evt.hdr_ack = (__u32)bpf_ntohl(tcp.ack_seq);
            if (!evt.key.tcp.seq)
                evt.key.tcp.seq = tcp.seq;
        }
    } else {
        struct tcphdr tcp = {};
        if (read_tcphdr(skb, &tcp) == 0) {
            evt.hdr_seq = (__u32)bpf_ntohl(tcp.seq);
            evt.hdr_ack = (__u32)bpf_ntohl(tcp.ack_seq);
        }
    }

    if (!apply_filters(&evt.key))
        return 0;

    emit_event(ctx, &evt);
    return 0;
}

int udp_send_skb_stage0(struct pt_regs *ctx, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork) {
    if (!skb)
        return 0;

    struct event_t evt = {};
    evt.stage = STAGE_UDP_TRANSPORT;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.cpu = bpf_get_smp_processor_id();
    evt.skb_ptr = (u64)skb;
    evt.sk_ptr = 0;
    evt.arg0 = (u64)fl4;
    evt.arg1 = (u64)cork;

    evt.key.protocol = IPPROTO_UDP;
    evt.key.first_seen_ns = evt.ts_ns;

    struct iphdr ip = {};
    if (read_iphdr(skb, &ip) == 0) {
        evt.key.src_ip = ip.saddr;
        evt.key.dst_ip = ip.daddr;
        evt.key.udp.ip_id = ip.id;
        evt.key.udp.frag_off = ip.frag_off;
        evt.ip_id = (__u16)bpf_ntohs(ip.id);
        evt.frag_off = (__u16)bpf_ntohs(ip.frag_off);
    }

    if (fl4) {
        evt.key.src_ip = fl4->saddr;
        evt.key.dst_ip = fl4->daddr;
        evt.key.udp.src_port = fl4->fl4_sport;
        evt.key.udp.dst_port = fl4->fl4_dport;
    }

    struct udphdr udp = {};
    if (read_udphdr(skb, &udp) == 0) {
        evt.key.udp.src_port = udp.source;
        evt.key.udp.dst_port = udp.dest;
        evt.udp_len = (__u16)bpf_ntohs(udp.len);
        evt.udp_check = bpf_ntohs(udp.check);
        evt.key.udp.udp_len = udp.len;
    }

    if (!apply_filters(&evt.key))
        return 0;

    emit_event(ctx, &evt);
    return 0;
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    if (!skb)
        return 0;

    struct event_t evt = {};
    evt.stage = STAGE_IP_OUTPUT;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.cpu = bpf_get_smp_processor_id();
    evt.skb_ptr = (u64)skb;
    evt.sk_ptr = (u64)sk;
    evt.arg0 = (u64)net;

    struct iphdr ip = {};
    if (read_iphdr(skb, &ip) != 0)
        return 0;

    evt.key.src_ip = ip.saddr;
    evt.key.dst_ip = ip.daddr;
    evt.key.protocol = ip.protocol;
    evt.key.first_seen_ns = evt.ts_ns;
    evt.ip_id = (__u16)bpf_ntohs(ip.id);
    evt.frag_off = (__u16)bpf_ntohs(ip.frag_off);

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp = {};
        if (read_tcphdr(skb, &tcp) == 0) {
            evt.key.tcp.src_port = tcp.source;
            evt.key.tcp.dst_port = tcp.dest;
            evt.key.tcp.seq = tcp.seq;
            evt.hdr_seq = (__u32)bpf_ntohl(tcp.seq);
            evt.hdr_ack = (__u32)bpf_ntohl(tcp.ack_seq);
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp = {};
        if (read_udphdr(skb, &udp) == 0) {
            evt.key.udp.src_port = udp.source;
            evt.key.udp.dst_port = udp.dest;
            evt.key.udp.udp_len = udp.len;
            evt.key.udp.ip_id = ip.id;
            evt.key.udp.frag_off = ip.frag_off;
            evt.udp_len = (__u16)bpf_ntohs(udp.len);
            evt.udp_check = bpf_ntohs(udp.check);
        }
    }

    if (!apply_filters(&evt.key))
        return 0;

    emit_event(ctx, &evt);
    return 0;
}
"""


class PacketKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("data", ctypes.c_uint8 * 12),
        ("first_seen_ns", ctypes.c_uint64),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("stage", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("key", PacketKey),
        ("skb_ptr", ctypes.c_uint64),
        ("sk_ptr", ctypes.c_uint64),
        ("arg0", ctypes.c_uint64),
        ("arg1", ctypes.c_uint64),
        ("arg2", ctypes.c_uint64),
        ("cb_seq", ctypes.c_uint32),
        ("cb_end_seq", ctypes.c_uint32),
        ("hdr_seq", ctypes.c_uint32),
        ("hdr_ack", ctypes.c_uint32),
        ("ip_id", ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16),
        ("udp_len", ctypes.c_uint16),
        ("udp_check", ctypes.c_uint16),
    ]


STAGE_NAMES = {
    0: "TCP_TRANSPORT",
    1: "UDP_TRANSPORT",
    2: "IP_OUTPUT",
}


def format_ip(addr: int) -> str:
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", addr))


def parse_tcp_fields(raw: Iterable[int]) -> Tuple[int, int, int]:
    data = bytes(raw[:8])
    src_port, dst_port, seq = struct.unpack("!HHI", data)
    return src_port, dst_port, seq


def parse_udp_fields(raw: Iterable[int]) -> Tuple[int, int, int, int, int]:
    data = bytes(raw[:10])
    src_port, dst_port, ip_id, udp_len, frag_off = struct.unpack("!HHHHH", data)
    return src_port, dst_port, ip_id, udp_len, frag_off


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src-ip", default="", help="Filter by source IP")
    parser.add_argument("--dst-ip", default="", help="Filter by destination IP")
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"], default="both")
    parser.add_argument("--duration", type=int, default=10, help="Run duration in seconds")
    parser.add_argument("--internal-interface", default="", help="Display helper only")
    parser.add_argument("--phy-interface", default="", help="Display helper only")

    args = parser.parse_args(argv)

    src_ip = ip_to_be32(args.src_ip)
    dst_ip = ip_to_be32(args.dst_ip)
    if args.protocol == "tcp":
        proto_filter = 6
    elif args.protocol == "udp":
        proto_filter = 17
    else:
        proto_filter = 0

    bpf_program = BPF_PROGRAM_TEMPLATE % (src_ip, dst_ip, proto_filter)
    b = BPF(text=bpf_program)

    if args.protocol in ("tcp", "both"):
        b.attach_kprobe(event="__tcp_transmit_skb", fn_name="kprobe____tcp_transmit_skb")

    if args.protocol in ("udp", "both"):
        attached = False
        try:
            for sym in b.get_kprobe_functions(b"udp_send_skb"):
                b.attach_kprobe(event=sym.decode("utf-8"), fn_name="udp_send_skb_stage0")
                attached = True
                break
        except Exception:
            pass
        if not attached:
            b.attach_kprobe(event="udp_send_skb", fn_name="udp_send_skb_stage0")

    b.attach_kprobe(event="ip_output", fn_name="kprobe__ip_output")

    print("=== Transport/IP Key Inspection ===")
    if args.src_ip:
        print(f"Source IP filter: {args.src_ip}")
    if args.dst_ip:
        print(f"Destination IP filter: {args.dst_ip}")
    print(f"Protocol filter: {args.protocol}")
    if args.internal_interface:
        print(f"Internal interface (display): {args.internal_interface}")
    if args.phy_interface:
        print(f"Physical interface (display): {args.phy_interface}")
    print("Run duration: %ds" % args.duration)

    src_ip_host = ip_to_host_u32(args.src_ip)
    dst_ip_host = ip_to_host_u32(args.dst_ip)

    start_time = datetime.datetime.now()
    stats = {"total": 0, "matched": 0}
    samples: List[Tuple[int, int, int]] = []

    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        stats["total"] += 1

        src_host_int = socket.ntohl(int(event.key.src_ip))
        dst_host_int = socket.ntohl(int(event.key.dst_ip))

        if len(samples) < 10:
            samples.append((src_host_int, dst_host_int, event.key.protocol))

        if src_ip_host and src_host_int != src_ip_host:
            return
        if dst_ip_host and dst_host_int != dst_ip_host:
            return

        stats["matched"] += 1

        stage_name = STAGE_NAMES.get(event.stage, f"STAGE_{event.stage}")
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip_str = format_ip(event.key.src_ip)
        dst_ip_str = format_ip(event.key.dst_ip)
        proto = event.key.protocol

        print("\n[%s] %s (CPU %d)" % (ts, stage_name, event.cpu))
        print("  skb=0x%x sk=0x%x" % (event.skb_ptr, event.sk_ptr))
        if event.stage == 0:  # TCP transport
            src_port, dst_port, seq = parse_tcp_fields(event.key.data)
            print("  TCP %s:%d -> %s:%d seq=0x%08x" % (src_ip_str, src_port, dst_ip_str, dst_port, seq))
            print("  cb_seq=0x%08x cb_end_seq=0x%08x hdr_seq=0x%08x hdr_ack=0x%08x" % (
                event.cb_seq, event.cb_end_seq, event.hdr_seq, event.hdr_ack))
            print("  args clone_it=%d gfp=0x%x rcv_nxt=0x%x" % (event.arg0, event.arg1, event.arg2))
        elif event.stage == 1:  # UDP transport
            src_port, dst_port, ip_id, udp_len, frag_off = parse_udp_fields(event.key.data)
            print("  UDP %s:%d -> %s:%d ip_id=0x%04x len=%d frag_off=%d" % (
                src_ip_str, src_port, dst_ip_str, dst_port, ip_id, udp_len, frag_off))
            print("  udp_len=%d udp_check=0x%04x fl4=0x%x cork=0x%x" % (
                event.udp_len, event.udp_check, event.arg0, event.arg1))
        else:  # IP output
            if proto == 6:
                src_port, dst_port, seq = parse_tcp_fields(event.key.data)
                print("  TCP %s:%d -> %s:%d seq=0x%08x" % (src_ip_str, src_port, dst_ip_str, dst_port, seq))
                print("  hdr_seq=0x%08x hdr_ack=0x%08x" % (event.hdr_seq, event.hdr_ack))
            elif proto == 17:
                src_port, dst_port, ip_id, udp_len, frag_off = parse_udp_fields(event.key.data)
                print("  UDP %s:%d -> %s:%d ip_id=0x%04x len=%d frag_off=%d" % (
                    src_ip_str, src_port, dst_ip_str, dst_port, ip_id, udp_len, frag_off))
                print("  udp_len=%d udp_check=0x%04x" % (event.udp_len, event.udp_check))
            else:
                print("  protocol=%d %s -> %s" % (proto, src_ip_str, dst_ip_str))
            print("  net=0x%x" % event.arg0)
        print("  ip_id=0x%04x frag_off=%d" % (event.ip_id, event.frag_off))

    b["events"].open_perf_buffer(print_event)

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
            if (datetime.datetime.now() - start_time).total_seconds() > args.duration:
                break
    except KeyboardInterrupt:
        pass

    print("\n=== Finished ===")
    print(f"Total events: {stats['total']}  Matched filters: {stats['matched']}")
    if samples:
        print("Sample src/dst pairs observed (host order):")
        for sip, dip, proto in samples:
            sip_str = socket.inet_ntoa(struct.pack('!I', socket.htonl(sip)))
            dip_str = socket.inet_ntoa(struct.pack('!I', socket.htonl(dip)))
            print(f"  {sip_str} -> {dip_str} proto={proto}")
    if stats["matched"] == 0:
        print("No events matched the specified filters during the capture window.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
