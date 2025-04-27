#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from bcc import BPF
import ctypes as ct
import argparse
import sys
import socket
import struct

def ip_to_int(ip_str):
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        return socket.htonl(struct.unpack("!I", packed_ip)[0])
    except socket.error:
        print >> sys.stderr, "ERROR: Invalid IP address format '%s'" % ip_str
        sys.exit(1)

PROTO_MAP = {
    'all': 0,
    'icmp': socket.IPPROTO_ICMP,
    'tcp': socket.IPPROTO_TCP,
    'udp': socket.IPPROTO_UDP,
}

parser = argparse.ArgumentParser(
    description="Trace skb->_nfct pointer value, filtering by network properties.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--src-ip', type=str, help='Filter by source IP address')
parser.add_argument('--dst-ip', type=str, help='Filter by destination IP address')
parser.add_argument('--protocol', type=str, choices=PROTO_MAP.keys(), default='all', help='Filter by protocol (tcp, udp, icmp, all)')
parser.add_argument('--src-port', type=int, default=0, help='Filter by source port (TCP/UDP only)')
parser.add_argument('--dst-port', type=int, default=0, help='Filter by destination port (TCP/UDP only)')
args = parser.parse_args()

src_ip_filter = ip_to_int(args.src_ip)
dst_ip_filter = ip_to_int(args.dst_ip)
proto_filter = PROTO_MAP[args.protocol]
src_port_filter = args.src_port
dst_port_filter = args.dst_port

print("--- Filters ---")
print("Src IP: %s (Network Order Int: 0x%x)" % (args.src_ip if args.src_ip else "Any", src_ip_filter))
print("Dst IP: %s (Network Order Int: 0x%x)" % (args.dst_ip if args.dst_ip else "Any", dst_ip_filter))
print("Protocol: %s (%d)" % (args.protocol, proto_filter))
if proto_filter in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
    print("Src Port: %s (Host Order)" % (src_port_filter if src_port_filter else "Any"))
    print("Dst Port: %s (Host Order)" % (dst_port_filter if dst_port_filter else "Any"))
print("---------------")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/atomic.h>
#include <linux/types.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define PROTO_FILTER %d
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d

struct data_t {
    u64 timestamp_ns;
    u64 nfct_ptr;
    int stack_id;
    u32 probe_id;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u8 ip_proto;
    u16 sport;
    u16 dport;
    s64 retval;
    u64 ct_status;
    u32 ctinfo;
    u8  commit_flag;
    u16 zone_id;
    u8  zone_dir;
    u64 ovs_info_nfct_ptr;
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 10240);

struct filter_decision_t {
    bool should_trace;
};
BPF_HASH(entry_filter_decision, u64, struct filter_decision_t, 10240);

enum probe_ids {
    PROBE_ID_NF_CONNTRACK_IN = 1,
    PROBE_ID_OVS_CT_LOOKUP   = 2,
    PROBE_ID_OVS_CT_UPDATE   = 3,
    PROBE_ID_NF_REFRESH_ACCT = 4,
    PROBE_ID_TCP_PACKET = 6,
    PROBE_ID_TCP_PACKET_RET = 7,
    PROBE_ID_TCP_ERROR = 8,
    PROBE_ID_OVS_CT_EXECUTE = 9,
};

static __always_inline int parse_skb_fields(struct sk_buff *skb, struct data_t *data) {
    if (skb == NULL) return 0;

    unsigned char *head;
    u16 network_header;
    u16 transport_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (network_header == (u16)~0U) return 0;

    void *ip_header_address = head + network_header;
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), ip_header_address) < 0) {
        return 0;
    }

    data->saddr = iph.saddr;
    data->daddr = iph.daddr;
    data->ip_proto = iph.protocol;

    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) {
       data->sport = 0;
       data->dport = 0;
       return 1;
    }
    if (transport_header == (u16)~0U) {
       data->sport = 0;
       data->dport = 0;
       return 1;
    }

    void *transport_header_address = head + transport_header;

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), transport_header_address) == 0) {
            data->sport = bpf_ntohs(tcph.source);
            data->dport = bpf_ntohs(tcph.dest);
        } else {
            data->sport = 0;
            data->dport = 0;
        }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), transport_header_address) == 0) {
            data->sport = bpf_ntohs(udph.source);
            data->dport = bpf_ntohs(udph.dest);
        } else {
            data->sport = 0;
            data->dport = 0;
        }
    } else {
        data->sport = 0;
        data->dport = 0;
    }

    return 1;
}

static inline int process_ret_event(struct pt_regs *ctx, u32 probe_id) {
    struct data_t data = {};
    data.timestamp_ns = bpf_ktime_get_ns();
    data.probe_id = probe_id;
    data.retval = PT_REGS_RC(ctx);
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.nfct_ptr = 0;
    data.saddr = 0;
    data.daddr = 0;
    data.ip_proto = 0;
    data.sport = 0;
    data.dport = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

static inline void init_ovs_fields(struct data_t *data) {
    data->commit_flag = (u8)-1;
    data->zone_id = (u16)-1;
    data->zone_dir = (u8)-1;
    data->ovs_info_nfct_ptr = (u64)-1;
}

static inline int check_filters_and_submit_entry(struct pt_regs *ctx, struct sk_buff *skb, u32 probe_id) {
    if (skb == NULL) {
        return 0;
    }

    struct data_t data = {};
    data.ct_status = (u64)-1;
    data.ctinfo = (u32)-1;
    init_ovs_fields(&data);

    if (!parse_skb_fields(skb, &data)) {
         return 0;
    }

    if (SRC_IP_FILTER != 0 && data.saddr != SRC_IP_FILTER) return 0;
    if (DST_IP_FILTER != 0 && data.daddr != DST_IP_FILTER) return 0;

    if (PROTO_FILTER != 0 && data.ip_proto != PROTO_FILTER) return 0;

    if (data.ip_proto == IPPROTO_TCP || data.ip_proto == IPPROTO_UDP) {
        if (SRC_PORT_FILTER != 0 && data.sport != SRC_PORT_FILTER) return 0;
        if (DST_PORT_FILTER != 0 && data.dport != DST_PORT_FILTER) return 0;
    }

    u64 skb_nfct_val = 0;
    bpf_probe_read_kernel(&skb_nfct_val, sizeof(skb_nfct_val), &skb->_nfct);
    data.nfct_ptr = skb_nfct_val;
    data.ctinfo = (u32)(skb_nfct_val & NFCT_INFOMASK);

    if (skb_nfct_val != 0) {
        struct nf_conn *tmpl_bpf = (struct nf_conn *)(skb_nfct_val & NFCT_PTRMASK);
        if (tmpl_bpf != NULL) {
            if (bpf_probe_read_kernel(&data.ct_status, sizeof(data.ct_status), &tmpl_bpf->status) < 0) {
                 data.ct_status = (u64)-2;
            }
        } else {
             data.ct_status = (u64)-3;
        }
    } else {
         data.ct_status = (u64)-4;
    }

    data.timestamp_ns = bpf_ktime_get_ns();
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.probe_id = probe_id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.retval = -999;

    events.perf_submit(ctx, &data, sizeof(data));
    return 1;
}

int trace_nf_conntrack_in(struct pt_regs *ctx, void *net, u8 pf, u32 hooknum, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_CONNTRACK_IN);
    return 0;
}

int trace_ovs_ct_lookup(struct pt_regs *ctx, void *net, void *key, void *info, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_OVS_CT_LOOKUP);
    return 0;
}

int trace_ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_OVS_CT_UPDATE);
    return 0;
}

int trace_nf_ct_refresh_acct(struct pt_regs *ctx, void *ct_ptr, int ctinfo, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_REFRESH_ACCT);
    return 0;
}

int trace_tcp_packet(struct pt_regs *ctx, void *ct, struct sk_buff *skb) {
    int match = check_filters_and_submit_entry(ctx, skb, PROBE_ID_TCP_PACKET);
    if (match) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        struct filter_decision_t decision = {.should_trace = true};
        entry_filter_decision.update(&pid_tgid, &decision);
    }
    return 0;
}

int trace_tcp_packet_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filter_decision_t *decision = entry_filter_decision.lookup(&pid_tgid);

    if (decision && decision->should_trace) {
        process_ret_event(ctx, PROBE_ID_TCP_PACKET_RET);
    }
    entry_filter_decision.delete(&pid_tgid);
    return 0;
}

int trace_tcp_error(struct pt_regs *ctx, void *net, void *tmpl, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_TCP_ERROR);
    return 0;
}

int trace_ovs_ct_execute(struct pt_regs *ctx, void *net, struct sk_buff *skb, void *key, const void *info_ptr) {
    struct data_t data = {};
    data.ct_status = (u64)-1;
    data.ctinfo = (u32)-1;
    init_ovs_fields(&data);
    data.retval = -999;

    if (!parse_skb_fields(skb, &data)) {
         return 0;
    }

    if (SRC_IP_FILTER != 0 && data.saddr != SRC_IP_FILTER) return 0;
    if (DST_IP_FILTER != 0 && data.daddr != DST_IP_FILTER) return 0;
    if (PROTO_FILTER != 0 && data.ip_proto != PROTO_FILTER) return 0;
    if (data.ip_proto == IPPROTO_TCP || data.ip_proto == IPPROTO_UDP) {
        if (SRC_PORT_FILTER != 0 && data.sport != SRC_PORT_FILTER) return 0;
        if (DST_PORT_FILTER != 0 && data.dport != DST_PORT_FILTER) return 0;
    }

    const struct ovs_conntrack_info {
        void *helper;
        struct {
            u16 id;
#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
            u8 dir;
#else
            u8 __pad_dir;
#endif
        } zone;
        struct nf_conn *ct;
        u8 bitfields;
    } *info = (const struct ovs_conntrack_info *)info_ptr;

    u8 tmp_commit = 0xff;
    u16 tmp_zone_id = 0xffff;
    u8 tmp_zone_dir = 0xff;
    u64 tmp_nfct_ptr = (u64)-1;

    if (info != NULL) {
        if (bpf_probe_read_kernel(&tmp_commit, sizeof(tmp_commit), &info->bitfields) == 0) {
            data.commit_flag = tmp_commit & 0x01;
        } else {
            data.commit_flag = (u8)-2;
        }

        if (bpf_probe_read_kernel(&tmp_zone_id, sizeof(tmp_zone_id), &info->zone.id) == 0) {
            data.zone_id = tmp_zone_id;
        } else {
            data.zone_id = (u16)-2;
        }

#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
        if (bpf_probe_read_kernel(&tmp_zone_dir, sizeof(tmp_zone_dir), &info->zone.dir) == 0) {
            data.zone_dir = tmp_zone_dir;
        } else {
             data.zone_dir = (u8)-2;
        }
#else
        data.zone_dir = (u8)-3;
#endif

        if (bpf_probe_read_kernel(&tmp_nfct_ptr, sizeof(tmp_nfct_ptr), &info->ct) == 0) {
            data.ovs_info_nfct_ptr = tmp_nfct_ptr;
        } else {
             data.ovs_info_nfct_ptr = (u64)-2;
        }
    }

    data.timestamp_ns = bpf_ktime_get_ns();
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.probe_id = PROBE_ID_OVS_CT_EXECUTE;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 skb_nfct_val = 0;
    bpf_probe_read_kernel(&skb_nfct_val, sizeof(skb_nfct_val), &skb->_nfct);
    data.nfct_ptr = skb_nfct_val;
    data.ctinfo = (u32)(skb_nfct_val & NFCT_INFOMASK);
    if (skb_nfct_val != 0) {
        struct nf_conn *tmpl_bpf = (struct nf_conn *)(skb_nfct_val & NFCT_PTRMASK);
        if (tmpl_bpf != NULL) {
            if (bpf_probe_read_kernel(&data.ct_status, sizeof(data.ct_status), &tmpl_bpf->status) < 0) {
                 data.ct_status = (u64)-2;
            }
        } else {
             data.ct_status = (u64)-3;
        }
    } else {
         data.ct_status = (u64)-4;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

probe_names = {
    1: "nf_conntrack_in",
    2: "__ovs_ct_lookup",
    3: "ovs_ct_update_key",
    4: "__nf_ct_refresh_acct",
    6: "tcp_packet",
    7: "tcp_packet_ret",
    8: "tcp_error",
    9: "ovs_ct_execute",
}

class Data(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("nfct_ptr", ct.c_ulonglong),
        ("stack_id", ct.c_int),
        ("probe_id", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("ip_proto", ct.c_uint8),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("retval", ct.c_longlong),
        ("ct_status", ct.c_ulonglong),
        ("ctinfo", ct.c_uint32),
        ("commit_flag", ct.c_uint8),
        ("zone_id", ct.c_uint16),
        ("zone_dir", ct.c_uint8),
        ("ovs_info_nfct_ptr", ct.c_ulonglong),
    ]

bpf_text_final = bpf_text % (src_ip_filter, dst_ip_filter, proto_filter, src_port_filter, dst_port_filter)

try:
    b = BPF(text=bpf_text_final)
except Exception as e:
    print >> sys.stderr, "ERROR: Failed to compile or load BPF program: %s" % e
    print >> sys.stderr, "Ensure kernel headers are installed and accessible (e.g., /lib/modules/$(uname -r)/build)."
    sys.exit(1)

def attach_probe(event_name, fn_name):
    try:
        b.attach_kprobe(event=event_name, fn_name=fn_name)
        print("Attached kprobe to %s" % event_name)
    except Exception as e:
        print >> sys.stderr, "WARN: Failed to attach kprobe to %s: %s" % (event_name, e)
        print >> sys.stderr, "      Check if the function exists in your kernel version and modules (e.g., nf_conntrack, openvswitch) are loaded."

def attach_kretprobe(event_name, fn_name):
    try:
        b.attach_kretprobe(event=event_name, fn_name=fn_name)
        print("Attached kretprobe to %s" % event_name)
    except Exception as e:
        print >> sys.stderr, "WARN: Failed to attach kretprobe to %s: %s" % (event_name, e)
        print >> sys.stderr, "      Check if the function exists in your kernel version."

attach_probe("nf_conntrack_in", "trace_nf_conntrack_in")
attach_probe("__ovs_ct_lookup", "trace_ovs_ct_lookup")
attach_probe("ovs_ct_update_key", "trace_ovs_ct_update_key")
attach_probe("__nf_ct_refresh_acct", "trace_nf_ct_refresh_acct")
attach_probe("tcp_packet", "trace_tcp_packet")
attach_kretprobe("tcp_packet", "trace_tcp_packet_ret")
attach_probe("tcp_error", "trace_tcp_error")
attach_probe("ovs_ct_execute", "trace_ovs_ct_execute")

print("\nTracing skb->_nfct pointer changes (filtered)... Press Ctrl-C to stop.")

start_ts = 0

def format_ip(addr):
    packed_ip = struct.pack("I", addr)
    try:
        return socket.inet_ntop(socket.AF_INET, packed_ip)
    except ValueError:
        return "Invalid IP Addr"
    except Exception as e:
        print >> sys.stderr, "Error formatting IP 0x%x: %s" % (addr, e)
        return "Format Error"

def print_event(cpu, data, size):
    global start_ts
    event = ct.cast(data, ct.POINTER(Data)).contents

    if start_ts == 0:
        start_ts = event.timestamp_ns

    probe_name = probe_names.get(event.probe_id, "Unknown Probe (%d)" % event.probe_id)
    comm = event.comm.decode('utf-8', 'replace')
    time_s = float(event.timestamp_ns - start_ts) / 1e9

    is_return_probe = event.retval != -999

    if not is_return_probe and event.saddr != 0:
        saddr_str = format_ip(event.saddr)
        daddr_str = format_ip(event.daddr)
        proto_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.ip_proto, str(event.ip_proto))
        if event.ip_proto in [socket.IPPROTO_TCP, socket.IPPROTO_UDP] and event.sport != 0:
            pkt_info = "%s:%d -> %s:%d (%s)" % (
                saddr_str, event.sport,
                daddr_str, event.dport,
                proto_str
            )
        else:
            pkt_info = "%s -> %s (%s)" % (
                saddr_str,
                daddr_str,
                proto_str
            )
    else:
        pkt_info = "(Pkt N/A)"

    if not is_return_probe:
        nfct_status = "(INVALID/NULL)" if event.nfct_ptr == 0 else ""
        nfct_info = "NFCT_PTR: 0x%x %s" % (event.nfct_ptr, nfct_status)
    else:
        nfct_info = "NFCT_PTR: N/A"

    if is_return_probe:
        retval_info = "RET: %d" % event.retval
    else:
        retval_info = ""

    status_info = ""
    if event.probe_id == 1:
        IPS_TEMPLATE_BIT = 11
        status_val = event.ct_status

        if status_val == (ct.c_ulonglong(-1).value):
             status_info = "CT_STATUS: N/A (Init/NULL)"
        elif status_val == (ct.c_ulonglong(-2).value):
             status_info = "CT_STATUS: N/A (Read Fail)"
        elif status_val == (ct.c_ulonglong(-3).value):
            status_info = "CT_STATUS: N/A (Masked Ptr NULL)"
        elif status_val == (ct.c_ulonglong(-4).value):
            status_info = "CT_STATUS: N/A (_nfct=0)"
        else:
             status_info = "CT_STATUS: 0x%x" % status_val
             if status_val & (1 << IPS_TEMPLATE_BIT):
                 status_info += " (TEMPLATE)"
             else:
                 status_info += " (NOT TEMPLATE)"

    ctinfo_str = ""
    if event.probe_id == 1:
        ctinfo_val = event.ctinfo

        ctinfo_map = {
            0: "IP_CT_ESTABLISHED",
            1: "IP_CT_RELATED",
            2: "IP_CT_NEW",
            3: "IP_CT_ESTABLISHED_REPLY",
            5: "IP_CT_RELATED_REPLY",
            7: "IP_CT_UNTRACKED",
        }

        if ctinfo_val == (ct.c_uint32(-1).value):
            ctinfo_str = "CTINFO: N/A"
        else:
            state_str = ctinfo_map.get(ctinfo_val, "UNKNOWN_VALUE")
            ctinfo_str = "CTINFO: %d (%s)" % (ctinfo_val, state_str)

    ovs_info_str = ""
    if event.probe_id == 9:
        commit_str = "Commit:%d" % event.commit_flag
        if event.commit_flag == (ct.c_uint8(-1).value):
            commit_str = "Commit:N/A(Init)"
        elif event.commit_flag == (ct.c_uint8(-2).value):
            commit_str = "Commit:N/A(ReadFail)"

        zone_id_str = "ZoneID:%d" % event.zone_id
        if event.zone_id == (ct.c_uint16(-1).value):
            zone_id_str = "ZoneID:N/A(Init)"
        elif event.zone_id == (ct.c_uint16(-2).value):
            zone_id_str = "ZoneID:N/A(ReadFail)"

        zone_dir_str = "ZoneDir:%d" % event.zone_dir
        if event.zone_dir == (ct.c_uint8(-1).value):
            zone_dir_str = "ZoneDir:N/A(Init)"
        elif event.zone_dir == (ct.c_uint8(-2).value):
            zone_dir_str = "ZoneDir:N/A(ReadFail)"
        elif event.zone_dir == (ct.c_uint8(-3).value):
            zone_dir_str = "ZoneDir:N/A(NoCfg)"

        ovs_nfct_str = "InfoNFCT:0x%x" % event.ovs_info_nfct_ptr
        if event.ovs_info_nfct_ptr == (ct.c_ulonglong(-1).value):
            ovs_nfct_str = "InfoNFCT:N/A(Init)"
        elif event.ovs_info_nfct_ptr == (ct.c_ulonglong(-2).value):
            ovs_nfct_str = "InfoNFCT:N/A(ReadFail)"

        skb_nfct_str = "(skbNFCT:0x%x)" % event.nfct_ptr
        if event.nfct_ptr == 0:
            skb_nfct_str = "(skbNFCT:NULL)"

        ovs_info_str = "%s %s %s %s %s" % (
            commit_str, zone_id_str, zone_dir_str, ovs_nfct_str, skb_nfct_str)

    print("TIME(s): %-9.4f COMM: %-16s FUNC: %-25s %s %s %s %s %s %s" % (
        time_s, comm, probe_name, nfct_info, pkt_info, retval_info, status_info, ctinfo_str, ovs_info_str))

    if event.stack_id >= 0:
        try:
            stack_trace = list(b.get_table("stack_traces").walk(event.stack_id))
            for addr in stack_trace:
                sym = b.ksym(addr, show_offset=True)
                print("  %s" % sym)
        except KeyError:
             print("  [WARN: Stack ID %d not found in stack_traces table]" % event.stack_id)
        except Exception as e:
             print("  [WARN: Error walking/resolving stack trace for stack_id %d: %s]" % (event.stack_id, e))
    else:
        print("  [Kernel Stack Trace Error: %d]" % event.stack_id)

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching probes and exiting...")
        sys.exit(0)
    except Exception as e:
        print >> sys.stderr, "ERROR during perf buffer polling: %s" % e
        sys.exit(1)