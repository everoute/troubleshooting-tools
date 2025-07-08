#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from bcc import BPF
import ctypes as ct
import argparse
import sys
import socket
import struct
from datetime import datetime
import time
import json
import os

def get_boot_time():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        
        return time.time() - uptime_seconds
    except Exception as e:
        print >> sys.stderr, "WARNING: Unable to get boot time: %s" % e
        return time.time()

def kernel_ns_to_datetime(ns):
    seconds_since_boot = float(ns) / 1e9
    absolute_time = BOOT_TIME + seconds_since_boot
    return datetime.fromtimestamp(absolute_time)

BOOT_TIME = get_boot_time()

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
parser.add_argument('--rel-time', action='store_true', help='Display relative seconds instead of absolute timestamps')
parser.add_argument('--filters-file', type=str, help='JSON file containing multiple filter rules')
args = parser.parse_args()

# 定义过滤器规则列表
filter_rules = []

# 如果指定了过滤器配置文件，则加载它
if args.filters_file:
    try:
        with open(args.filters_file, 'r') as f:
            filter_data = json.load(f)
            
            # 处理过滤器规则
            if isinstance(filter_data, list):
                for rule in filter_data:
                    filter_rule = {
                        'src_ip': ip_to_int(rule.get('src_ip')),
                        'dst_ip': ip_to_int(rule.get('dst_ip')),
                        'proto': PROTO_MAP.get(rule.get('protocol', 'all'), 0),
                        'src_port': int(rule.get('src_port', 0)),
                        'dst_port': int(rule.get('dst_port', 0))
                    }
                    filter_rules.append(filter_rule)
                    
                    # 打印规则信息
                    print("Added filter rule: %s" % rule)
    except Exception as e:
        print >> sys.stderr, "ERROR: Failed to load filter rules from %s: %s" % (args.filters_file, e)
        sys.exit(1)
    
    if not filter_rules:
        print >> sys.stderr, "WARNING: No filter rules found in %s" % args.filters_file
else:
    # 使用命令行参数作为单个过滤器
    src_ip_filter = ip_to_int(args.src_ip)
    dst_ip_filter = ip_to_int(args.dst_ip)
    proto_filter = PROTO_MAP[args.protocol]
    src_port_filter = args.src_port
    dst_port_filter = args.dst_port
    
    # 将命令行参数添加为单个过滤器规则
    if src_ip_filter != 0 or dst_ip_filter != 0 or proto_filter != 0 or src_port_filter != 0 or dst_port_filter != 0:
        filter_rules.append({
            'src_ip': src_ip_filter,
            'dst_ip': dst_ip_filter,
            'proto': proto_filter,
            'src_port': src_port_filter,
            'dst_port': dst_port_filter
        })

    print("--- Filters ---")
    print("Src IP: %s (Network Order Int: 0x%x)" % (args.src_ip if args.src_ip else "Any", src_ip_filter))
    print("Dst IP: %s (Network Order Int: 0x%x)" % (args.dst_ip if args.dst_ip else "Any", dst_ip_filter))
    print("Protocol: %s (%d)" % (args.protocol, proto_filter))
    if proto_filter in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
        print("Src Port: %s (Host Order)" % (src_port_filter if src_port_filter else "Any"))
        print("Dst Port: %s (Host Order)" % (dst_port_filter if dst_port_filter else "Any"))
    print("---------------")

print("For multiple connection filters, create a JSON file with this structure:")
print('''
[
    {
        "src_ip": "10.200.0.243",
        "dst_ip": "10.200.0.245",
        "protocol": "tcp",
        "src_port": 9900,
        "dst_port": 0
    },
    {
        "src_ip": "10.200.0.245",
        "dst_ip": "10.200.0.243",
        "protocol": "tcp", 
        "src_port": 0, 
        "dst_port": 9900
    }
]
''')
print("And use it with: --filters-file /path/to/filters.json")
print("---------------")

# 最多支持10个过滤器规则
MAX_FILTER_RULES = 10

# 填充过滤器规则数组
filter_array = []
for i in range(MAX_FILTER_RULES):
    if i < len(filter_rules):
        rule = filter_rules[i]
        filter_array.append((rule['src_ip'], rule['dst_ip'], rule['proto'], rule['src_port'], rule['dst_port']))
    else:
        filter_array.append((0, 0, 0, 0, 0))  # 空规则

# 计算实际规则数
num_filters = min(len(filter_rules), MAX_FILTER_RULES)

# 修改BPF代码模板，加入多过滤器支持
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/inet_connection_sock.h>
#include <linux/netfilter/nf_conntrack_zones_common.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <net/sock.h>

// 多过滤器规则支持
#define MAX_FILTER_RULES %d
#define NUM_FILTERS %d

struct filter_rule {
    u32 src_ip;
    u32 dst_ip;
    u8 proto;
    u16 src_port;
    u16 dst_port;
};

// 全局过滤器规则数组
struct filter_rule filter_rules[MAX_FILTER_RULES] = {
"""

# 添加所有过滤器规则
#pragma unroll
for i, (src_ip, dst_ip, proto, src_port, dst_port) in enumerate(filter_array):
    bpf_text += "    {%sU, %sU, %d, %d, %d}" % (hex(src_ip), hex(dst_ip), proto, src_port, dst_port)
    if i < MAX_FILTER_RULES - 1:
        bpf_text += ",\n"
    else:
        bpf_text += "\n"

bpf_text += """
};

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
    u8  tcp_state;
    u32 ifindex;
    char devname[16];  // Device name max length is 16 in Linux
    u16 ip_id;         // IP identification field
    u32 tcp_seq;       // TCP sequence number
    u32 tcp_ack;       // TCP acknowledgment number
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

    // Extract device info from skb->dev
    struct net_device *dev = NULL;
    data->ifindex = 0;
    __builtin_memset(&data->devname, 0, sizeof(data->devname));
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        // Read ifindex
        bpf_probe_read_kernel(&data->ifindex, sizeof(data->ifindex), &dev->ifindex);
        
        // Read device name
        char devname[16];
        if (bpf_probe_read_kernel_str(&devname, sizeof(devname), dev->name) > 0) {
            __builtin_memcpy(&data->devname, devname, sizeof(devname));
        }
    }

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
    data->tcp_state = 0xFF;
    
    // Extract IP ID
    data->ip_id = bpf_ntohs(iph.id);

    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) {
       data->sport = 0;
       data->dport = 0;
       data->tcp_seq = 0;
       data->tcp_ack = 0;
       return 1;
    }
    if (transport_header == (u16)~0U) {
       data->sport = 0;
       data->dport = 0;
       data->tcp_seq = 0;
       data->tcp_ack = 0;
       return 1;
    }

    void *transport_header_address = head + transport_header;

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), transport_header_address) == 0) {
            data->sport = bpf_ntohs(tcph.source);
            data->dport = bpf_ntohs(tcph.dest);
            
            // Extract TCP sequence and ACK numbers
            data->tcp_seq = bpf_ntohl(tcph.seq);
            data->tcp_ack = bpf_ntohl(tcph.ack_seq);
            
            struct sock *sk = NULL;
            if (bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk) == 0 && sk != NULL) {
                u8 tcp_state = 0;
                void *state_addr = (void *)&sk->__sk_common.skc_state;
                if (bpf_probe_read_kernel(&tcp_state, sizeof(tcp_state), state_addr) == 0) {
                    data->tcp_state = tcp_state;
                }
            }
        } else {
            data->sport = 0;
            data->dport = 0;
            data->tcp_seq = 0;
            data->tcp_ack = 0;
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
        data->tcp_seq = 0;
        data->tcp_ack = 0;
    } else {
        data->sport = 0;
        data->dport = 0;
        data->tcp_seq = 0;
        data->tcp_ack = 0;
    }

    return 1;
}

// Define the shared ovs_conntrack_info structure
struct ovs_conntrack_info {
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
};

// Shared function to parse ovs_conntrack_info
static inline void parse_ovs_conntrack_info(const struct ovs_conntrack_info *info, struct data_t *data) {
    if (info == NULL) {
        data->commit_flag = (u8)-1;
        data->zone_id = (u16)-1;
        data->zone_dir = (u8)-1;
        data->ovs_info_nfct_ptr = (u64)-1;
        return;
    }

    // Parse commit flag
    u8 tmp_commit = 0xff;
    if (bpf_probe_read_kernel(&tmp_commit, sizeof(tmp_commit), &info->bitfields) == 0) {
        data->commit_flag = tmp_commit & 0x01;
    } else {
        data->commit_flag = (u8)-2;
    }

    // Parse zone ID
    u16 tmp_zone_id = 0xffff;
    if (bpf_probe_read_kernel(&tmp_zone_id, sizeof(tmp_zone_id), &info->zone.id) == 0) {
        data->zone_id = tmp_zone_id;
    } else {
        data->zone_id = (u16)-2;
    }

    // Parse zone direction
#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
    u8 tmp_zone_dir = 0xff;
    if (bpf_probe_read_kernel(&tmp_zone_dir, sizeof(tmp_zone_dir), &info->zone.dir) == 0) {
        data->zone_dir = tmp_zone_dir;
    } else {
        data->zone_dir = (u8)-2;
    }
#else
    data->zone_dir = (u8)-3;
#endif

    // Parse nfct pointer
    u64 tmp_nfct_ptr = (u64)-1;
    if (bpf_probe_read_kernel(&tmp_nfct_ptr, sizeof(tmp_nfct_ptr), &info->ct) == 0) {
        data->ovs_info_nfct_ptr = tmp_nfct_ptr;
    } else {
        data->ovs_info_nfct_ptr = (u64)-2;
    }
}

static inline void init_ovs_fields(struct data_t *data) {
    data->commit_flag = (u8)-1;
    data->zone_id = (u16)-1;
    data->zone_dir = (u8)-1;
    data->ovs_info_nfct_ptr = (u64)-1;
}

static inline int process_ret_event(struct pt_regs *ctx, u32 probe_id) {
    struct data_t data = {};
    data.timestamp_ns = bpf_ktime_get_ns();
    data.probe_id = probe_id;
    data.retval = (s32)PT_REGS_RC(ctx);
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.nfct_ptr = 0;
    data.saddr = 0;
    data.daddr = 0;
    data.ip_proto = 0;
    data.sport = 0;
    data.dport = 0;
    data.tcp_state = 0xFF;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Shared function to extract packet information and apply filters
static inline int prepare_data_and_check_filters(struct pt_regs *ctx, struct sk_buff *skb, struct data_t *data) {
    if (skb == NULL) {
        return 0;
    }

    // Initialize data fields
    data->ct_status = (u64)-1;
    data->ctinfo = (u32)-1;
    init_ovs_fields(data);

    // Parse SKB fields
    if (!parse_skb_fields(skb, data)) {
        return 0;
    }

    // No filter rules means trace everything
    if (NUM_FILTERS == 0) {
        return 1;
    }
    
    // Apply filters with OR logic - match any rule to pass
    #pragma unroll
    for (int i = 0; i < NUM_FILTERS; i++) {
        struct filter_rule *rule = &filter_rules[i];
        bool rule_match = true;
        
        // Skip empty rules
        if (rule->src_ip == 0 && rule->dst_ip == 0 && rule->proto == 0 && 
            rule->src_port == 0 && rule->dst_port == 0) {
            continue;
        }
        
        // First try to match direct direction
        rule_match = true;
        
        // Check source IP if specified
        if (rule->src_ip != 0 && data->saddr != rule->src_ip) {
            rule_match = false;
        }
        
        // Check destination IP if specified
        if (rule_match && rule->dst_ip != 0 && data->daddr != rule->dst_ip) {
            rule_match = false;
        }
        
        // Check protocol if specified
        if (rule_match && rule->proto != 0 && data->ip_proto != rule->proto) {
            rule_match = false;
        }
        
        // Check ports for TCP/UDP
        if (rule_match && (data->ip_proto == IPPROTO_TCP || data->ip_proto == IPPROTO_UDP)) {
            // Check source port if specified
            if (rule->src_port != 0 && data->sport != rule->src_port) {
                rule_match = false;
            }
            
            // Check destination port if specified
            if (rule_match && rule->dst_port != 0 && data->dport != rule->dst_port) {
                rule_match = false;
            }
        }
        
        // If direct match succeeds
        if (rule_match) {
            goto filter_match;
        }
        
        // Try reverse direction match (for connection tracking)
        rule_match = true;
        
        // Swap src/dst in filter check
        if (rule->dst_ip != 0 && data->saddr != rule->dst_ip) {
            rule_match = false;
        }
        
        if (rule_match && rule->src_ip != 0 && data->daddr != rule->src_ip) {
            rule_match = false;
        }
        
        // Protocol stays the same
        if (rule_match && rule->proto != 0 && data->ip_proto != rule->proto) {
            rule_match = false;
        }
        
        // Swap ports for TCP/UDP
        if (rule_match && (data->ip_proto == IPPROTO_TCP || data->ip_proto == IPPROTO_UDP)) {
            // Check destination port against src_port
            if (rule->src_port != 0 && data->dport != rule->src_port) {
                rule_match = false;
            }
            
            // Check source port against dst_port
            if (rule_match && rule->dst_port != 0 && data->sport != rule->dst_port) {
                rule_match = false;
            }
        }
        
        // If reverse direction match succeeds
        if (rule_match) {
            goto filter_match;
        }
    }
    
    // If we get here, no rules matched
    return 0;
    
filter_match: 
    u64 skb_nfct_val = 0;
    // Extract nfct information
    bpf_probe_read_kernel(&skb_nfct_val, sizeof(skb_nfct_val), &skb->_nfct);
    data->nfct_ptr = skb_nfct_val;
    data->ctinfo = (u32)(skb_nfct_val & NFCT_INFOMASK);

    if (skb_nfct_val != 0) {
        struct nf_conn *tmpl_bpf = (struct nf_conn *)(skb_nfct_val & NFCT_PTRMASK);
        if (tmpl_bpf != NULL) {
            if (bpf_probe_read_kernel(&data->ct_status, sizeof(data->ct_status), &tmpl_bpf->status) < 0) {
                data->ct_status = (u64)-2;
            }
        } else {
            data->ct_status = (u64)-3;
        }
    } else {
        data->ct_status = (u64)-4;
    }

    // Setup common fields
    data->timestamp_ns = bpf_ktime_get_ns();
    data->stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->retval = -999;

    return 1;
}

static inline int check_filters_and_submit_entry(struct pt_regs *ctx, struct sk_buff *skb, u32 probe_id) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    data.probe_id = probe_id;
    events.perf_submit(ctx, &data, sizeof(data));
    return 1;
}

int trace_nf_conntrack_in(struct pt_regs *ctx, void *net, u8 pf, u32 hooknum, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_CONNTRACK_IN);
    return 0;
}

int trace_ovs_ct_lookup(struct pt_regs *ctx, void *net, void *key, void *info_ptr, struct sk_buff *skb) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    // Parse ovs_conntrack_info from this probe
    const struct ovs_conntrack_info *info = (const struct ovs_conntrack_info *)info_ptr;
    parse_ovs_conntrack_info(info, &data);
    
    data.probe_id = PROBE_ID_OVS_CT_LOOKUP;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, const struct ovs_conntrack_info *info_ptr, void *key, bool post_ct, bool keep_nat_flags) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    // Parse ovs_conntrack_info from this probe
    parse_ovs_conntrack_info(info_ptr, &data);
    
    data.probe_id = PROBE_ID_OVS_CT_UPDATE;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_nf_ct_refresh_acct(struct pt_regs *ctx, void *ct_ptr, int ctinfo, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_REFRESH_ACCT);
    return 0;
}

// Parse nf_conn fields (for tcp_packet and tcp_error probes)
static inline void parse_nf_conn_fields(struct nf_conn *ct, struct data_t *data) {
    if (ct == NULL) {
        return;
    }
    
    // Parse nf_conn->zone using the proper structure from the header file
    struct nf_conntrack_zone zone;
    
    if (bpf_probe_read_kernel(&zone, sizeof(zone), &ct->zone) == 0) {
        //bpf_trace_printk("zone.id: %%d, zone.dir: %%d\\n", zone.id, zone.dir);
        data->zone_id = zone.id;
        data->zone_dir = zone.dir;
        // You can access zone.flags if needed in the future
    }
    
    // Read ct_status
    if (bpf_probe_read_kernel(&data->ct_status, sizeof(data->ct_status), &ct->status) < 0) {
        data->ct_status = (u64)-5; // Indicate failed to read ct->status
    }
}

int trace_tcp_packet(struct pt_regs *ctx, struct nf_conn *ct, struct sk_buff *skb) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    // Parse nf_conn fields
    parse_nf_conn_fields(ct, &data);
    
    data.probe_id = PROBE_ID_TCP_PACKET;
    events.perf_submit(ctx, &data, sizeof(data));
    
    // Set filter decision for return probe
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filter_decision_t decision = {.should_trace = true};
    entry_filter_decision.update(&pid_tgid, &decision);
    
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

int trace_tcp_error(struct pt_regs *ctx, void *net, struct nf_conn *tmpl, struct sk_buff *skb) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    // Parse nf_conn fields
    parse_nf_conn_fields(tmpl, &data);
    
    data.probe_id = PROBE_ID_TCP_ERROR;
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

int trace_ovs_ct_execute(struct pt_regs *ctx, void *net, struct sk_buff *skb, void *key, const void *info_ptr) {
    struct data_t data = {};
    
    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }
    
    // Parse ovs_conntrack_info from this probe
    const struct ovs_conntrack_info *info = (const struct ovs_conntrack_info *)info_ptr;
    parse_ovs_conntrack_info(info, &data);
    
    data.probe_id = PROBE_ID_OVS_CT_EXECUTE;
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
        ("tcp_state", ct.c_uint8),
        ("ifindex", ct.c_uint32),
        ("devname", ct.c_char * 16),
        ("ip_id", ct.c_uint16),
        ("tcp_seq", ct.c_uint32),
        ("tcp_ack", ct.c_uint32),
    ]

bpf_text_final = bpf_text % (MAX_FILTER_RULES, num_filters)


cflags = []        # 不能用 v3/v4
try:
    # Pass cflags during BPF object initialization
    b = BPF(text=bpf_text_final, cflags=cflags)
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
start_time = time.time()  # Record wall clock time when we start

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
        
        # Add IP ID to every packet
        pkt_id_info = "IP_ID:0x%x" % event.ip_id
        
        # TCP状态信息
        tcp_state_str = ""
        if event.ip_proto == socket.IPPROTO_TCP:
            tcp_state_map = {
                1: "TCP_ESTABLISHED",
                2: "TCP_SYN_SENT",
                3: "TCP_SYN_RECV",
                4: "TCP_FIN_WAIT1",
                5: "TCP_FIN_WAIT2",
                6: "TCP_TIME_WAIT",
                7: "TCP_CLOSE",
                8: "TCP_CLOSE_WAIT",
                9: "TCP_LAST_ACK",
                10: "TCP_LISTEN",
                11: "TCP_CLOSING",
                12: "TCP_NEW_SYN_RECV",
            }
            tcp_state_str = tcp_state_map.get(event.tcp_state, "UNKNOWN_STATE(%d)" % event.tcp_state)
            
            # Add TCP sequence/ACK for TCP packets
            pkt_id_info += " SEQ:%u ACK:%u" % (event.tcp_seq, event.tcp_ack)
        
        if event.ip_proto in [socket.IPPROTO_TCP, socket.IPPROTO_UDP] and event.sport != 0:
            pkt_info = "%s:%d -> %s:%d (%s) %s" % (
                saddr_str, event.sport,
                daddr_str, event.dport,
                proto_str,
                pkt_id_info
            )
            # 为TCP包添加状态信息
            if tcp_state_str:
                pkt_info += " [%s]" % tcp_state_str
        else:
            pkt_info = "%s -> %s (%s) %s" % (
                saddr_str,
                daddr_str,
                proto_str,
                pkt_id_info
            )
            # 为TCP包添加状态信息
            if tcp_state_str:
                pkt_info += " [%s]" % tcp_state_str
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

    # Show ct_status for all probe points, not just probe_id 1
    status_info = ""
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

    # Show ctinfo for all probe points, not just probe_id 1
    ctinfo_str = ""
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

    # Show ovs_conntrack_info related fields for all OVS-related probe points (2, 3, 9)
    ovs_info_str = ""
    is_ovs_probe = event.probe_id in [2, 3, 9]  # __ovs_ct_lookup, ovs_ct_update_key, ovs_ct_execute
    if is_ovs_probe:
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

    is_tcp_probe = event.probe_id in [6, 8]  # tcp_packet, tcp_error
    if is_tcp_probe:
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
            
        # Add the zone information to the output
        if not ovs_info_str:
            # should ct info str
            ovs_info_str = "%s %s" % (zone_id_str, zone_dir_str)

    # Format device information
    dev_info = ""
    if not is_return_probe:
        if event.ifindex != 0:
            dev_name = event.devname.decode('utf-8', 'replace').strip('\x00')
            if dev_name:
                dev_info = "DEV: %s[%d]" % (dev_name, event.ifindex)
            else:
                dev_info = "DEV: ifidx=%d" % event.ifindex
        else:
            dev_info = "DEV: N/A"

    if args.rel_time:
        time_str = "%-9.4f" % time_s
    else:
        time_str = kernel_ns_to_datetime(event.timestamp_ns).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    print("%s %s COMM: %-16s FUNC: %-25s %s %s %s %s %s %s %s" % (
        "TIME(s):" if args.rel_time else "DATETIME:",
        time_str,
        comm, probe_name, nfct_info, pkt_info, retval_info, status_info, ctinfo_str, ovs_info_str, dev_info))

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