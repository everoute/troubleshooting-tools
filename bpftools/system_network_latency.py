#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# 注意事项：
#   1) 如果是 oe 系统:
#      a) 请修改第一行 python2 为 python3:  #!/usr/bin/env python2  ->  #!/usr/bin/env python3
#      b) 修改 from bcc import BPF 为 from bpfcc import BPF
#   2) 如果是 el7 系统:
#      a) 安装 bcc 和 python-bcc 0.21.0:
# curl -fLO http://192.168.24.6/tmp/bpftools/x86_64/bcc-0.21.0-1.el7.x86_64.rpm
# curl -fLO http://192.168.24.6/tmp/bpftools/noarch/python-bcc-0.21.0-1.el7.noarch.rpm 
# rpm -ivh bcc-0.21.0-1.el7.x86_64.rpm python-bcc-0.21.0-1.el7.noarch.rpm --force 

# 使用说明:
# ./icmp_rtt_latency.py --help (Updated for L4 tracing)
# usage: icmp_rtt_latency.py [-h] --src-ip SRC_IP --dst-ip DST_IP
#                            --protocol {tcp,udp,icmp}
#                            [--src-port SRC_PORT] [--dst-port DST_PORT]
#                            --phy-iface1 PHY_IFACE1 [--phy-iface2 PHY_IFACE2]
#                            [--latency-ms LATENCY_MS]
#                            [--direction {outgoing,incoming}]
#                            [--disable-kernel-stacks]

# Trace L4 (TCP, UDP, ICMP) latency through the Linux network stack and OVS.
# For TCP/UDP, traces single direction (TX or RX path). For ICMP, RTT.

# optional arguments:
#   -h, --help            show this help message and exit
#   --src-ip SRC_IP       Primary IP of the host where this script runs.
#                         For "outgoing", this is the source. For "incoming", this is the destination.
#   --dst-ip DST_IP       Secondary IP involved in the trace.
#                         For "outgoing", this is the destination. For "incoming", this is the source.
#   --protocol {tcp,udp,icmp}
#                         Protocol to trace.
#   --src-port SRC_PORT   Source port for TCP/UDP (default: 0, wildcard).
#   --dst-port DST_PORT   Destination port for TCP/UDP (default: 0, wildcard).
#   --phy-iface1 PHY_IFACE1
#                         First physical interface to monitor.
#   --phy-iface2 PHY_IFACE2
#                         Second physical interface to monitor (optional).
#   --latency-ms LATENCY_MS
#                         Minimum latency threshold in ms to report (default: 0).
#   --direction {outgoing,incoming}
#                         Direction of trace: "outgoing" (TX path from src-ip)
#                         or "incoming" (RX path to src-ip). Default: outgoing.
#                         For ICMP, "outgoing" traces local ping RTT, "incoming" traces RTT of ping to local.
#   --disable-kernel-stacks
#                         Disable printing of kernel stack traces.

# Examples:
#   Outgoing TCP from 192.168.1.10:12345 to 192.168.1.20:80:
#     sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                                --protocol tcp --src-port 12345 --dst-port 80 \
#                                --phy-iface1 eth0 --direction outgoing
#
#   Incoming UDP to 192.168.1.10:5000 from any source:
#     sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 0.0.0.0 \
#                                --protocol udp --dst-port 5000 \
#                                --phy-iface1 eth0 --direction incoming

# ... (rest of original comments can be adapted later) ...
#
# This tool traces the specified L4 protocol traffic:
# - For TCP/UDP "outgoing": Application -> Protocol Stack -> OVS -> Physical NIC
# - For TCP/UDP "incoming": Physical NIC -> OVS -> Protocol Stack -> Application
# - For ICMP: full RTT as before.
#
# It identifies matching packets/flows and reports segment latencies.


from bcc import BPF
#from bpfcc import BPF
from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl # Needed for ioctl


bpf_text = """
#include <linux/tcp.h>
#include <linux/udp.h>

# User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d // network byte order
#define DST_PORT_FILTER %d // network byte order
#define PROTOCOL_FILTER %d // 6 for TCP, 17 for UDP, 1 for ICMP
#define LATENCY_THRESHOLD_NS %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define TRACE_DIRECTION %d // 0 for Outgoing (default), 1 for Incoming

# For ICMP RTT, we still need two paths of stages.
# For TCP/UDP single direction, we use one path of stages.
# MAX_STAGES_PER_PATH should be enough for one direction of TCP/UDP or one leg of ICMP.
#define MAX_STAGES_PER_PATH      10 // Max stages for a single TX or RX path, or one ICMP leg

// ICMP stages (original, can be reused if PROTOCOL_FILTER is ICMP)
#define ICMP_PATH1_STAGE_0    0
#define ICMP_PATH1_STAGE_1    1
#define ICMP_PATH1_STAGE_2    2
#define ICMP_PATH1_STAGE_3    3
#define ICMP_PATH1_STAGE_4    4
#define ICMP_PATH1_STAGE_5    5
#define ICMP_PATH1_STAGE_6    6 // End of ICMP Path 1 (TX request or RX request)

#define ICMP_PATH2_STAGE_0    (MAX_STAGES_PER_PATH + 0) // Start of ICMP Path 2 (e.g. 10)
#define ICMP_PATH2_STAGE_1    (MAX_STAGES_PER_PATH + 1)
#define ICMP_PATH2_STAGE_2    (MAX_STAGES_PER_PATH + 2)
#define ICMP_PATH2_STAGE_3    (MAX_STAGES_PER_PATH + 3)
#define ICMP_PATH2_STAGE_4    (MAX_STAGES_PER_PATH + 4)
#define ICMP_PATH2_STAGE_5    (MAX_STAGES_PER_PATH + 5)
#define ICMP_PATH2_STAGE_6    (MAX_STAGES_PER_PATH + 6) // End of ICMP Path 2 (RX reply or TX reply)

// TCP/UDP Single Direction Stages (conceptual, relative 0 to N-1)
// Actual stage IDs will be mapped carefully.
// Example: TCP Outgoing
#define TCP_OUT_S0_SENDMSG   0
#define TCP_OUT_S1_XMITSKB   1
#define TCP_OUT_S2_IPQUEUE   2 // e.g. ip_queue_xmit
#define TCP_OUT_S3_OVS_DP    3 // (example, map to existing OVS logic)
#define TCP_OUT_S4_OVS_VPORT 4 // (example)
#define TCP_OUT_S5_DEVQ      5 // dev_queue_xmit (final)
#define TCP_OUT_NUM_STAGES   6

// Example: TCP Incoming
#define TCP_IN_S0_NETRECV    0 // __netif_receive_skb
#define TCP_IN_S1_NETHOOK    1 // netdev_frame_hook
#define TCP_IN_S2_OVS_DP     2 // (example)
#define TCP_IN_S3_IPRCV      3 // ip_rcv
#define TCP_IN_S4_TCPRCV     4 // tcp_v4_rcv
#define TCP_IN_S5_ESTABL     5 // tcp_rcv_established (final)
#define TCP_IN_NUM_STAGES    6

// UDP stages similarly...

#define MAX_TOTAL_STAGES         (2 * MAX_STAGES_PER_PATH) // For ICMP RTT (e.g. 20) or single TCP/UDP path (uses up to MAX_STAGES_PER_PATH)
#define IFNAMSIZ                 16
#define TASK_COMM_LEN            16


// Packet key structure
// New design with union to avoid confusion between TCP/UDP and ICMP fields
struct packet_key_t {
    __be32 sip;    // Source IP (canonical)
    __be32 dip;    // Destination IP (canonical)
    union {
        struct {
            __be16 sport;  // TCP/UDP source port
            __be16 dport;  // TCP/UDP destination port
        } l4;
        struct {
            __be16 id;     // ICMP ID 
            __be16 seq;    // ICMP sequence number
        } icmp;
    };
};

// Structure to track flow data
struct flow_data_t {
    u64 ts[MAX_TOTAL_STAGES];
    u64 skb_ptr[MAX_TOTAL_STAGES]; // sk_ptr for sock probes
    int kstack_id[MAX_TOTAL_STAGES];
    
    // Info for the primary path (Path1 for ICMP RTT, or the single TCP/UDP path)
    u32 p_pid;
    char p_comm[TASK_COMM_LEN];
    char p_ifname[IFNAMSIZ];
    
    // Info for ICMP Path 2 (reply path) - only used if PROTOCOL_FILTER == ICMP
    u32 p2_pid;
    char p2_comm[TASK_COMM_LEN];
    char p2_ifname[IFNAMSIZ];
        
    // ICMP type info (only for ICMP)
    u8 request_type;
    u8 reply_type;
    
    // Flags
    u8 saw_path_start:1;  // For TCP/UDP single path, or ICMP Path1
    u8 saw_path_end:1;    // For TCP/UDP single path, or ICMP Path1
    u8 saw_path2_start:1; // Only for ICMP Path2
    u8 saw_path2_end:1;   // Only for ICMP Path2

    u8 final_stage_id_for_trace; // Stores the actual final stage ID for this specific flow type (TCP out, UDP in, etc.)
    u8 start_stage_id_for_trace; // Stores the actual start stage ID
};

// Structure for perf event output
struct event_data_t {
    struct packet_key_t key;
    struct flow_data_t data;
};

BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);

// Helper function to check if an interface index matches our targets
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}

// Function to manually parse SKB data coming from userspace (different structure)
// This was for ovs_flow_key_extract_userspace, might need review for TCP/UDP if that probe is used.
static __always_inline int parse_packet_key_userspace_icmp(struct sk_buff *skb, struct packet_key_t *key,
                                                     u8 *icmp_type_out, int path_is_primary) {
    // This function is ICMP specific, based on its logic (ICMP_ECHO/ECHOREPLY)
    // It will only be called if PROTOCOL_FILTER == ICMP
    if (skb == NULL) {
        return 0;
    }

    unsigned char *skb_head;
    if(bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }
    
    unsigned long skb_data_ptr_val; 
    if(bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);

    unsigned int mac_offset = data_offset; 
    
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    
    __be16 h_proto = eth.h_proto;
    
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        net_offset += VLAN_HLEN; 
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 0;
        }
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
             net_offset += VLAN_HLEN;
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + (2 * VLAN_HLEN) + 2) < 0) {
                 return 0;
             }
        }
    }

    
    if (h_proto != htons(ETH_P_IP)) {
        return 0;
    }
    
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0) {
        return 0;
    }
    
    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    u8 expected_icmp_type_val;

    if (path_is_primary) { 
        if (!(actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)) return 0;
        expected_icmp_type_val = ICMP_ECHO;
    } else { 
        if (!(actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)) return 0;
        expected_icmp_type_val = ICMP_ECHOREPLY;
    }
    
    if (ip.protocol != IPPROTO_ICMP) {
        return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    // Calculate transport offset based on net_offset and ip_ihl
    unsigned int trans_offset = net_offset + (ip_ihl * 4);
    
    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset) < 0) {
        return 0;
    }

    if (icmph.type != expected_icmp_type_val) {
        return 0;
    }

    *icmp_type_out = icmph.type;
    key->sip = SRC_IP_FILTER; 
    key->dip = DST_IP_FILTER;
    key->proto = ip.protocol; 
    key->icmp.id = icmph.un.echo.id;
    key->icmp.seq = icmph.un.echo.sequence;

    return 1;
}

// Generic skb parser for TCP/UDP/ICMP packet identification and key creation
static __always_inline int get_key_from_skb(struct sk_buff *skb, struct packet_key_t *pkt_key_out, u8 *icmp_type_out_opt) {
    if (!skb) return 0;

    unsigned char *head;
    u16 network_header_offset, transport_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        return 0;
    }
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) return 0;

    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header_offset) < 0) return 0;

    if (iph.protocol != PROTOCOL_FILTER) return 0; // Filter by protocol first

    // IP address filtering (applies to all protocols)
    // Canonical IPs: SRC_IP_FILTER is local, DST_IP_FILTER is remote for the trace
    bool ip_match = false;
    if (TRACE_DIRECTION == 0) { // Outgoing: skb: src=local, dst=remote
        if (iph.saddr == SRC_IP_FILTER && (DST_IP_FILTER == 0 || iph.daddr == DST_IP_FILTER)) {
            ip_match = true;
            pkt_key_out->sip = SRC_IP_FILTER;
            pkt_key_out->dip = DST_IP_FILTER == 0 ? iph.daddr : DST_IP_FILTER;
        }
    } else { // Incoming: skb: src=remote, dst=local
        if (iph.daddr == SRC_IP_FILTER && (DST_IP_FILTER == 0 || iph.saddr == DST_IP_FILTER)) {
            ip_match = true;
            pkt_key_out->sip = SRC_IP_FILTER; // local
            pkt_key_out->dip = DST_IP_FILTER == 0 ? iph.saddr : DST_IP_FILTER; // remote
        }
    }
    if (!ip_match) return 0;

    u8 ip_ihl = iph.ihl & 0x0F;
    if (ip_ihl < 5) return 0;
    
    // If transport_header_offset is not set by kernel (e.g. for some early stages or fragmented packets)
    // try to calculate it from ip_ihl.
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }


    if (PROTOCOL_FILTER == IPPROTO_ICMP) {
        struct icmphdr icmph;
        if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) < 0) return 0;

        u8 expected_icmp_type;
        // For ICMP, TRACE_DIRECTION determines if we expect ECHO (path1) or ECHOREPLY (path2-like)
        // This logic becomes tricky with single direction trace for TCP/UDP vs RTT for ICMP.
        // Let's simplify: outgoing trace expects ECHO, incoming trace expects ECHOREPLY (as the *trigger*)
        // The original code had path_is_primary which mapped to this.
        bool is_path1_equivalent = false; // Is this the "request" part of the flow
        if (TRACE_DIRECTION == 0 && iph.saddr == SRC_IP_FILTER) is_path1_equivalent = true; // Outgoing request
        if (TRACE_DIRECTION == 1 && iph.daddr == SRC_IP_FILTER) is_path1_equivalent = true; // Incoming request

        if (is_path1_equivalent) expected_icmp_type = ICMP_ECHO;
        else expected_icmp_type = ICMP_ECHOREPLY; // This is for the reply part of an RTT

        if (icmph.type != expected_icmp_type) {
             // If it's an RTT trace, we might see the other type on the other path.
             // This needs to be handled by the stage logic. For now, match one type.
             // This simple check might be insufficient for full ICMP RTT logic if we are at a common probe.
             // The original parse_packet_key had 'path_is_primary' to distinguish.
        }


        if (icmp_type_out_opt) *icmp_type_out_opt = icmph.type;
        pkt_key_out->icmp.id = icmph.un.echo.id;
        pkt_key_out->icmp.seq = icmph.un.echo.sequence;
        return 1;

    } else if (PROTOCOL_FILTER == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header_offset) < 0) return 0;
        
        bool port_match = false;
        if (TRACE_DIRECTION == 0) { // Outgoing: key.sport=local_cfg, key.dport=remote_cfg
            if ((SRC_PORT_FILTER == 0 || tcph.source == SRC_PORT_FILTER) &&
                (DST_PORT_FILTER == 0 || tcph.dest == DST_PORT_FILTER)) {
                port_match = true;
                pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? tcph.source : SRC_PORT_FILTER;
                pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? tcph.dest : DST_PORT_FILTER;
            }
        } else { // Incoming: key.sport=local_cfg, key.dport=remote_cfg (remote is tcph.source)
            if ((SRC_PORT_FILTER == 0 || tcph.dest == SRC_PORT_FILTER) &&
                (DST_PORT_FILTER == 0 || tcph.source == DST_PORT_FILTER)) {
                port_match = true;
                pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? tcph.dest : SRC_PORT_FILTER;
                pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? tcph.source : DST_PORT_FILTER;
            }
        }
        return port_match ? 1 : 0;

    } else if (PROTOCOL_FILTER == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset) < 0) return 0;

        bool port_match = false;
        if (TRACE_DIRECTION == 0) {
            if ((SRC_PORT_FILTER == 0 || udph.source == SRC_PORT_FILTER) &&
                (DST_PORT_FILTER == 0 || udph.dest == DST_PORT_FILTER)) {
                port_match = true;
                pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? udph.source : SRC_PORT_FILTER;
                pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? udph.dest : DST_PORT_FILTER;
            }
        } else { // Incoming
            if ((SRC_PORT_FILTER == 0 || udph.dest == SRC_PORT_FILTER) &&
                (DST_PORT_FILTER == 0 || udph.source == DST_PORT_FILTER)) {
                port_match = true;
                pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? udph.dest : SRC_PORT_FILTER;
                pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? udph.source : DST_PORT_FILTER;
            }
        }
        return port_match ? 1 : 0;
    }
    return 0; // Unknown protocol or not matched
}

// Placeholder: Get key from sock structure (for tcp_sendmsg, udp_sendmsg etc.)
static __always_inline int get_key_from_sock(struct sock *sk, struct packet_key_t *pkt_key_out) {
    if (!sk) return 0;

    u16 sk_family, sk_sport_val, sk_dport_val;
    __be32 sk_saddr_val, sk_daddr_val;
    u8 sk_protocol;

    bpf_probe_read_kernel(&sk_family, sizeof(sk_family), &sk->sk_family);
    if (sk_family != AF_INET) return 0;

    // Read details from sock_common
    struct sock_common skc;
    bpf_probe_read_kernel(&skc, sizeof(skc), &sk->sk_common);

    sk_protocol = skc.skc_prot->type; // This requires kernel CONFIG_BPF_KPROBE_OVERRIDE or careful access
                                      // For simplicity, assume PROTOCOL_FILTER matches the kprobe context.
                                      // Or, pass protocol from kprobe.
    if (sk_protocol != PROTOCOL_FILTER) { 
        // A check here, or assume the kprobe (e.g. kprobe__tcp_sendmsg) is protocol specific.
        // return 0; 
    }


    sk_saddr_val = skc.skc_rcv_saddr; // Local address for listener, or bound local address
    sk_daddr_val = skc.skc_daddr;     // Remote address
    sk_sport_val = skc.skc_num;       // Local port (host byte order for skc.skc_num)
    sk_dport_val = skc.skc_dport;     // Remote port (network byte order for skc.skc_dport)


    // Apply IP filters
    bool ip_match = false;
    if (TRACE_DIRECTION == 0) { // Outgoing: sock has local=src, remote=dst
        if (sk_saddr_val == SRC_IP_FILTER && (DST_IP_FILTER == 0 || sk_daddr_val == DST_IP_FILTER)) {
            ip_match = true;
            pkt_key_out->sip = SRC_IP_FILTER;
            pkt_key_out->dip = DST_IP_FILTER == 0 ? sk_daddr_val : DST_IP_FILTER;
        }
    } else { // Incoming: sock has local=dst, remote=src (typically for established sockets)
             // For a pure RX trace starting from NIC, sock probes are less common as initial triggers.
             // If used for e.g. tcp_rcv_established, IPs should match.
        if (sk_daddr_val == SRC_IP_FILTER && (DST_IP_FILTER == 0 || sk_saddr_val == DST_IP_FILTER)) {
            ip_match = true;
            pkt_key_out->sip = SRC_IP_FILTER; // local (dst for incoming packet)
            pkt_key_out->dip = DST_IP_FILTER == 0 ? sk_saddr_val : DST_IP_FILTER; // remote (src for incoming packet)
        }
    }
    if (!ip_match) return 0;

    // Apply port filters (convert sk_sport_val to network order for comparison if needed)
    // skc_num is host byte order, skc_dport is network byte order.
    // SRC_PORT_FILTER and DST_PORT_FILTER are expected in network byte order from Python.
    __be16 local_port_from_sock_net = htons(sk_sport_val);
    __be16 remote_port_from_sock_net = sk_dport_val;


    bool port_match = false;
    if (TRACE_DIRECTION == 0) { // Outgoing from sock perspective
        if ((SRC_PORT_FILTER == 0 || local_port_from_sock_net == SRC_PORT_FILTER) &&
            (DST_PORT_FILTER == 0 || remote_port_from_sock_net == DST_PORT_FILTER)) {
            port_match = true;
            pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? local_port_from_sock_net : SRC_PORT_FILTER;
            pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? remote_port_from_sock_net : DST_PORT_FILTER;
        }
    } else { // Incoming to sock perspective
        // Here, the "source" port of the filter is the sock's local port (destination of packet)
        // and "destination" port of the filter is the sock's remote port (source of packet)
        if ((SRC_PORT_FILTER == 0 || local_port_from_sock_net == SRC_PORT_FILTER) &&
            (DST_PORT_FILTER == 0 || remote_port_from_sock_net == DST_PORT_FILTER)) {
            port_match = true;
            pkt_key_out->l4.sport = SRC_PORT_FILTER == 0 ? local_port_from_sock_net : SRC_PORT_FILTER;
            pkt_key_out->l4.dport = DST_PORT_FILTER == 0 ? remote_port_from_sock_net : DST_PORT_FILTER;
        }
    }
    return port_match ? 1 : 0;
}


// Generalized event handler
// stage_id is relative to the specific trace type (e.g., 0 to TCP_OUT_NUM_STAGES-1)
// actual_final_stage_id is the last stage_id for this specific trace (e.g. TCP_OUT_S5_DEVQ)
static __always_inline void handle_event(struct pt_regs *ctx, void *entity_ptr, // skb or sock
                                         u8 stage_id, bool is_sock_probe,
                                         bool is_start_stage, bool is_final_stage,
                                         u8 actual_start_stage_id_val, u8 actual_final_stage_id_val,
                                         u8 icmp_type_val_opt // Only for ICMP path init
                                         ) {
    struct packet_key_t pkt_key = {};
    int key_valid = 0;
    if (is_sock_probe) {
        key_valid = get_key_from_sock((struct sock *)entity_ptr, &pkt_key);
    } else {
        // For ICMP, the icmp_type_out might be needed by get_key_from_skb
        // but get_key_from_skb is now generic.
        // The original parse_packet_key had complex logic for this.
        // Let's pass icmp_type_val_opt to get_key_from_skb if it needs it for ICMP.
        u8 icmp_type_holder; // Temporary for icmp_type output if needed by get_key_from_skb
        key_valid = get_key_from_skb((struct sk_buff *)entity_ptr, &pkt_key, &icmp_type_holder);
        if (PROTOCOL_FILTER == IPPROTO_ICMP && is_start_stage) {
            // icmp_type_val_opt is passed by ICMP start kprobes to initialize flow_data request_type
        }
    }

    if (!key_valid) return;

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;

    if (is_start_stage) {
        struct flow_data_t zero = {}; // Initialize all fields to zero
        zero.start_stage_id_for_trace = actual_start_stage_id_val;
        zero.final_stage_id_for_trace = actual_final_stage_id_val;

        flow_sessions.delete(&pkt_key);
        flow_ptr = flow_sessions.lookup_or_try_init(&pkt_key, &zero);
        if (flow_ptr) {
            flow_ptr->saw_path_start = 1;
            flow_ptr->p_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p_comm, sizeof(flow_ptr->p_comm));
            if (!is_sock_probe) {
                struct net_device *dev;
                char if_name_buffer[IFNAMSIZ];
                __builtin_memset(if_name_buffer, 0, IFNAMSIZ);
                if (bpf_probe_read_kernel(&dev, sizeof(dev), &((struct sk_buff *)entity_ptr)->dev) == 0 && dev != NULL) {
                    bpf_probe_read_kernel_str(if_name_buffer, IFNAMSIZ, dev->name);
                } else {
                    char unk[] = "unknown";
                    bpf_probe_read_kernel_str(if_name_buffer, sizeof(unk), unk);
                }
                bpf_probe_read_kernel_str(flow_ptr->p_ifname, IFNAMSIZ, if_name_buffer);
            } else {
                 char sock_str[] = "sock";
                 bpf_probe_read_kernel_str(flow_ptr->p_ifname, sizeof(sock_str), sock_str);
            }
            if (PROTOCOL_FILTER == IPPROTO_ICMP) {
                flow_ptr->request_type = icmp_type_val_opt; // Passed by ICMP kprobe
            }
        }
    } else {
        flow_ptr = flow_sessions.lookup(&pkt_key);
    }

    if (!flow_ptr) return;

    // Record current stage if timestamp is not already set (first hit for this stage)
    // Stage IDs are relative to the trace type (0 to N-1). MAX_STAGES_PER_PATH is the array size.
    if (stage_id < MAX_STAGES_PER_PATH && flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)entity_ptr;
        flow_ptr->kstack_id[stage_id] = stack_id;
    }

    if (is_final_stage) {
        flow_ptr->saw_path_end = 1;
    }

    // Check for completion for single-direction TCP/UDP or full RTT for ICMP
    bool completed = false;
    u64 latency_start_ts = 0;
    u64 latency_end_ts = 0;

    if (PROTOCOL_FILTER == IPPROTO_ICMP) {
        // ICMP RTT logic: uses saw_path1_start/end and saw_path2_start/end
        // This part needs to be more carefully reconstructed if we keep full ICMP RTT
        // For now, let's assume 'is_final_stage' for ICMP means end of Path2 (e.g. icmp_rcv for outgoing)
        // And 'is_start_stage' means start of Path1 (e.g. ip_send_skb for outgoing)
        // The stage_id for ICMP will be global (0..MAX_TOTAL_STAGES-1)
        
        // Simplified: if it's the final stage of the second leg of ICMP
        if (is_final_stage && flow_ptr->saw_path_start && flow_ptr->saw_path_end &&
            flow_ptr->saw_path2_start && flow_ptr->saw_path2_end) { // This implies ICMP stages are global
            
            // This logic is from old RTT, need to map stage_id to global ICMP stages
            // For example, if actual_final_stage_id_val is ICMP_PATH2_STAGE_6
            if (flow_ptr->ts[ICMP_PATH1_STAGE_0] > 0 && flow_ptr->ts[actual_final_stage_id_val] > 0) {
                 latency_start_ts = flow_ptr->ts[ICMP_PATH1_STAGE_0];
                 latency_end_ts = flow_ptr->ts[actual_final_stage_id_val];
                 completed = true;
            }
        }

    } else { // TCP or UDP (single direction)
        if (flow_ptr->saw_path_start && flow_ptr->saw_path_end && is_final_stage) {
            // actual_start_stage_id_val is the first stage (e.g. 0 for this path type)
            // actual_final_stage_id_val is the last stage for this path type
            if (flow_ptr->ts[actual_start_stage_id_val] > 0 && flow_ptr->ts[actual_final_stage_id_val] > 0) {
                latency_start_ts = flow_ptr->ts[actual_start_stage_id_val];
                latency_end_ts = flow_ptr->ts[actual_final_stage_id_val];
                completed = true;
            }
        }
    }
    
    if (completed) {
        if (LATENCY_THRESHOLD_NS > 0) {
            if (latency_start_ts == 0 || latency_end_ts == 0 || (latency_end_ts - latency_start_ts) < LATENCY_THRESHOLD_NS) {
                return; 
            }
        }
        
        u32 map_key_zero = 0; 
        struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_data_ptr) return; 
        
        event_data_ptr->key = pkt_key; 
        // Copy only relevant parts of flow_data for the perf event
        // e.g., flow_ptr->ts array up to actual_final_stage_id_val + 1 or MAX_STAGES_PER_PATH
        // and p_pid, p_comm etc.
        bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr);
        // Ensure copied data reflects the completed path
        // For TCP/UDP, only one path's info is relevant in flow_data_t.
        
        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
        flow_sessions.delete(&pkt_key); 
    } else if (is_final_stage && !completed) {
        // If it was marked final, but conditions for completion not met (e.g. start not seen)
        // This might indicate a logic error or missed start packet. Clean up to avoid stale entries.
        // flow_sessions.delete(&pkt_key); // Or let it timeout by LRU hash
    }
}


// --- KPROBE DEFINITIONS ---
// Kprobes need to be specific about protocol and direction checks
// and call handle_event with correct stage IDs, is_start, is_final flags.

// == TCP Outgoing Probes (Example) ==
// TRACE_DIRECTION == 0 (outgoing), PROTOCOL_FILTER == IPPROTO_TCP
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    if (PROTOCOL_FILTER != IPPROTO_TCP || TRACE_DIRECTION != 0) return 0;
    // actual_start_stage_id_val = TCP_OUT_S0_SENDMSG, actual_final_stage_id_val = TCP_OUT_S5_DEVQ
    handle_event(ctx, sk, TCP_OUT_S0_SENDMSG, true /*is_sock*/,
                 true /*is_start*/, false /*is_final*/,
                 TCP_OUT_S0_SENDMSG, TCP_OUT_S5_DEVQ, 0);
    return 0;
}

int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_TCP || TRACE_DIRECTION != 0) return 0;
    if (!skb) return 0;
    handle_event(ctx, skb, TCP_OUT_S1_XMITSKB, false /*!sock*/,
                 false /*!start*/, false /*!final*/,
                 TCP_OUT_S0_SENDMSG, TCP_OUT_S5_DEVQ, 0);
    return 0;
}
// ... other TCP outgoing probes for ip_queue_xmit, OVS stages ...

// Example of a common probe adapted for TCP Outgoing final stage:
int kprobe__dev_queue_xmit_tcp_out(struct pt_regs *ctx, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_TCP || TRACE_DIRECTION != 0) return 0;
    if (!is_target_ifindex(skb)) return 0;
    handle_event(ctx, skb, TCP_OUT_S5_DEVQ, false /*!sock*/,
                 false /*!start*/, true /*is_final*/,
                 TCP_OUT_S0_SENDMSG, TCP_OUT_S5_DEVQ, 0);
    return 0;
}


// == TCP Incoming Probes (Example Placeholder) ==
// TRACE_DIRECTION == 1 (incoming), PROTOCOL_FILTER == IPPROTO_TCP
int kprobe____netif_receive_skb_tcp_in(struct pt_regs *ctx, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_TCP || TRACE_DIRECTION != 1) return 0;
    if (!is_target_ifindex(skb)) return 0;
    handle_event(ctx, skb, TCP_IN_S0_NETRECV, false, true, false, TCP_IN_S0_NETRECV, TCP_IN_S5_ESTABL, 0);
    return 0;
}
// ... other TCP incoming probes for netdev_frame_hook, OVS, ip_rcv, tcp_v4_rcv ...
int kprobe__tcp_rcv_established_tcp_in(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_TCP || TRACE_DIRECTION != 1) return 0;
     // skb might be NULL here if it's just acks, or refers to skb on queue.
     // For latency, we'd ideally want the skb that contains data.
     // Using sk for keying if skb is not reliable for data packets here.
    void *entity = skb ? (void*)skb : (void*)sk;
    bool is_sock = skb ? false : true;
    handle_event(ctx, entity, TCP_IN_S5_ESTABL, is_sock, false, true, TCP_IN_S0_NETRECV, TCP_IN_S5_ESTABL, 0);
    return 0;
}

// == UDP Probes (Placeholders) ==
// ... similar structure for UDP outgoing and incoming ...


// == ICMP Probes (Original, need careful adaptation for new handle_event and stage model) ==
// For ICMP RTT, stage_id passed to handle_event should be global (0 to MAX_TOTAL_STAGES-1)
// is_start should be true for ICMP_PATH1_STAGE_0
// is_final should be true for ICMP_PATH2_STAGE_6
// actual_start_stage_id_val = ICMP_PATH1_STAGE_0
// actual_final_stage_id_val = ICMP_PATH2_STAGE_6

// Example: kprobe__ip_send_skb for ICMP
int kprobe__ip_send_skb_icmp(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_ICMP) return 0;
    u8 icmp_type = 0;
    // This function was dual purpose in original: Path1_S0 (outgoing) or Path2_S0 (incoming reply TX)
    // With new handle_event, need to be specific.

    if (TRACE_DIRECTION == 0) { // Outgoing ICMP (request path starts)
        // Here, this is ICMP_PATH1_STAGE_0
        // We need to get icmp_type from skb for flow_data->request_type
        // The old parse_packet_key did this based on path_is_primary.
        // Let's assume get_key_from_skb populates pkt_key, and we can get type separately if needed.

        handle_event(ctx, skb, ICMP_PATH1_STAGE_0, false,
                     true /*is_start*/, false /*is_final*/,
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, icmp_type /* pass parsed type */);
    } else { // Incoming ICMP (reply path starts, after local processing of request)
        // This is ICMP_PATH2_STAGE_0 (TX of reply)
         handle_event(ctx, skb, ICMP_PATH2_STAGE_0, false,
                     false /*!start of RTT*/, false /*!final of RTT*/, //This is start of path2, not start of RTT
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
        // Update flow_data saw_path2_start if this is the logic
        // This needs careful thought on how saw_path2_start is set.
        // Original: flow_ptr->p2_pid etc. set here for PATH2_STAGE_0.
    }
    return 0;
}

// Example: kprobe____netif_receive_skb for ICMP
int kprobe____netif_receive_skb_icmp(struct pt_regs *ctx, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_ICMP) return 0;
    if (!is_target_ifindex(skb)) return 0;
    
    if (TRACE_DIRECTION == 0) { // Outgoing trace, this is RX of ICMP reply (Path2)
        // This is ICMP_PATH2_STAGE_0
         handle_event(ctx, skb, ICMP_PATH2_STAGE_0, false,
                     false, false, 
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
        // Also set saw_path2_start for flow here
    } else { // Incoming trace, this is RX of ICMP request (Path1)
        // This is ICMP_PATH1_STAGE_0
        u8 actual_icmp_type_from_skb = 0; // Placeholder, parse properly
        handle_event(ctx, skb, ICMP_PATH1_STAGE_0, false,
                     true, false,
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, actual_icmp_type_from_skb);
    }
    return 0;
}


// Example: kprobe__icmp_rcv for ICMP (final stage for one of the paths)
int kprobe__icmp_rcv_icmp(struct pt_regs *ctx, struct sk_buff *skb) {
    if (PROTOCOL_FILTER != IPPROTO_ICMP) return 0;
    
    if (TRACE_DIRECTION == 0) { // Outgoing trace, icmp_rcv is end of RX reply path (Path2)
        // This is ICMP_PATH2_STAGE_6 (final stage of RTT)
        handle_event(ctx, skb, ICMP_PATH2_STAGE_6, false,
                     false, true /*is_final*/,
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
    } else { // Incoming trace, icmp_rcv is end of RX request path (Path1)
        // This is ICMP_PATH1_STAGE_6 (end of Path1, but not end of RTT)
        handle_event(ctx, skb, ICMP_PATH1_STAGE_6, false,
                     false, false, // Not final for RTT
                     ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
        // Set saw_path_end (for path1) here.
    }
    return 0;
}


// == Common Probes (OVS, dev_queue_xmit for non-final TCP/UDP, etc.) ==
// These need to dispatch to handle_event with protocol-specific stage IDs if they are part of a TCP/UDP path
// or with ICMP global stage IDs if part of ICMP path.

int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    // Example: if (PROTOCOL_FILTER == IPPROTO_TCP && TRACE_DIRECTION == 0) {
    //    handle_event(ctx, skb, TCP_OUT_S_SOME_OVS_ENTRY_STAGE, ...);
    // } else if (PROTOCOL_FILTER == IPPROTO_ICMP && TRACE_DIRECTION == 0) {
    //    handle_event(ctx, skb, ICMP_PATH1_STAGE_1, ...);
    // } // etc.
    return 0;
}

int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    // Similar dispatch logic
    return 0;
}

int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    // Similar dispatch logic
    return 0;
}
// ... and so on for other common probes like ovs_dp_upcall, ovs_vport_send etc.
// dev_queue_xmit would be a final stage for TCP/UDP outgoing, or ICMP Path2_S6 (TX reply for incoming)
// or ICMP Path1_S6 (TX request for outgoing).

// Fallback for original dev_queue_xmit if not handled by specific (e.g. tcp_out) one
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!is_target_ifindex(skb)) return 0;

    if (PROTOCOL_FILTER == IPPROTO_ICMP) {
        if (TRACE_DIRECTION == 0) { // Outgoing ICMP, dev_queue_xmit is for request (Path1 final)
            handle_event(ctx, skb, ICMP_PATH1_STAGE_6, false, false, false, /* not final for RTT */
                         ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
            // set saw_path_end for path1
        } else { // Incoming ICMP, dev_queue_xmit is for reply (Path2 final)
             handle_event(ctx, skb, ICMP_PATH2_STAGE_6, false, false, true, /* final for RTT */
                         ICMP_PATH1_STAGE_0, ICMP_PATH2_STAGE_6, 0);
        }
    }
    // If TCP/UDP outgoing, specific dev_queue_xmit_tcp_out (etc.) should handle it.
    // This generic one acts as a fallback or for protocols not yet fully specified.
    return 0;
}


// Original kprobes from icmp_rtt_latency.py that are not yet fully re-mapped:
// kprobe__ip_send_skb -> kprobe__ip_send_skb_icmp
// kprobe__internal_dev_xmit -> common, needs dispatch
// kprobe____netif_receive_skb -> kprobe____netif_receive_skb_icmp (and _tcp_in etc.)
// kprobe__netdev_frame_hook -> common, needs dispatch
// kprobe__ovs_dp_process_packet -> common, needs dispatch
// kprobe__ovs_dp_upcall -> common, needs dispatch
// kprobe__ovs_flow_key_extract_userspace -> This one used parse_packet_key_userspace_icmp.
//                                            If used for TCP/UDP, needs new user-space parser.
// kprobe__ovs_vport_send -> common, needs dispatch
// kprobe__dev_queue_xmit -> kprobe__dev_queue_xmit (generic), kprobe__dev_queue_xmit_tcp_out etc.
// kprobe__icmp_rcv -> kprobe__icmp_rcv_icmp


// The old parse_packet_key and parse_packet_key_userspace are now
// get_key_from_skb, get_key_from_sock, and parse_packet_key_userspace_icmp.
// The old handle_event is replaced by the new handle_event.
// All kprobe functions need to be reviewed to call the new handle_event with correct parameters.
// This is a partial refactoring. More kprobes and dispatch logic in common probes needed.

"""

# Constants
MAX_STAGES_PER_PATH = 10 # Max stages for one leg of trace (e.g. TCP TX path)
MAX_TOTAL_STAGES = 2 * MAX_STAGES_PER_PATH # For ICMP RTT or general buffer sizing
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# Define the TCP/UDP fields structure
class TcpUdpPorts(ctypes.Structure):
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
    ]

# Define the ICMP fields structure
class IcmpFields(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16),
    ]

# Define the union part
class L4IcmpUnion(ctypes.Union):
    _fields_ = [
        ("l4", TcpUdpPorts),
        ("icmp", IcmpFields),
    ]

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32), 
        ("dip", ctypes.c_uint32),
        ("_union", L4IcmpUnion),
    ]
    
    # Add property accessors for easier access to legacy field names
    @property
    def sport(self):
        return self._union.l4.sport
        
    @property
    def dport(self):
        return self._union.l4.dport
        
    @property
    def id(self):
        return self._union.icmp.id
        
    @property
    def seq(self):
        return self._union.icmp.seq

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * MAX_TOTAL_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_TOTAL_STAGES), # sk_ptr for sock probes
        ("kstack_id", ctypes.c_int * MAX_TOTAL_STAGES),
        
        ("p_pid", ctypes.c_uint32), # For primary path (TCP/UDP single path, or ICMP Path1)
        ("p_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p_ifname", ctypes.c_char * IFNAMSIZ),
        
        # Only for ICMP RTT's second path
        ("p2_pid", ctypes.c_uint32),
        ("p2_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p2_ifname", ctypes.c_char * IFNAMSIZ),

        ("request_type", ctypes.c_uint8),
        ("reply_type", ctypes.c_uint8),
        
        ("saw_path_start", ctypes.c_uint8, 1), 
        ("saw_path_end", ctypes.c_uint8, 1),
        ("saw_path2_start", ctypes.c_uint8, 1), # For ICMP Path2
        ("saw_path2_end", ctypes.c_uint8, 1),   # For ICMP Path2

        ("final_stage_id_for_trace", ctypes.c_uint8),
        ("start_stage_id_for_trace", ctypes.c_uint8)
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("data", FlowData)
    ]

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
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int) # BPF expects network byte order for filters
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def format_latency(ts_start, ts_end):
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0: # Only return N/A if one of the timestamps is actually zero
        return " N/A ".rjust(7)
    
    # Calculate delta, which can be negative if ts_end < ts_start
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(7)


def get_detailed_stage_name(stage_id, protocol, direction, is_icmp_path2=False):
    """Returns a detailed stage name including the BPF probe point."""
    # This function needs to be significantly expanded based on the new stage definitions
    # for TCP (outgoing/incoming) and UDP (outgoing/incoming), and ICMP.

    # Placeholder names for now
    # ICMP stages (global IDs)
    icmp_base_names = {
        0: "ICMP_P1:S0_INIT", 1: "ICMP_P1:S1_STACK_PROC", 2: "ICMP_P1:S2_OVS_DP_PROC",
        3: "ICMP_P1:S3_OVS_UPCALL", 4: "ICMP_P1:S4_OVS_KEYEXT", 5: "ICMP_P1:S5_OVS_VPORT_SND",
        6: "ICMP_P1:S6_FINAL",
        # Path 2 starts at MAX_STAGES_PER_PATH offset
        MAX_STAGES_PER_PATH + 0: "ICMP_P2:S0_INIT", MAX_STAGES_PER_PATH + 1: "ICMP_P2:S1_STACK_PROC", 
        MAX_STAGES_PER_PATH + 2: "ICMP_P2:S2_OVS_DP_PROC", MAX_STAGES_PER_PATH + 3: "ICMP_P2:S3_OVS_UPCALL",
        MAX_STAGES_PER_PATH + 4: "ICMP_P2:S4_OVS_KEYEXT", MAX_STAGES_PER_PATH + 5: "ICMP_P2:S5_OVS_VPORT_SND",
        MAX_STAGES_PER_PATH + 6: "ICMP_P2:S6_FINAL"
    }
    # TCP Outgoing stages (relative IDs 0-5)
    tcp_out_base_names = {
        0: "TCP_OUT:S0_SENDMSG", 1: "TCP_OUT:S1_XMIT_SKB", 2: "TCP_OUT:S2_IP_QUEUE",
        3: "TCP_OUT:S3_OVS_DP", 4: "TCP_OUT:S4_OVS_VPORT", 5: "TCP_OUT:S5_DEV_XMIT"
    }
    # TCP Incoming stages (relative IDs 0-5)
    tcp_in_base_names = {
        0: "TCP_IN:S0_NETRECV", 1: "TCP_IN:S1_NETHOOK", 2: "TCP_IN:S2_OVS_DP",
        3: "TCP_IN:S3_IPRCV", 4: "TCP_IN:S4_TCPRCV", 5: "TCP_IN:S5_ESTABL"
    }
    # UDP names similarly...

    # Probe mappings also need to be protocol/direction specific
    # probe_map_outgoing_icmp = { ... }
    # probe_map_incoming_icmp_path1 = { ... } (request leg)
    # probe_map_incoming_icmp_path2 = { ... } (reply leg)
    # probe_map_tcp_outgoing = { ... }
    # probe_map_tcp_incoming = { ... }

    base_name = "Unknown Stage %d" % stage_id
    probe_name = "N/A"

    if protocol == "icmp":
        base_name = icmp_base_names.get(stage_id, "ICMP Unknown Stage %d" % stage_id)
        # Probe name determination for ICMP would need original logic based on direction and if path1/path2
        # Example for ICMP (needs full mapping from original script if kept)
        if direction == "outgoing": # Local pings remote
            probe_map = { 0: "ip_send_skb", 6: "dev_queue_xmit", 
                          MAX_STAGES_PER_PATH + 0: "__netif_receive_skb", MAX_STAGES_PER_PATH + 6: "icmp_rcv"}
            probe_name = probe_map.get(stage_id, "N/A")
        else: # Remote pings local
            probe_map = { 0: "__netif_receive_skb", 6: "icmp_rcv", 
                          MAX_STAGES_PER_PATH + 0: "ip_send_skb", MAX_STAGES_PER_PATH + 6: "dev_queue_xmit"}
            probe_name = probe_map.get(stage_id, "N/A")

    elif protocol == "tcp":
        if direction == "outgoing":
            base_name = tcp_out_base_names.get(stage_id, "TCP_OUT Unknown Stage %d" % stage_id)
            probe_map_tcp_outgoing = {0: "tcp_sendmsg", 1: "__tcp_transmit_skb", 5:"dev_queue_xmit"} # Example
            probe_name = probe_map_tcp_outgoing.get(stage_id, "N/A")
        elif direction == "incoming":
            base_name = tcp_in_base_names.get(stage_id, "TCP_IN Unknown Stage %d" % stage_id)
            probe_map_tcp_incoming = {0: "__netif_receive_skb", 5: "tcp_rcv_established"} # Example
            probe_name = probe_map_tcp_incoming.get(stage_id, "N/A")
    # elif protocol == "udp": ...
        
    return "%s (%s)" % (base_name, probe_name)


def _print_latency_segment(start_idx, end_idx, flow_data, protocol, direction_str, label_suffix=""):
    """Helper function to print a single latency segment."""
    latency = format_latency(flow_data.ts[start_idx], flow_data.ts[end_idx])
    
    is_icmp_p2_start = protocol == "icmp" and start_idx >= MAX_STAGES_PER_PATH
    is_icmp_p2_end = protocol == "icmp" and end_idx >= MAX_STAGES_PER_PATH

    start_name = get_detailed_stage_name(start_idx, protocol, direction_str, is_icmp_p2_start)
    end_name = get_detailed_stage_name(end_idx, protocol, direction_str, is_icmp_p2_end)
    effective_label_suffix = " " + label_suffix if label_suffix else ""
    
    idx_part_str = "  [%2d->%-2d]" % (start_idx, end_idx) 
    stages_desc_str = "%s -> %s" % (start_name, end_name)
    
    stages_desc_padded_width = 105 
    
    print("%s %-*s: %s us%s" % (
        idx_part_str, 
        stages_desc_padded_width, 
        stages_desc_str, 
        latency, 
        effective_label_suffix
    ))

def _print_kernel_stack_trace_for_stage(stage_idx, stack_id, protocol, direction_str):
    """Helper function to print a single kernel stack trace."""
    global args, b
    is_icmp_p2 = protocol == "icmp" and stage_idx >= MAX_STAGES_PER_PATH
    stage_name = get_detailed_stage_name(stage_idx, protocol, direction_str, is_icmp_p2)
    print("  Stage %d (%s):" % (stage_idx, stage_name))

    if stack_id <= 0:
        print("    <BPF 'get_stackid' call failed or returned no stack: id=%d>" % stack_id)
        return

    try:
        if not b:
            print("    <BPF object 'b' is not available for stack traces>")
            return

        stack_table = b.get_table("stack_traces")
        resolved_one = False
        for addr in stack_table.walk(stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("    %s" % sym)
            resolved_one = True
        
        if not resolved_one:
            print("    <Stack trace walk for id %d yielded no symbols>" % stack_id)

    except KeyError:
        print("    <'stack_traces' table not found in BPF object. Kernel may lack CONFIG_BPF_STACK_TRACE.>")
        if b and hasattr(b, 'tables'):
            print("    Available tables: %s" % list(b.tables.keys()))
        else:
            print("    BPF object 'b' or 'b.tables' not available to list tables.")
    except Exception as e:
        print("    <Python error during stack trace resolution for id %d: %s>" % (stack_id, e))

def print_all_kernel_stack_traces(flow_data, protocol, direction_str):
    """Prints kernel stack traces for all relevant stages in the flow."""
    print("\nKernel Stack Traces (Path Stages):") 
    
    num_stages_to_print = 0
    if protocol == "icmp":
        num_stages_to_print = MAX_TOTAL_STAGES 
    elif protocol == "tcp": 
        if direction_str == "outgoing":
            num_stages_to_print = TCP_OUT_NUM_STAGES # This constant is defined in BPF C, should be mirrored in Python
        else: # incoming
            num_stages_to_print = TCP_IN_NUM_STAGES  # This constant is defined in BPF C, should be mirrored in Python
    # Add UDP logic: e.g. elif protocol == "udp": num_stages_to_print = UDP_NUM_STAGES_MAPPING[direction_str]
    else:
        num_stages_to_print = MAX_STAGES_PER_PATH 

    for i in range(num_stages_to_print):
        if flow_data.ts[i] != 0: 
            _print_kernel_stack_trace_for_stage(i, flow_data.kstack_id[i], protocol, direction_str)

def print_event(cpu, data, size):
    global args 
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    protocol_str = args.protocol
    trace_dir_str = args.direction
    
    print("=== %s Latency Trace: %s (%s) ===" % (protocol_str.upper(), time_str, trace_dir_str))

    # IPs from key are canonical (local, remote for the trace direction)
    # Ports from key are canonical (local, remote for the trace direction)
    local_ip_key_str = format_ip(socket.ntohl(key.sip))
    remote_ip_key_str = format_ip(socket.ntohl(key.dip))
    
    if args.protocol == "icmp":
        local_id_key_int = socket.ntohs(key._union.icmp.id)
        remote_seq_key_int = socket.ntohs(key._union.icmp.seq)
        print("Session: %s (ID: %d) -> %s (Seq: %d) -- ActualKey: %s (%d) -> %s (%d)" % (
            args.src_ip, # Configured local IP
            local_id_key_int, # ID
            args.dst_ip, # Configured remote IP
            remote_seq_key_int, # Seq
            local_ip_key_str, local_id_key_int,
            remote_ip_key_str, remote_seq_key_int
        ))
    else: # TCP/UDP
        local_port_key_int = socket.ntohs(key._union.l4.sport)
        remote_port_key_int = socket.ntohs(key._union.l4.dport)
        print("Session: %s:%s -> %s:%s -- ActualKey: %s:%d -> %s:%d" % (
            args.src_ip, 
            args.src_port if args.src_port != 0 else str(local_port_key_int), # Show actual traced port if arg was wildcard
            args.dst_ip, 
            args.dst_port if args.dst_port != 0 else str(remote_port_key_int), # Show actual traced port if arg was wildcard
            local_ip_key_str, local_port_key_int,
            remote_ip_key_str, remote_port_key_int
        ))

    path_desc_padding_width = 45 
    
    if args.protocol == "icmp":
        path1_desc_detail = ""
        path2_desc_detail = ""
        if args.direction == "incoming": 
            path1_desc_detail = "Path 1 (Request RX from %s)" % remote_ip_key_str 
            path2_desc_detail = "Path 2 (Reply TX to %s)" % remote_ip_key_str
        else: 
            path1_desc_detail = "Path 1 (Request TX to %s)" % remote_ip_key_str
            path2_desc_detail = "Path 2 (Reply RX from %s)" % remote_ip_key_str

        print("%-*s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
            path_desc_padding_width, path1_desc_detail,
            flow.p_pid, flow.p_comm.decode('utf-8', 'replace'),
            flow.p_ifname.decode('utf-8', 'replace'), flow.request_type
        ))
        print("%-*s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
            path_desc_padding_width, path2_desc_detail,
            flow.p2_pid, flow.p2_comm.decode('utf-8', 'replace'),
            flow.p2_ifname.decode('utf-8', 'replace'), flow.reply_type
        ))
    else: 
        path_label = "TX Path" if args.direction == "outgoing" else "RX Path"
        # For TCP/UDP, src_ip/dst_ip from args define the perspective
        # key.sip/dip are canonical local/remote for the trace session
        from_ip_disp = local_ip_key_str # This is the canonical local IP of the traced flow
        to_ip_disp = remote_ip_key_str   # This is the canonical remote IP of the traced flow
        
        # Display perspective based on trace direction and configured IPs
        # If outgoing, configured src_ip is local_ip_key_str. If incoming, configured src_ip is local_ip_key_str (it's the target being traced).
        path_desc_detail = "%s (%s:%s -> %s:%s)" % (
            path_label, 
            local_ip_key_str, str(local_port_key_int),
            remote_ip_key_str, str(remote_port_key_int)
        )
        print("%-*s: PID=%-6d COMM=%-12s IF=%-10s" % ( 
            path_desc_padding_width, path_desc_detail,
            flow.p_pid, flow.p_comm.decode('utf-8', 'replace'),
            flow.p_ifname.decode('utf-8', 'replace')
        ))

    print("\nSKB/Sock Pointers (Path Stages):")
    stage_name_padding_width = 55 
    
    num_skb_stages = 0
    if args.protocol == "icmp":
        num_skb_stages = MAX_TOTAL_STAGES
    elif args.protocol == "tcp": 
        if args.direction == "outgoing": num_skb_stages = TCP_OUT_NUM_STAGES
        else: num_skb_stages = TCP_IN_NUM_STAGES 
    # Add UDP logic here for num_skb_stages
    else:
        num_skb_stages = MAX_STAGES_PER_PATH

    for i in range(num_skb_stages):
        if flow.skb_ptr[i] != 0:
            is_icmp_p2 = args.protocol == "icmp" and i >= MAX_STAGES_PER_PATH
            stage_name_str = get_detailed_stage_name(i, args.protocol, args.direction, is_icmp_p2)
            print("  Stage %2d (%-*s): 0x%x" % (
                i, stage_name_padding_width, stage_name_str, flow.skb_ptr[i]
            ))
    
    if args.protocol == "icmp":
        print("\nPath 1 Latencies (us):")
        _print_latency_segment(0, 1, flow, args.protocol, args.direction) 
        _print_latency_segment(1, 2, flow, args.protocol, args.direction) 
        if flow.ts[2] > 0 and flow.ts[3] > 0 : _print_latency_segment(2,3,flow, args.protocol, args.direction)
        if flow.ts[3] > 0 and flow.ts[4] > 0 and flow.ts[5] > 0 : 
             _print_latency_segment(3,4,flow, args.protocol, args.direction)
             _print_latency_segment(4,5,flow, args.protocol, args.direction)
        elif flow.ts[3] > 0 and not flow.ts[4] > 0 and flow.ts[5] > 0:
             _print_latency_segment(3,5,flow, args.protocol, args.direction, label_suffix="(S4 N/A)")
        elif flow.ts[2] > 0 and not flow.ts[3] > 0 and not flow.ts[4] > 0 and flow.ts[5] > 0:
             _print_latency_segment(2,5,flow, args.protocol, args.direction, label_suffix="(OVS No Upcall P1)")

        _print_latency_segment(5, 6, flow, args.protocol, args.direction) 

        if flow.ts[flow.start_stage_id_for_trace] > 0 and flow.ts[ICMP_PATH1_STAGE_6] > 0: 
            path1_total = format_latency(flow.ts[flow.start_stage_id_for_trace], flow.ts[ICMP_PATH1_STAGE_6])
            print("  Total Path 1: %s us" % path1_total)
        
        print("\nPath 2 Latencies (us):")
        p2_base = MAX_STAGES_PER_PATH
        _print_latency_segment(p2_base + 0, p2_base + 1, flow, args.protocol, args.direction)
        _print_latency_segment(p2_base + 1, p2_base + 2, flow, args.protocol, args.direction)
        if flow.ts[p2_base+2] > 0 and flow.ts[p2_base+3] > 0 : _print_latency_segment(p2_base+2,p2_base+3,flow, args.protocol, args.direction)
        if flow.ts[p2_base+3] > 0 and flow.ts[p2_base+4] > 0 and flow.ts[p2_base+5] > 0 : 
             _print_latency_segment(p2_base+3,p2_base+4,flow, args.protocol, args.direction)
             _print_latency_segment(p2_base+4,p2_base+5,flow, args.protocol, args.direction)
        elif flow.ts[p2_base+3] > 0 and not flow.ts[p2_base+4] > 0 and flow.ts[p2_base+5] > 0:
             _print_latency_segment(p2_base+3,p2_base+5,flow, args.protocol, args.direction, label_suffix="(S4 N/A P2)")
        elif flow.ts[p2_base+2] > 0 and not flow.ts[p2_base+3] > 0 and not flow.ts[p2_base+4] > 0 and flow.ts[p2_base+5] > 0:
             _print_latency_segment(p2_base+2,p2_base+5,flow, args.protocol, args.direction, label_suffix="(OVS No Upcall P2)")

        _print_latency_segment(p2_base + 5, p2_base + 6, flow, args.protocol, args.direction)

        if flow.ts[p2_base + 0] > 0 and flow.ts[flow.final_stage_id_for_trace] > 0:
            path2_total = format_latency(flow.ts[p2_base + 0], flow.ts[flow.final_stage_id_for_trace])
            print("  Total Path 2: %s us" % path2_total)
        
        if flow.ts[flow.start_stage_id_for_trace] > 0 and flow.ts[flow.final_stage_id_for_trace] > 0: 
            rtt = format_latency(flow.ts[flow.start_stage_id_for_trace], flow.ts[flow.final_stage_id_for_trace])
            print("\nTotal RTT (Path1 Start to Path2 End): %s us" % rtt)
            
            if flow.ts[ICMP_PATH1_STAGE_6] > 0 and flow.ts[p2_base + 0] > 0: 
                inter_path_latency = format_latency(flow.ts[ICMP_PATH1_STAGE_6], flow.ts[p2_base + 0])
                print("Inter-Path Latency (P1 end -> P2 start): %s us" % inter_path_latency)
    
    else: 
        print("\nPath Latencies (us):")
        # This section needs to be made generic based on defined stages for protocol/direction
        # Example for TCP Outgoing (0-5 stages, as per TCP_OUT_NUM_STAGES = 6)
        # These constants (TCP_OUT_NUM_STAGES etc.) should be available in Python
        # For now, using conceptual values. 
        # We need a robust way to get num_stages for current proto/dir.
        num_stages_for_path = flow.final_stage_id_for_trace + 1 
        if num_stages_for_path > 1: # Need at least two stages for a segment
            for i in range(num_stages_for_path -1):
                # Only print segment if both start and end timestamps exist
                if flow.ts[i] > 0 and flow.ts[i+1] > 0:
                     _print_latency_segment(i, i + 1, flow, args.protocol, args.direction)
            
        if flow.ts[flow.start_stage_id_for_trace] > 0 and flow.ts[flow.final_stage_id_for_trace] > 0:
             total_path_latency = format_latency(flow.ts[flow.start_stage_id_for_trace], flow.ts[flow.final_stage_id_for_trace])
             print("  Total Path Latency: %s us" % total_path_latency)

    if not args.disable_kernel_stacks:
        print_all_kernel_stack_traces(flow, args.protocol, args.direction)
    
    print("\n" + "="*50 + "\n")

# Python-side definitions for constants used in BPF C, for print_event logic
TCP_OUT_NUM_STAGES = 6 # Corresponds to #define TCP_OUT_NUM_STAGES in BPF C
TCP_IN_NUM_STAGES = 6  # Corresponds to #define TCP_IN_NUM_STAGES in BPF C
# Add UDP_OUT_NUM_STAGES, UDP_IN_NUM_STAGES when defined in BPF C

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Trace L4 (TCP, UDP, ICMP) latency through the Linux network stack and OVS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Outgoing TCP from 192.168.1.10:12345 to 192.168.1.20:80, interface eth0:
    sudo ./%(prog)s --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                               --protocol tcp --src-port 12345 --dst-port 80 \\
                               --phy-iface1 eth0 --direction outgoing

  Incoming UDP to 192.168.1.10:5000 from any source, interface eth0:
    sudo ./%(prog)s --src-ip 192.168.1.10 --dst-ip 0.0.0.0 \\
                               --protocol udp --dst-port 5000 \\
                               --phy-iface1 eth0 --direction incoming

  ICMP RTT from 192.168.1.10 to 192.168.1.20, interfaces eth0, eth1:
    sudo ./%(prog)s --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                               --protocol icmp --phy-iface1 eth0 --phy-iface2 eth1 --direction outgoing
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=True, 
                      help='Primary IP of the host where this script runs. For "outgoing" trace, this is the source IP. For "incoming" trace, this is the local IP that receives the traffic.')
    parser.add_argument('--dst-ip', type=str, required=True,
                      help='Secondary IP involved in the trace. For "outgoing" trace, this is the destination IP. For "incoming" trace, this is the remote IP sending the traffic. Use "0.0.0.0" for wildcard.')
    parser.add_argument('--protocol', type=str, choices=["tcp", "udp", "icmp"], required=True,
                      help='Protocol to trace.')
    parser.add_argument('--src-port', type=int, default=0,
                      help='Source port for TCP/UDP filtering (default: 0, wildcard). This is the local port for outgoing, remote port for incoming if specified.')
    parser.add_argument('--dst-port', type=int, default=0,
                      help='Destination port for TCP/UDP filtering (default: 0, wildcard). This is the remote port for outgoing, local port for incoming if specified.')
    parser.add_argument('--phy-iface1', type=str, required=True,
                      help='First physical interface to monitor (e.g., for dev_queue_xmit on TX path, or __netif_receive_skb on RX path).')
    parser.add_argument('--phy-iface2', type=str, required=False, default=None,
                      help='Second physical interface to monitor (optional).')
    parser.add_argument('--latency-ms', type=float, default=0,
                      help='Minimum latency threshold in ms to report (default: 0).')
    parser.add_argument('--direction', type=str, choices=["outgoing", "incoming"], default="outgoing",
                      help='Direction of trace: "outgoing" (TX path from src-ip) or "incoming" (RX path to src-ip). Default: outgoing.')
    parser.add_argument('--disable-kernel-stacks', action='store_true', default=False,
                      help='Disable printing of kernel stack traces.')
    
    args = parser.parse_args()
    
    direction_val = 0 if args.direction == "outgoing" else 1 
    protocol_val = 0
    if args.protocol == "icmp":
        protocol_val = PROTO_ICMP
    elif args.protocol == "tcp":
        protocol_val = PROTO_TCP
    elif args.protocol == "udp":
        protocol_val = PROTO_UDP
    else: 
        print("Error: Invalid protocol specified.")
        sys.exit(1)

    src_port_val_net = socket.htons(args.src_port)
    dst_port_val_net = socket.htons(args.dst_port)


    try:
        ifindex1 = get_if_index(args.phy_iface1)
        if args.phy_iface2:
            ifindex2 = get_if_index(args.phy_iface2)
        else:
            ifindex2 = ifindex1 
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)
        
    src_ip_hex_val = ip_to_hex(args.src_ip)
    dst_ip_hex_val = ip_to_hex(args.dst_ip) 
    
    latency_threshold_ns_val = int(args.latency_ms * 1000000)
    
    print("=== L4 Latency Tracer ===")
    print("Protocol: %s, Trace Direction: %s" % (args.protocol.upper(), args.direction.upper()))
    print("SRC_IP_FILTER (Configured Local IP for trace): %s (0x%x)" % (args.src_ip, socket.ntohl(src_ip_hex_val) if src_ip_hex_val !=0 else 0)) 
    print("DST_IP_FILTER (Configured Remote IP for trace): %s (0x%x)" % (args.dst_ip, socket.ntohl(dst_ip_hex_val) if dst_ip_hex_val !=0 else 0))
    if args.protocol == "tcp" or args.protocol == "udp":
        print("SRC_PORT_FILTER (Configured Local Port for trace): %d (Net: %d)" % (args.src_port, src_port_val_net))
        print("DST_PORT_FILTER (Configured Remote Port for trace): %d (Net: %d)" % (args.dst_port, dst_port_val_net))

    if args.phy_iface2 and args.phy_iface1 != args.phy_iface2:
        print("Monitoring physical interfaces: %s (ifindex %d) and %s (ifindex %d)" % 
              (args.phy_iface1, ifindex1, args.phy_iface2, ifindex2))
    else:
        print("Monitoring physical interface: %s (ifindex %d)" % 
              (args.phy_iface1, ifindex1))
    
    if latency_threshold_ns_val > 0:
        print("Reporting only traces with latency >= %.3f ms" % args.latency_ms)
    
    try:
        # Define Python-side stage counts to mirror BPF C defines for print_event logic
        # These should ideally be sourced more dynamically if BPF stages change often.
        global TCP_OUT_NUM_STAGES, TCP_IN_NUM_STAGES # Make them accessible in print_event
        TCP_OUT_NUM_STAGES = 6
        TCP_IN_NUM_STAGES = 6
        # Add UDP stage counts here

        b = BPF(text=bpf_text % (
            src_ip_hex_val, 
            dst_ip_hex_val,
            src_port_val_net, 
            dst_port_val_net, 
            protocol_val,
            latency_threshold_ns_val,
            ifindex1, 
            ifindex2,
            direction_val  
        ))
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nEnsure all kprobe function names in the BPF C code are correct for your kernel version.")
        sys.exit(1)
        
    b["events"].open_perf_buffer(print_event) 
    
    print("\nTracing %s (%s) traffic for src_ip=%s, dst_ip=%s ... Hit Ctrl-C to end." % 
          (args.protocol.upper(), args.direction, args.src_ip, args.dst_ip))
    
    try:
        while True:
            b.perf_buffer_poll() 
    except KeyboardInterrupt:
        print("\nDetaching...")
    finally:
        print("Exiting.") 