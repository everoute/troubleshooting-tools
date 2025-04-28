#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# for el7 
# curl -fLO http://192.168.24.6/tmp/bpftools/x86_64/bcc-0.21.0-1.el7.x86_64.rpm
# curl -fLO http://192.168.24.6/tmp/bpftools/noarch/python-bcc-0.21.0-1.el7.noarch.rpm 
# rpm -ivh bcc-0.21.0-1.el7.x86_64.rpm python-bcc-0.21.0-1.el7.noarch.rpm --force 
# Usage: sudo ./internal_port_delay.py [--src-ip x.x.x.x] [--dst-ip y.y.y.y] [--latency-ms L]
# --src-ip ： 源IP地址
# --dst-ip ： 目的IP地址
# --latency-ms ： 延迟阈值，单位为毫秒, 追踪物理网卡收包到协议栈处理完成整个过程延迟大于指定值的包 
#  显示分段延迟，共计算 6段，为 smtxos 数据路径量身定做，包含 ovs 处理关键路径延迟统计，

# sameple output :---                                                                                                                                                                          
# PKT: 10.255.0.104 -> 10.255.0.143 Proto=ICMP ICMP Type=8 ID=3657 Seq=1798                                                                                                    
#   Initial Context: PID=0      COMM=swapper/45   IF=ens2f1                                                                                                                    
#   Latencies (us): [0->1]:   N/A  [1->2]:   N/A  [2->3]:   N/A  [3->4]:   N/A  [4->5]:1620.309 | Total[0->5]:1720.494                                          
#   Kernel Stack Traces:                                                                                                                                                       
#     Stage 0 (NETIF_RECV): Stack ID 15153                                                                                                                                     
#       __netif_receive_skb+0x1                                                                                                                                                
#       netif_receive_skb_internal+0x3d                                                                                                                                        
#       napi_gro_receive+0xba                                                                                                                                                  
#       mlx5e_handle_rx_cqe+0xa3                                                                                                                                               
#       mlx5e_poll_rx_cq+0xb61                                                                                                                                                 
#       mlx5e_napi_poll+0xee                                                                                                                                                   
#       net_rx_action+0x149                                                                                                                                                    
#       __softirqentry_text_start+0xe3                                                                                                                                         
#       irq_exit+0x111                                                                                                                                                         
#       do_IRQ+0x7f                                                                                                                                                            
#       ret_from_intr+0x0                                                                                                                                                      
#     Stage 1 (NETDEV_FRAME): <Skipped>                                                                                                                                        
#     Stage 2 (DP_PROCESS): Stack ID 6447                                                                                                                                      
#       ovs_dp_process_packet+0x1                                                                                                                                              
#       ovs_vport_receive+0x6c                                                                                                                                                 
#       netdev_frame_hook+0xd5                                                                                                                                                 
#       __netif_receive_skb_core+0x6a3
#       __netif_receive_skb_one_core+0x3c
#       netif_receive_skb_internal+0x3d
#       napi_gro_receive+0xba         
#       mlx5e_handle_rx_cqe+0xa3
#       mlx5e_poll_rx_cq+0xb61      
#       mlx5e_napi_poll+0xee        
#       net_rx_action+0x149              
#       __softirqentry_text_start+0xe3   
#       irq_exit+0x111                   
#       do_IRQ+0x7f             
#       ret_from_intr+0x0         
#     Stage 3 (DP_UPCALL): <Skipped>
#     Stage 4 (VPORT_SEND): Stack ID 1072
#       ovs_vport_send+0x1               
#       do_execute_actions+0x401         
#       ovs_execute_actions+0x48         
#       ovs_dp_process_packet+0x7d     
#       ovs_vport_receive+0x6c  
#       netdev_frame_hook+0xd5  
#       __netif_receive_skb_core+0x6a3
#       __netif_receive_skb_one_core+0x3c
#       netif_receive_skb_internal+0x3d
#       napi_gro_receive+0xba
#       mlx5e_handle_rx_cqe+0xa3
#       mlx5e_poll_rx_cq+0xb61
#       mlx5e_napi_poll+0xee
#       net_rx_action+0x149
#       __softirqentry_text_start+0xe3
#       irq_exit+0x111
#       do_IRQ+0x7f
#       ret_from_intr+0x0
#     Stage 5 (ICMP_RCV): Stack ID 14796
#       icmp_rcv+0x1
#       ip_local_deliver_finish+0x60


from bcc import BPF, PerfType, PerfSWConfig
# for oe kernel, using python3
#from bpfcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime, time as time_time
import argparse
from ctypes import *
import socket
import struct
import os
import sys
import datetime
import fcntl # Needed for ioctl

# --- ADD get_if_index function ---
def get_if_index(devname):
    """Python2 fallback for socket.if_nametoindex"""
    SIOCGIFINDEX = 0x8933
    # IFNAMSIZ is 16, check length against 15 for null terminator space
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    # Pack interface name into bytes, padded to 256 (a common size for ifreq)
    # Requires careful struct packing knowledge - using 16s for name based on typical ifreq
    # Format might vary, this is a common guess for SIOCGIFINDEX ioctl
    # Safer might be to define the full ifreq structure if possible.
    # Let's try a simpler buffer packing just the name + padding
    # buf = struct.pack('16s', devname.encode('ascii')) # Pack just the name
    # Need sufficient buffer size for the kernel to write back into
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))

    try:
        # ioctl syscall: s.fileno() is the socket fd, SIOCGIFINDEX is the request code,
        # buf is the buffer (ifreq structure expected by kernel)
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        # Kernel writes the index back into the buffer at a specific offset.
        # For ifreq, the index (ifr_ifindex) is typically at offset 16.
        # We unpack 4 bytes (int) starting from offset 16.
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()
# --- End get_if_index --- 


# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/ip.h>    // For struct iphdr
#include <net/icmp.h>  // For struct icmphdr
#include <linux/string.h> // for strstr (use carefully in BPF)
#include <net/flow.h>    // For struct flowi4

// --- User IP Placeholders (Filled by Python) ---
#define USR_SRC_IP 0x%x
#define USR_DST_IP 0x%x
#define LATENCY_THRESHOLD_NS %d
// --- ADD Target Ifindex Placeholder ---
#define TARGET_IFINDEX %d

// --- Stages --- REVISED (Using __netif_receive_skb as Stage 0) ---
// RX Path
#define RX_STAGE_0_NETIF_RECV     0 // Stage 0 (NEW START POINT)
#define RX_STAGE_1_NETDEV_FRAME   1
#define RX_STAGE_2_DP_PROCESS     2
#define RX_STAGE_3_DP_UPCALL      3
#define RX_STAGE_4_EXEC_ACTIONS   4
#define RX_STAGE_5_VPORT_SEND     5
#define RX_STAGE_6_ICMP_RCV       6
// TX Path (Shifted)
#define TX_STAGE_0_IP_QUEUE_XMIT  7
#define TX_STAGE_1_INTERNAL_XMIT  8
#define TX_STAGE_2_DP_PROCESS     9
#define TX_STAGE_3_DP_UPCALL     10
#define TX_STAGE_4_EXEC_ACTIONS  11
#define TX_STAGE_5_VPORT_SEND    12
#define TX_STAGE_6_DEV_XMIT      13
#define MAX_STAGES               14 // Updated Max (0-13)

// --- Session Key ---
struct session_key_t {
    __be32 ip1; // min(sip, dip)
    __be32 ip2; // max(sip, dip)
    u16 seq;   // ICMP Sequence number (network byte order)
};

// --- Original Packet Info ---
struct packet_info_t {
    __be32 sip;
    __be32 dip;
    u8  proto;
    u8  icmp_type;
    __be16 id; // ICMP ID (network byte order)
};

#define IFNAMSIZ 16
#define TASK_COMM_LEN 16

// --- Flow Data (Value in Map) ---
struct flow_data_t {
    u64 ts[MAX_STAGES];
    int kstack_id[MAX_STAGES];
    struct packet_info_t req_info;
    struct packet_info_t rep_info;
    u32 first_pid;
    char first_comm[TASK_COMM_LEN];
    char first_ifname[IFNAMSIZ];
    u32 last_pid;
    char last_comm[TASK_COMM_LEN];
    char last_ifname[IFNAMSIZ];
};

// --- Perf Event Data ---
struct latency_event_data_t {
    struct session_key_t key;
    struct flow_data_t data;
};

// Map definition
BPF_TABLE("lru_hash", struct session_key_t, struct flow_data_t, flow_sessions, 20480);
// Stack traces
BPF_STACK_TRACE(stack_traces, 10240); 
// Perf output
BPF_PERF_OUTPUT(latency_events);
// Per-CPU scratch buffer for event submission
BPF_PERCPU_ARRAY(event_scratch_map, struct latency_event_data_t, 1);

// --- Helper Functions ---

// NEW Core Parsing Function
// Parses skb, populates key/info if relevant ICMP packet, returns direction (1=Req, 2=Rep, 0=Ignore)
static __always_inline int parse_skb_for_key_info_dir(
    struct sk_buff *skb,
    struct session_key_t *session_key,
    struct packet_info_t *pkt_info)
{
    if (skb == NULL) return 0;

    // Read necessary skb fields
    unsigned char *head = NULL;
    u16 network_header = 0;
    u16 transport_header = 0;
    u32 len = 0;

    // Check reads for safety
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) return 0; // Read even if 0

    // Read IP header
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) {
         //bpf_trace_printk("BPF DBG: Failed IP hdr read at net_hdr=0x%%x", network_header);
         return 0;
    }

    // Check IP protocol
    if (iph.protocol != IPPROTO_ICMP) {
         return 0;
    }
    pkt_info->proto = iph.protocol;

    // Calculate expected transport header offset if not set
    if (transport_header == 0) {
        u8 ihl = iph.ihl & 0x0F; // In 4-byte words - DECLARE AND CALCULATE HERE
        if (ihl < 5) return 0; // Invalid IHL
        transport_header = network_header + ihl * 4;
    }

    // Read ICMP header
    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header) < 0) {
         //bpf_trace_printk("BPF DBG: Failed ICMP hdr read at trans_hdr=0x%%x", transport_header);
         return 0;
    }

    // Check ICMP type
    if (icmph.type != ICMP_ECHO && icmph.type != ICMP_ECHOREPLY) {
         //bpf_trace_printk("BPF DBG: Not ECHO/ECHOREPLY type=%%d", icmph.type);
         return 0;
    }
    pkt_info->icmp_type = icmph.type;

    // Fill remaining packet info from IP/ICMP headers
    pkt_info->sip = iph.saddr;
    pkt_info->dip = iph.daddr;
    pkt_info->id = icmph.un.echo.id;       // ID from ICMP header
    __be16 sequence = icmph.un.echo.sequence; // Sequence from ICMP header

    // Determine Direction based on user filters and ICMP type
    int direction = 0;
    __be32 usr_src = USR_SRC_IP;
    __be32 usr_dst = USR_DST_IP;

    if ((usr_src == 0 || iph.saddr == usr_src) && (usr_dst == 0 || iph.daddr == usr_dst) && icmph.type == ICMP_ECHO) {
        direction = 1; // Request
    } else if ((usr_dst == 0 || iph.saddr == usr_dst) && (usr_src == 0 || iph.daddr == usr_src) && icmph.type == ICMP_ECHOREPLY) {
        direction = 2; // Reply
    } else {
        //bpf_trace_printk("BPF DBG: Fail direction match s=0x%%x d=0x%%x type=%%d", iph.saddr, iph.daddr, icmph.type);
        return 0;
    }

    // Construct Session Key
    if (iph.saddr < iph.daddr) {
        session_key->ip1 = iph.saddr;
        session_key->ip2 = iph.daddr;
    } else {
        session_key->ip1 = iph.daddr;
        session_key->ip2 = iph.saddr;
    }
    session_key->seq = sequence; // Use sequence from ICMP header

    //bpf_trace_printk("BPF DBG: Parse success dir=%%d", direction);
    return direction;
}

// Helper to check physical interface index
static __always_inline bool check_ifindex(struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    // Read dev pointer
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    // Read ifindex from dev
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    // Compare with target
    return (ifindex == TARGET_IFINDEX);
}

// --- Main Event Handler --- // REFACTORED Signature & Logic
static __always_inline void handle_flow_event(
    struct pt_regs *ctx,
    struct sk_buff *skb,
    u64 stage_id,
    struct session_key_t *session_key, // Passed in
    struct packet_info_t *current_pkt_info // Passed in
) {
    if (skb == NULL || stage_id >= MAX_STAGES || session_key == NULL || current_pkt_info == NULL) return;

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    struct flow_data_t *flow_data_ptr, zero = {};

    // Debug prints (can be re-enabled if needed)
    // bpf_trace_printk("BPF Hdl: Stage=%%llu", stage_id);
    // bpf_trace_printk("BPF Hdl Key: IPs 0x%%x -> 0x%%x, Seq=%%u", session_key->ip1, session_key->ip2, bpf_ntohs(session_key->seq));

    flow_data_ptr = flow_sessions.lookup_or_try_init(session_key, &zero); // Use passed-in key
    if (!flow_data_ptr) {
        //bpf_trace_printk("BPF DEBUG: Map lookup_or_try_init FAILED (Stage=%%llu)", stage_id);
        return; // Map full or other error
    }

    // Record timestamp and stack ID for the current stage if not already done
    if (flow_data_ptr->ts[stage_id] == 0) {
        flow_data_ptr->ts[stage_id] = current_ts;
        flow_data_ptr->kstack_id[stage_id] = stack_id;

        // --- Store Initial/Request Context (ONLY ONCE when first ts is recorded) ---
        if (flow_data_ptr->first_pid == 0) { // Use first_pid as indicator for first record
            flow_data_ptr->first_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_data_ptr->first_comm, sizeof(flow_data_ptr->first_comm));
            // Read dev name for first context store
            struct net_device *dev_for_ctx = NULL;
            char ifname_for_ctx[IFNAMSIZ] = {0};
            if (bpf_probe_read_kernel(&dev_for_ctx, sizeof(dev_for_ctx), &skb->dev) == 0 && dev_for_ctx != NULL) {
                if (bpf_probe_read_kernel_str(ifname_for_ctx, IFNAMSIZ, dev_for_ctx->name) < 0) { ifname_for_ctx[0] = '?'; }
            } else { ifname_for_ctx[0] = '?'; }
            __builtin_memcpy(flow_data_ptr->first_ifname, ifname_for_ctx, IFNAMSIZ);
            flow_data_ptr->first_ifname[IFNAMSIZ - 1] = '\\0'; // Ensure null termination

            // Store Request packet info also only on first record
            if (current_pkt_info->icmp_type == ICMP_ECHO) { // Check if current packet is the request
                flow_data_ptr->req_info = *current_pkt_info;
            }
        }

        // --- Store Reply Packet Info (ONLY ONCE) ---
        // If it's a reply packet and rep_info hasn't been stored yet
        if (current_pkt_info->icmp_type == ICMP_ECHOREPLY && flow_data_ptr->rep_info.proto == 0) {
             flow_data_ptr->rep_info = *current_pkt_info;
        }

        // --- Store Final Context (Only at final stage) ---
        if (stage_id == TX_STAGE_6_DEV_XMIT) {
             flow_data_ptr->last_pid = bpf_get_current_pid_tgid() >> 32;
             bpf_get_current_comm(&flow_data_ptr->last_comm, sizeof(flow_data_ptr->last_comm));
             struct net_device *dev;
             char final_ifname[IFNAMSIZ] = {0};
             if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
                  if (bpf_probe_read_kernel_str(final_ifname, IFNAMSIZ, dev->name) < 0) { final_ifname[0] = '?';}
             } else { final_ifname[0] = '?';}
             __builtin_memcpy(flow_data_ptr->last_ifname, final_ifname, IFNAMSIZ);
             flow_data_ptr->last_ifname[IFNAMSIZ - 1] = '\\0'; // Ensure null termination
        }
    }

    // --- Submit Event ONLY at the final TX stage (No latency check here) ---
    if (stage_id == TX_STAGE_6_DEV_XMIT) {
        u32 zero_key = 0;
        struct latency_event_data_t *event_data_ptr = event_scratch_map.lookup(&zero_key);
        if (!event_data_ptr) {
            // Should not happen for percpu array index 0, but check anyway
            return; // Cannot get scratch buffer
        }

        // --- Populate event_data via pointer ---
        event_data_ptr->key = *session_key; // Copy the key
        // Read flow data into the map value
        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_data_ptr) != 0) {
            flow_sessions.delete(session_key); // Clean up flow if read fails
            return; // Failed to read flow data
        }
        // Note: last_pid, last_comm, last_ifname were already potentially updated in flow_data_ptr earlier

        // --- Submit event using pointer ---
        latency_events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));

        // Clean up map entry after submitting
        flow_sessions.delete(session_key);
    }
} // End handle_flow_event


// --- KProbes --- //

// Using __netif_receive_skb as it's often the main entry before internal calls
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    // Filter by physical interface first
    //if (!check_ifindex(skb)) {
    //    return 0;
    //}
    // If match, try to parse and handle
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) { // Only process if parsing succeeds
        return 0;
    }
    // Call handler
    handle_flow_event(ctx, skb, RX_STAGE_0_NETIF_RECV, &session_key, &current_pkt_info);
    return 0;
}

// Now Stage 1
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff *skb) {
    // Filter by physical interface first
    //if (!check_ifindex(skb)) {
    //    return 0;
    //}
    // If match, try to parse and handle
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) { // Only process if parsing succeeds
        return 0;
    }
    // Call handler
    handle_flow_event(ctx, skb, RX_STAGE_1_NETDEV_FRAME, &session_key, &current_pkt_info);
    return 0;
}

// Shared probes - No ifindex check needed here
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir((struct sk_buff *)skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;

    u64 stage_id;
    if (direction == 1) stage_id = RX_STAGE_2_DP_PROCESS; // RX Path
    else stage_id = TX_STAGE_2_DP_PROCESS; // TX Path (Stage 9)

    handle_flow_event(ctx, (struct sk_buff *)skb, stage_id, &session_key, &current_pkt_info);
    return 0;
}
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir((struct sk_buff *)skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;

    u64 stage_id;
    if (direction == 1) stage_id = RX_STAGE_3_DP_UPCALL; // RX Path
    else stage_id = TX_STAGE_3_DP_UPCALL; // TX Path (Stage 10)

    handle_flow_event(ctx, (struct sk_buff *)skb, stage_id, &session_key, &current_pkt_info);
    return 0;
}
int kprobe__ovs_execute_actions(struct pt_regs *ctx, void *dp, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;

    u64 stage_id;
    if (direction == 1) stage_id = RX_STAGE_4_EXEC_ACTIONS; // RX Path
    else stage_id = TX_STAGE_4_EXEC_ACTIONS; // TX Path (Stage 11)

    handle_flow_event(ctx, skb, stage_id, &session_key, &current_pkt_info);
    return 0;
}
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;

    u64 stage_id;
    if (direction == 1) stage_id = RX_STAGE_5_VPORT_SEND; // RX Path
    else stage_id = TX_STAGE_5_VPORT_SEND; // TX Path (Stage 12)

    handle_flow_event(ctx, skb, stage_id, &session_key, &current_pkt_info);
    return 0;
}
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;

    // Direction doesn't determine stage here, it's always RX_STAGE_6
    handle_flow_event(ctx, skb, RX_STAGE_6_ICMP_RCV, &session_key, &current_pkt_info);
        return 0;
    }

// Renumbered TX Probes (Stage 7 onwards)
// REMOVE kprobe____ip_queue_xmit
// int kprobe____ip_queue_xmit(...) { ... }

// ADD kprobe__ip_send_skb (Still targeting Stage 7)
// Verify signature: int ip_send_skb(struct net *net, struct sk_buff *skb);
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;
    // Call handler with the ORIGINAL Stage 7 ID (TX_STAGE_0_IP_QUEUE_XMIT)
    handle_flow_event(ctx, skb, TX_STAGE_0_IP_QUEUE_XMIT, &session_key, &current_pkt_info); 
        return 0;
    }

// Stage 8
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;
    handle_flow_event(ctx, skb, TX_STAGE_1_INTERNAL_XMIT, &session_key, &current_pkt_info);
            return 0;
        }
// Stage 9-12 (OVS probes call handler with correct indices)
// ...
// Stage 13
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct session_key_t session_key = {};
    struct packet_info_t current_pkt_info = {};
    int direction = parse_skb_for_key_info_dir(skb, &session_key, &current_pkt_info);
    if (direction == 0) return 0;
    handle_flow_event(ctx, skb, TX_STAGE_6_DEV_XMIT, &session_key, &current_pkt_info);
    return 0;
}

"""

# Python Code Starts Here
IFNAMSIZ = 16      # Should match BPF define
TASK_COMM_LEN = 16 # Should match BPF define
MAX_STAGES = 14    # Updated Max (0-13)

# --- CTypes Definitions ---
class SessionKey(Structure):
    _fields_ = [
        ("ip1", c_uint32),
        ("ip2", c_uint32),
        ("seq", c_uint16)
    ]

class PacketInfo(Structure):
     _fields_ = [
        ("sip", c_uint32),
        ("dip", c_uint32),
        ("proto", c_uint8),
        ("icmp_type", c_uint8),
        ("id", c_uint16),
    ]

class FlowData(Structure):
    _fields_ = [
        ("ts", c_uint64 * MAX_STAGES), # Updated size
        ("kstack_id", c_int * MAX_STAGES), # Updated size
        ("req_info", PacketInfo),
        ("rep_info", PacketInfo),
        ("first_pid", c_uint32),
        ("first_comm", c_char * TASK_COMM_LEN),
        ("first_ifname", c_char * IFNAMSIZ),
        ("last_pid", c_uint32),
        ("last_comm", c_char * TASK_COMM_LEN),
        ("last_ifname", c_char * IFNAMSIZ),
    ]

class LatencyEventData(Structure):
    _fields_ = [
        ("key", SessionKey),
        ("data", FlowData)
    ]
# --- End CTypes ---

# --- Stage Names --- Updated ---
stage_names = {
    0: "RX:NETIF_RECV",     # Stage 0 (NEW START POINT)
    1: "RX:NETDEV_FRAME",   # Stage 1
    2: "RX:DP_PROCESS",     # Stage 2
    3: "RX:DP_UPCALL",      # Stage 3
    4: "RX:EXEC_ACTIONS",   # Stage 4
    5: "RX:VPORT_SEND(->int)",# Stage 5
    6: "RX:ICMP_RCV",       # Stage 6
    7: "TX:IP_QUEUE_XMIT",  # Stage 7
    8: "TX:INTERNAL_XMIT",  # Stage 8
    9: "TX:DP_PROCESS",     # Stage 9
    10: "TX:DP_UPCALL",      # Stage 10
    11: "TX:EXEC_ACTIONS",   # Stage 11
    12: "TX:VPORT_SEND(->phy)",# Stage 12
    13: "TX:DEV_XMIT",       # Stage 13
}
# Update stage constants to match new indices (back to original)
RX_STAGE_0_NETIF_RECV     = 0
RX_STAGE_1_NETDEV_FRAME   = 1
RX_STAGE_2_DP_PROCESS     = 2
RX_STAGE_3_DP_UPCALL      = 3
RX_STAGE_4_EXEC_ACTIONS   = 4 # Renamed from _EXEC_ACTIONS
RX_STAGE_5_VPORT_SEND     = 5 # Renamed from _VPORT_SEND
RX_STAGE_6_ICMP_RCV       = 6
TX_STAGE_0_IP_QUEUE_XMIT  = 7
TX_STAGE_1_INTERNAL_XMIT  = 8
TX_STAGE_2_DP_PROCESS     = 9
TX_STAGE_3_DP_UPCALL      = 10
TX_STAGE_4_EXEC_ACTIONS   = 11
TX_STAGE_5_VPORT_SEND     = 12
TX_STAGE_6_DEV_XMIT       = 13
# --- End Stage Names ---

# --- Helper Functions ---
def ip_to_hex(ip_str):
    if not ip_str or ip_str == "0.0.0.0": return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '{}'".format(ip_str)); sys.exit(1)

def format_ip(addr):
    # Handle potential 0 address if info wasn't captured
    if addr == 0: return "0.0.0.0"
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

proto_names = {socket.IPPROTO_ICMP: "ICMP"}

def format_latency(ts_start, ts_end):
    if ts_start == 0 or ts_end == 0 or ts_end < ts_start:
        return " N/A ".rjust(7)
    delta_us = (ts_end - ts_start) / 1000.0
    # Adjust precision and padding if needed
    return ("%.3f" % delta_us).rjust(7)
# --- End Helper Functions ---

# --- Main Print Function --- Updated ---
def print_latency_event(cpu, data, size):
    event = cast(data, POINTER(LatencyEventData)).contents
    flow = event.data
    skey = event.key
    req = flow.req_info
    rep = flow.rep_info

    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # Determine request direction from stored info
    req_sip_str = format_ip(req.sip)
    req_dip_str = format_ip(req.dip)
    req_seq_str = str(socket.ntohs(skey.seq)) # Seq from session key
    req_id_str = str(socket.ntohs(req.id)) if req.proto != 0 else "N/A"

    print("--- %s ---" % time_str)
    print("SESSION: %s <-> %s Seq=%s" % (req_sip_str if req.proto != 0 else format_ip(skey.ip1),
                                         req_dip_str if req.proto != 0 else format_ip(skey.ip2),
                                         req_seq_str))
    if req.proto != 0:
        print("  Request: %s -> %s (ID: %s, Type: %d)" % (req_sip_str, req_dip_str, req_id_str, req.icmp_type))
    else:
        print("  Request: <Missed>")

    if rep.proto != 0:
        print("  Reply:   %s -> %s (ID: %s, Type: %d)" % (format_ip(rep.sip), format_ip(rep.dip), str(socket.ntohs(rep.id)), rep.icmp_type))
    else:
        print("  Reply:   <Missed>")

    print("  Initial Context (RX): PID=%-6d COMM=%-12s IF=%-10s" % (
          flow.first_pid, flow.first_comm.decode('utf-8', 'replace'),
          flow.first_ifname.decode('utf-8', 'replace')))
    if flow.ts[TX_STAGE_6_DEV_XMIT] > 0 : # Check if final TX stage (now 13) was hit
        print("  Final Context   (TX): PID=%-6d COMM=%-12s IF=%-10s" % (
              flow.last_pid, flow.last_comm.decode('utf-8', 'replace'),
              flow.last_ifname.decode('utf-8', 'replace')))
    else:
         print("  Final Context   (TX): <Not Reached>")


    # --- Latency Calculation --- Updated stage indices ---
    ts = flow.ts # Alias for shorter access
    latencies = []
    # RX Path (Stages 0-6)
    latencies.append(format_latency(ts[0], ts[1])) # 0->1 NETIF_RECV->FRAME
    latencies.append(format_latency(ts[1], ts[2])) # 1->2 FRAME->DP_PROC
    if ts[RX_STAGE_3_DP_UPCALL] > 0: # RX Flow Miss path 2->3->4 (using new indices)
        latencies.append(format_latency(ts[2], ts[3])) # 2->3 DP_PROC->UPCALL
        latencies.append(format_latency(ts[3], ts[4])) # 3->4 UPCALL->EXEC
    else: # RX Flow Hit path 2->4
        latencies.append("   Skip   ".rjust(7)) # Placeholder for 2->3
        latencies.append(format_latency(ts[2], ts[4])) # 2->4 (displayed in 2->3 slot)
    latencies.append(format_latency(ts[4], ts[5])) # 4->5 EXEC->VPORT(int)
    latencies.append(format_latency(ts[5], ts[6])) # 5->6 VPORT(int)->ICMP_RCV

    # Host Path (Stage 6->7)
    latencies.append(format_latency(ts[6], ts[7])) # 6->7 ICMP_RCV->IP_Q_XMIT

    # TX Path (Stages 7-13)
    latencies.append(format_latency(ts[7], ts[8]))   # 7->8 IP_Q->INT_XMIT
    latencies.append(format_latency(ts[8], ts[9]))   # 8->9 INT_XMIT->DP_PROC
    if ts[TX_STAGE_3_DP_UPCALL] > 0: # TX Flow Miss path 9->10->11 (using new indices)
        latencies.append(format_latency(ts[9], ts[10])) # 9->10 DP_PROC->UPCALL
        latencies.append(format_latency(ts[10],ts[11])) # 10->11 UPCALL->EXEC
    else: # TX Flow Hit path 9->11
        latencies.append("   Skip   ".rjust(7)) # Placeholder for 9->10
        latencies.append(format_latency(ts[9], ts[11])) # 9->11 (displayed in 10->11 slot)
    latencies.append(format_latency(ts[11], ts[12])) # 11->12 EXEC->VPORT(phy)
    latencies.append(format_latency(ts[12], ts[13])) # 12->13 VPORT(phy)->DEV_XMIT

    # Overall RTT (Stage 0 -> Stage 13)
    rtt_total = format_latency(ts[RX_STAGE_0_NETIF_RECV], ts[TX_STAGE_6_DEV_XMIT])

    # Print latencies (adjust indices and labels)
    print("  Latencies RX (us): [0->1]:%s [1->2]:%s [2->3]:%s [3->4]:%s [4->5]:%s [5->6]:%s" % tuple(latencies[0:6])) # RX 0-6
    print("  Latency Host (us): [6->7]:%s" % latencies[6]) # Host 6-7
    print("  Latencies TX (us): [7->8]:%s [8->9]:%s [9->10]:%s [10->11]:%s [11->12]:%s [12->13]:%s" % tuple(latencies[7:13])) # TX 7-13
    print("  Overall RTT[0->13](us):%s" % rtt_total)
    if ts[RX_STAGE_3_DP_UPCALL] > 0: print("  (RX Path: Flow Miss)") # Use new index 3
    if ts[TX_STAGE_3_DP_UPCALL] > 0: print("  (TX Path: Flow Miss)") # Use new index 10

    # --- Stack Traces --- Updated ---
    print("  Kernel Stack Traces:")
    kstack_id = flow.kstack_id
    for i in range(MAX_STAGES): # Iterate through all 14 stages (0-13)
        stage_name = stage_names.get(i, "?")
        # Update skip logic indices
        is_rx_upcall_stage = (i == RX_STAGE_3_DP_UPCALL) # New index 3
        is_tx_upcall_stage = (i == TX_STAGE_3_DP_UPCALL) # New index 10
        was_rx_upcall_skipped = (is_rx_upcall_stage and ts[RX_STAGE_3_DP_UPCALL] == 0 and ts[RX_STAGE_2_DP_PROCESS] != 0) # Use new indices 3, 2
        was_tx_upcall_skipped = (is_tx_upcall_stage and ts[TX_STAGE_3_DP_UPCALL] == 0 and ts[TX_STAGE_2_DP_PROCESS] != 0) # Use new indices 10, 9

        if kstack_id[i] >= 0:
            print("    Stage %d (%s): Stack ID %d" % (i, stage_name, kstack_id[i]))

# --- End Print Function ---

# --- Main Execution --- Updated ---
if __name__ == "__main__":
    if os.geteuid() != 0: print("Requires root privileges"); sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Trace ICMP Req/Reply RTT & Latency through kernel/OVS stages.",
        epilog="""Example Usage:
  sudo ./internal_port_delay.py --src-ip 1.1.1.1 --dst-ip 2.2.2.2 --phy-iface eth0
  sudo ./internal_port_delay.py --src-ip 1.1.1.1 --dst-ip 2.2.2.2 --phy-iface eth0 --latency-ms 10
""")
    parser.add_argument('--src-ip', type=str, required=True, help='Source IP of ICMP Request')
    parser.add_argument('--dst-ip', type=str, required=True, help='Destination IP of ICMP Request')
    parser.add_argument('--phy-iface', type=str, required=True, help='Name of the physical interface receiving initial request')
    parser.add_argument('--latency-ms', type=float, default=0,
                        help='Minimum RTT latency (First valid timestamp -> Final timestamp) in ms to report (default: 0, report all)') # Updated help text
    args = parser.parse_args()

    # --- Get ifindex from phy_iface name --- 
    phy_iface_name = args.phy_iface
    try:
        target_ifindex = get_if_index(phy_iface_name)
        print("Target physical interface: %s (ifindex: %d)" % (phy_iface_name, target_ifindex))
    except OSError as e:
        print("Error getting index for interface '%s': %s" % (phy_iface_name, e))
        sys.exit(1)
    # --- End Get ifindex --- 

    src_ip_filter_hex = ip_to_hex(args.src_ip)
    dst_ip_filter_hex = ip_to_hex(args.dst_ip)
    latency_threshold_ns = int(args.latency_ms * 1000000)

    print("Starting ICMP RTT latency trace...")
    print("Filtering for Request: %s -> %s on Interface index: %d" % (args.src_ip, args.dst_ip, target_ifindex))
    print("Filtering for Reply:   %s -> %s" % (args.dst_ip, args.src_ip))
    if latency_threshold_ns > 0: print("Reporting only if tracked RTT latency >= %.3f ms" % args.latency_ms)

    if os.system("lsmod | grep openvswitch > /dev/null") != 0:
         print("Warning: Open vSwitch kernel module does not appear to be loaded.")

    # --- Prepare BPF text - Needs 4 arguments now (IPs, threshold, ifindex) ---
    final_bpf_text = bpf_text % (src_ip_filter_hex, dst_ip_filter_hex, latency_threshold_ns, target_ifindex)

    cflags = [
        "-Wno-unused-value",
        "-Wno-pointer-sign",
        "-Wno-compare-distinct-pointer-types",
    ]
    try:
        global b # Make b global for print_latency_event
        print("Compiling and loading BPF program...")
        b = BPF(text=final_bpf_text, cflags=cflags)
        print("BPF program loaded successfully.")
    except Exception as e:
        print("Error compiling or loading BPF program:")
        print(e); sys.exit(1)

    print("\nTracing ICMP RTT latencies... Hit Ctrl-C to end.")

    # Open perf buffer AFTER probes are attached
    try:
        # Define the event handler function that includes the threshold check
        def handle_perf_event(cpu, data, size):
            event = cast(data, POINTER(LatencyEventData)).contents
            ts = event.data.ts
            
            # Find first valid RX timestamp (stages 0-6)
            first_valid_rx_ts = 0
            for i in range(RX_STAGE_6_ICMP_RCV + 1):
                if ts[i] > 0:
                    first_valid_rx_ts = ts[i]
                    break
            
            # Check if final TX stage was hit
            final_tx_ts = ts[TX_STAGE_6_DEV_XMIT]
            
            # Check latency threshold only if we have valid start and end points
            if latency_threshold_ns > 0 and first_valid_rx_ts > 0 and final_tx_ts > 0:
                total_latency = final_tx_ts - first_valid_rx_ts
                if total_latency < latency_threshold_ns:
                    return # Skip printing if below threshold
            elif first_valid_rx_ts == 0 or final_tx_ts == 0:
                # If we cannot calculate latency (missing start or end), 
                # apply threshold=0 logic (always print if threshold wasn't set > 0)
                if latency_threshold_ns > 0:
                     return # Don't print if threshold was set but latency is unmeasurable

            # If checks pass, call the main printing function
            print_latency_event(cpu, data, size)

        # Open perf buffer with the new handler
        b["latency_events"].open_perf_buffer(handle_perf_event, page_cnt=128)
    except Exception as e:
        print("Error opening perf buffer: %s" % e)
        sys.exit(1)

    # --- Probe Attachment --- Updated ---
    probe_points = [
        "__netif_receive_skb",   # Stage 0 (NEW START POINT)
        "netdev_frame_hook",     # Stage 1
        "ovs_dp_process_packet", # Stage 2(RX)/9(TX)
        "ovs_dp_upcall",         # Stage 3(RX)/10(TX)
        "ovs_execute_actions",   # Stage 4(RX)/11(TX)
        "ovs_vport_send",        # Stage 5(RX)/12(TX)
        "icmp_rcv",              # Stage 6
        "ip_send_skb",           # << CHANGED from __ip_queue_xmit (Stage 7)
        "internal_dev_xmit",     # Stage 8
        "dev_queue_xmit",        # Stage 13
    ]
    probe_map = {
        "__netif_receive_skb": "kprobe____netif_receive_skb",
        "netdev_frame_hook": "kprobe__netdev_frame_hook",
        "ovs_dp_process_packet": "kprobe__ovs_dp_process_packet",
        "ovs_dp_upcall": "kprobe__ovs_dp_upcall",
        "ovs_execute_actions": "kprobe__ovs_execute_actions",
        "ovs_vport_send": "kprobe__ovs_vport_send",
        "icmp_rcv": "kprobe__icmp_rcv",
        "ip_send_skb": "kprobe__ip_send_skb", # << CHANGED from __ip_queue_xmit map
        "internal_dev_xmit": "kprobe__internal_dev_xmit",
        "dev_queue_xmit": "kprobe__dev_queue_xmit",
    }

    attached_probes = 0
    # Check kernel symbols first
    available_ksyms = set()
    all_ksyms_checked = True
    print("Checking kernel symbols...")
    for sym in probe_points:
         try:
             # Check if symbol exists using BPF.ksymname (more reliable)
             # Note: Ensure 'b' (BPF object) is defined before this loop
             if b.ksymname(sym):
                  available_ksyms.add(sym)
             else:
                  print("Info: Kernel symbol '%s' not found." % sym)
         except AttributeError:
             # Fallback if ksymname isn't available on the BPF object directly
             # This check might be less reliable or need adjustment based on BCC version
             print("Warning: Cannot use b.ksymname, trying alternative check for '%s'" % sym)
             try:
                 if BPF.get_kprobe_functions(sym): available_ksyms.add(sym)
                 else: print("Info: Kernel symbol '%s' not found (fallback)." % sym)
             except Exception as e_inner:
                 print("Warning: Fallback check failed for ksym '%s' (%s). Assuming unavailable." % (sym, e_inner))
                 all_ksyms_checked = False
         except Exception as e:
              print("Warning: Could not check ksym '%s' (%s). Assuming unavailable." % (sym, e))
              all_ksyms_checked = False


    print("Attaching probes...")
    for func in probe_points:
        if func not in available_ksyms:
             # Already printed info above if not found
             continue
        bpf_func_name = probe_map.get(func)
        if not bpf_func_name: continue
        try:
            # --- THIS IS THE CRITICAL ATTACHMENT CALL ---
            b.attach_kprobe(event=func, fn_name=bpf_func_name)
            # print("Attached kprobe to %s" % func) # Uncomment for verbose logging
            attached_probes += 1
        except Exception as e:
             print("Failed to attach kprobe to %s: %s" % (func, e))
             # Exit if critical probes fail to attach
             if func in ["napi_gro_receive", "dev_queue_xmit", "ip_send_skb"]: # Updated critical check
                  print("Error: Failed attaching critical probe '%s'. Exiting." % func)
                  sys.exit(1)

    # Check if minimum required probes attached (Stage 0 and Stage 13)
    if not b.ksymname("__netif_receive_skb") or not b.ksymname("dev_queue_xmit") or not b.ksymname("ip_send_skb"):
         print("\nError: Critical probes (__netif_receive_skb, ip_send_skb, dev_queue_xmit) could not be attached or resolved. Exiting.")
        sys.exit(1)

    print("\nAttached %d probes." % attached_probes)
    if attached_probes < len(available_ksyms): # Compare against found symbols
         print("Warning: Not all *found* probes could be attached.")
    if not all_ksyms_checked:
        print("Warning: Symbol availability check was incomplete.")

    while True:
        try:
            b.perf_buffer_poll() # Block until events
        except KeyboardInterrupt:
            print("\nDetaching probes and exiting...")
            # Optional: Detach probes (consider order?)
            # for func in reversed(probe_points): ...
            exit()
        except ValueError as e:
             if "negative size" in str(e):
                  print("\nError: Perf buffer issue likely due to data size mismatch (check C/Python structs). Exiting.")
                  # Consider printing struct sizes
                  # print("Size of LatencyEventData (Python): %d bytes" % ctypes.sizeof(LatencyEventData))
                  exit(1)
             else:
                  print("Error in main loop (ValueError): %s" % e)
                  sleep(1)
        except Exception as e:
            print("Error in main loop: %s" % e)
            sleep(1) # Avoid busy-looping