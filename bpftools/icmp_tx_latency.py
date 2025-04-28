#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from bcc import BPF
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
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()
# --- End get_if_index ---

# --- BPF C Code ---
# Simplified for TX path only
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/flow.h> // For flowi4

// User Filters
#define USR_SRC_IP 0x%x
#define USR_DST_IP 0x%x
#define LATENCY_THRESHOLD_NS %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d

// --- Stages --- TX ONLY ---
#define TX_STAGE_0_IP_SEND_SKB    0
#define TX_STAGE_1_INTERNAL_XMIT  1
#define TX_STAGE_2_DP_PROCESS     2
#define TX_STAGE_3_DP_UPCALL      3
#define TX_STAGE_4_EXEC_ACTIONS   4
#define TX_STAGE_5_VPORT_SEND     5 // To physical port
#define TX_STAGE_6_DEV_XMIT       6
#define MAX_STAGES                7 // 0-6

// --- Session Key (IPs ordered + Seq) ---
struct session_key_t {
    __be32 ip1;
    __be32 ip2;
    u16 seq; // Network byte order
};

// --- Packet Info (For context) ---
struct packet_info_t {
    __be32 sip;
    __be32 dip;
    u8  proto;
    u8  icmp_type;
    __be16 id;
};

#define IFNAMSIZ 16
#define TASK_COMM_LEN 16

// --- Flow Data (Value in Map) --- SIMPLIFIED ---
struct flow_data_t {
    u64 ts[MAX_STAGES]; // Only 7 stages now
    int kstack_id[MAX_STAGES];
    struct packet_info_t req_info; // Info from the request packet
    u32 tx_start_pid;
    char tx_start_comm[TASK_COMM_LEN];
    char tx_start_ifname[IFNAMSIZ]; // Interface seen at TX stage 0
};

// --- Perf Event Data --- SIMPLIFIED ---
struct event_t {
    struct session_key_t key;
    struct flow_data_t data;
};

// --- Maps ---
BPF_TABLE("lru_hash", struct session_key_t, struct flow_data_t, flow_sessions, 20480);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_t, 1);

// --- Helper: Parse SKB --- SIMPLIFIED ---
// Returns: 1=Request(TX Path), 0=Ignore
static __always_inline int parse_skb(struct sk_buff *skb, struct session_key_t *key, struct packet_info_t *info, int stage_id)
{
    //bpf_trace_printk("BPF DBG: Enter parse_skb"); // Add if needed
    if (!skb) return 0;
    unsigned char *head = NULL;
    u16 network_header = 0;
    u16 transport_header = 0;
    u32 len = 0;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) return 0;


    if (network_header == 0) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail net_hdr is 0"); // 
        }
        return 0;
    }

    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header) < 0) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail IP read"); // 
        }
        return 0;
    }

    // --- Filter for specific Request Packet ---
    if (iph.protocol != IPPROTO_ICMP) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail IP/Proto match"); // 
        }
        return 0;
    }

    if (iph.saddr != USR_SRC_IP || iph.daddr != USR_DST_IP) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse:  failed src && dst ip match, ip.saddr=0x%%x ip.daddr=0x%%x", iph.saddr, iph.daddr); // 
        }
        return 0;
    }

    if (transport_header == 0) {
        u8 ihl = iph.ihl & 0x0F;
        if (ihl < 5) { 
            if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
                //bpf_trace_printk("BPF DBG Parse: Fail invalid IHL"); 
            }
            return 0; 
        }
        transport_header = network_header + ihl * 4;
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Calculated trans_hdr=0x%%x", transport_header); // 
        }
    }

    struct icmphdr icmph;
    void *data_end = (void *)(head + len);
     if ((void*)(head + transport_header + sizeof(icmph)) > data_end) {
            if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
                //bpf_trace_printk("BPF DBG Parse: Fail ICMP boundary check"); // 
        }
        return 0;
    }
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header) < 0) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail ICMP read"); // 
        }
        return 0;
    }

    if (icmph.type != ICMP_ECHO) {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail ICMP Type check"); // 
        }
        return 0;
    }

    info->sip = iph.saddr;
    info->dip = iph.daddr;
    info->proto = iph.protocol;
    info->icmp_type = icmph.type;
    info->id = icmph.un.echo.id;

    if (USR_SRC_IP < USR_DST_IP) {
        key->ip1 = USR_SRC_IP;
        key->ip2 = USR_DST_IP;
    } else {
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            //bpf_trace_printk("BPF DBG Parse: Fail IP order"); // 
        }
        key->ip1 = USR_DST_IP;
        key->ip2 = USR_SRC_IP;
    }
    key->seq = icmph.un.echo.sequence;

    //if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
    //if (stage_id == TX_STAGE_1_INTERNAL_XMIT) {
        //bpf_trace_printk("BPF DBG Parse: Stage %%d, icmp type: %%d", stage_id, info->icmp_type);
        //bpf_trace_printk("BPF DBG Parse: Success, key.ip1=0x%%x key.ip2=0x%%x key.seq=%%d", key->ip1, key->ip2, key->seq); // 
    //}
    return 1; // It's the request packet
}

// --- Main Event Handler --- UPDATED Map Logic ---
static __always_inline void handle_event(
    struct pt_regs *ctx,
    struct sk_buff *skb,
    u64 stage_id,
    struct session_key_t *key,
    struct packet_info_t *info
) {
    if (!skb || !key || !info || stage_id >= MAX_STAGES) return;

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, 0);
    struct flow_data_t *flow_ptr, zero = {};

    // --- Map Interaction: Init ONLY at Stage 0, Lookup otherwise ---
    if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
        // Try to init map ONLY at Stage 0
        flow_ptr = flow_sessions.lookup_or_try_init(key, &zero);
        if (!flow_ptr) {
            //bpf_trace_printk("BPF DBG: Map Init FAILED (Stage=0)");
            return; // Map init failed
        }
        // If init successful, proceed to record data for Stage 0 below
    } else {
        // For all subsequent stages, strictly lookup
        flow_ptr = flow_sessions.lookup(key);
        if (!flow_ptr) {
            //bpf_trace_printk("BPF DBG: Lookup FAILED (Stage=%%llu)", stage_id); // 
            return; // Entry doesn't exist (Stage 0 missed or evicted), ignore this stage
        }
        // If lookup successful, proceed to record data below
    }
    // --- End Map Interaction ---
    //if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
    //if (stage_id == TX_STAGE_1_INTERNAL_XMIT) {
        //bpf_trace_printk("BPF DBG handle_event: Stage %%d, ts=%%d, icmp type: %%d", stage_id, flow_ptr->ts[stage_id], info->icmp_type);
        //bpf_trace_printk("BPF DBG handle_event: Success, key.ip1=0x%%x key.ip2=0x%%x key.seq=%%d", key->ip1, key->ip2, key->seq); // 
    //}

    // --- Record Timestamp, Stack ID, and Context ---
    // Record if timestamp for this stage is not already set
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->kstack_id[stage_id] = stack_id;

        // Store Initial TX Context (ONLY when recording Stage 0)
        if (stage_id == TX_STAGE_0_IP_SEND_SKB) {
            // Check tx_start_pid==0 removed, as this branch only runs once anyway if ts[0]==0
            flow_ptr->tx_start_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->tx_start_comm, sizeof(flow_ptr->tx_start_comm));
            struct net_device *dev = NULL;
            bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
            if (dev) bpf_probe_read_kernel_str(flow_ptr->tx_start_ifname, IFNAMSIZ, dev->name);
            else flow_ptr->tx_start_ifname[0] = '?';
            flow_ptr->tx_start_ifname[IFNAMSIZ - 1] = '\\0';
            flow_ptr->req_info = *info;
        }
    }

    // --- Submit Event from Final TX Stage (index 6) ---
    if (stage_id == TX_STAGE_6_DEV_XMIT) {
        u32 zero_key = 0;
        struct event_t *event_data_ptr = event_scratch_map.lookup(&zero_key);
        if (!event_data_ptr) return;

        event_data_ptr->key = *key;
        // Use bpf_probe_read_kernel for safety when copying from flow_ptr
        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr) != 0) {
            flow_sessions.delete(key);
            return;
        }

        // Latency Threshold Check (Still based on Stage 0 start)
        u64 tx_start_ts = event_data_ptr->data.ts[TX_STAGE_0_IP_SEND_SKB];
        // End timestamp is the one recorded for *this* stage (TX_STAGE_6)
        u64 tx_end_ts = event_data_ptr->data.ts[TX_STAGE_6_DEV_XMIT];
        if (LATENCY_THRESHOLD_NS > 0 && tx_start_ts > 0) {
            if ((tx_end_ts - tx_start_ts) < LATENCY_THRESHOLD_NS) { return; }
        } else if (tx_start_ts == 0 && LATENCY_THRESHOLD_NS > 0) { return; }

        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
        flow_sessions.delete(key);
    }
}

// --- KProbes --- TX ONLY ---
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    int ret = parse_skb(skb, &key, &info, TX_STAGE_0_IP_SEND_SKB);
    if (ret != 1) { // Must be Request
        return 0;
    }
    // bpf_trace_printk("BPF DBG: ip_send_skb Parse OK, calling handler"); // Keep this commented for now
    handle_event(ctx, skb, TX_STAGE_0_IP_SEND_SKB, &key, &info);
    return 0;
}
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb(skb, &key, &info, TX_STAGE_1_INTERNAL_XMIT) != 1) return 0;
    handle_event(ctx, skb, TX_STAGE_1_INTERNAL_XMIT, &key, &info);
    return 0;
}
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb((struct sk_buff *)skb, &key, &info, TX_STAGE_2_DP_PROCESS) != 1) return 0; // Only care about TX path now
    handle_event(ctx, (struct sk_buff *)skb, TX_STAGE_2_DP_PROCESS, &key, &info);
    return 0;
}
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb((struct sk_buff *)skb, &key, &info, TX_STAGE_3_DP_UPCALL) != 1) return 0;
    handle_event(ctx, (struct sk_buff *)skb, TX_STAGE_3_DP_UPCALL, &key, &info);
    return 0;
}
int kprobe__ovs_execute_actions(struct pt_regs *ctx, void *dp, struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb(skb, &key, &info, TX_STAGE_4_EXEC_ACTIONS) != 1) return 0;
    handle_event(ctx, skb, TX_STAGE_4_EXEC_ACTIONS, &key, &info);
    return 0;
}
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb(skb, &key, &info, TX_STAGE_5_VPORT_SEND) != 1) return 0;
    handle_event(ctx, skb, TX_STAGE_5_VPORT_SEND, &key, &info);
    return 0;
}
int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct session_key_t key = {}; struct packet_info_t info = {};
    if (parse_skb(skb, &key, &info, TX_STAGE_6_DEV_XMIT) != 1) return 0;

    // --- MODIFIED ifindex Check ---
    struct net_device *dev = NULL;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) == 0) {
             // Check if current index matches EITHER target index
             if (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2) {
                  //bpf_trace_printk("BPF DBG: dev_queue_xmit ifindex MATCH (%%d), calling handler", ifindex);  
                  handle_event(ctx, skb, TX_STAGE_6_DEV_XMIT, &key, &info); // Stage 6
             } else {
                  // Optional: trace non-matching ifindex
                  // bpf_trace_printk("BPF DBG: dev_queue_xmit wrong ifindex=%%d, targets=%%d|%%d", ifindex, TARGET_IFINDEX1, TARGET_IFINDEX2);
             }
        }
    }
    // --- End ifindex Check ---

    return 0;
}

"""

# Python Code Starts Here
MAX_STAGES = 7 # 0-6 TX Stages
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# --- CTypes Structs --- SIMPLIFIED ---
class SessionKey(Structure):
    _fields_ = [ ("ip1", c_uint32), ("ip2", c_uint32), ("seq", c_uint16)]

class PacketInfo(Structure):
    _fields_ = [ ("sip", c_uint32), ("dip", c_uint32), ("proto", c_uint8), ("icmp_type", c_uint8), ("id", c_uint16)]

class FlowData(Structure): # Simplified
    _fields_ = [
        ("ts", c_uint64 * MAX_STAGES),
        ("kstack_id", c_int * MAX_STAGES),
        ("req_info", PacketInfo),
        ("tx_start_pid", c_uint32),
        ("tx_start_comm", c_char * TASK_COMM_LEN),
        ("tx_start_ifname", c_char * IFNAMSIZ),
    ]

class EventData(Structure): # Renamed from latency_event_data_t
    _fields_ = [ ("key", SessionKey), ("data", FlowData) ]
# --- End CTypes ---

# --- Stage Names --- TX ONLY ---
stage_names = {
    0: "TX:IP_SEND_SKB",    1: "TX:INTERNAL_XMIT",  2: "TX:DP_PROCESS",
    3: "TX:DP_UPCALL",      4: "TX:EXEC_ACTIONS",   5: "TX:VPORT_SEND(->phy)",
    6: "TX:DEV_XMIT",
}
# Stage constants
TX_STAGE_0_IP_SEND_SKB    = 0
TX_STAGE_1_INTERNAL_XMIT  = 1
TX_STAGE_2_DP_PROCESS     = 2
TX_STAGE_3_DP_UPCALL      = 3
TX_STAGE_4_EXEC_ACTIONS   = 4
TX_STAGE_5_VPORT_SEND     = 5
TX_STAGE_6_DEV_XMIT       = 6
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
    if addr == 0: return "0.0.0.0"
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def format_latency(ts_start, ts_end):
    if ts_start == 0 or ts_end == 0 or ts_end < ts_start:
        return " N/A ".rjust(7)
    delta_us = (ts_end - ts_start) / 1000.0
    return ("%.3f" % delta_us).rjust(7)
# --- End Helper Functions ---

# --- Main Print Function --- SIMPLIFIED ---
def print_event_data(event):
    flow = event.data
    skey = event.key
    req = flow.req_info

    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    req_sip_str = format_ip(req.sip)
    req_dip_str = format_ip(req.dip)
    seq_str = str(socket.ntohs(skey.seq))

    print("--- %s ---" % time_str)
    print("SESSION: %s -> %s Seq=%s" % (req_sip_str, req_dip_str, seq_str))
    print("  Request: %s -> %s (ID: %d, Type: %d)" % (req_sip_str, req_dip_str, socket.ntohs(req.id), req.icmp_type))

    print("  TX Start Context: PID=%-6d COMM=%-12s IF=%-10s" % (
          flow.tx_start_pid, flow.tx_start_comm.decode('utf-8', 'replace'),
          flow.tx_start_ifname.decode('utf-8', 'replace')))

    # --- Latency Calculation & Printing ---
    ts = flow.ts
    latencies = []
    # TX Path (Stages 0-6)
    latencies.append(format_latency(ts[0], ts[1])) # 0->1 IP_SEND->INT_XMIT
    latencies.append(format_latency(ts[1], ts[2])) # 1->2 INT_XMIT->DP_PROC
    if ts[TX_STAGE_3_DP_UPCALL] > 0: # TX Flow Miss path 2->3->4
        latencies.append(format_latency(ts[2], ts[3])) # 2->3 DP_PROC->UPCALL
        latencies.append(format_latency(ts[3], ts[4])) # 3->4 UPCALL->EXEC
    else: # TX Flow Hit path 2->4
        latencies.append("   Skip   ".rjust(7))
        latencies.append(format_latency(ts[2], ts[4])) # 2->4
    latencies.append(format_latency(ts[4], ts[5])) # 4->5 EXEC->VPORT(phy)
    latencies.append(format_latency(ts[5], ts[6])) # 5->6 VPORT(phy)->DEV_XMIT
    tx_total = format_latency(ts[TX_STAGE_0_IP_SEND_SKB], ts[TX_STAGE_6_DEV_XMIT])

    print("  Latencies TX (us): [0->1]:%s [1->2]:%s [2->3]:%s [3->4]:%s [4->5]:%s [5->6]:%s | Total[0->6]:%s" %
          (tuple(latencies[0:6]) + (tx_total,)))
    if ts[TX_STAGE_3_DP_UPCALL] > 0: print("  (TX Path: Flow Miss)")

    # --- Stack Traces ---
    print("  Kernel Stack Traces:")
    kstack_id = flow.kstack_id
    for i in range(MAX_STAGES):
        stage_name = stage_names.get(i, "?")
        stack_id = kstack_id[i]
        timestamp = ts[i]
        # Skip printing stack if stage was logically skipped
        is_tx_upcall_stage = (i == TX_STAGE_3_DP_UPCALL)
        was_tx_upcall_skipped = (is_tx_upcall_stage and ts[TX_STAGE_3_DP_UPCALL] == 0 and ts[TX_STAGE_2_DP_PROCESS] != 0)
        if was_tx_upcall_skipped: print("    Stage %d (%s): <Skipped - TX Flow Hit>" % (i, stage_name)); continue

        if timestamp == 0: print("    Stage %d (%s): <Missed>" % (i, stage_name)); continue
        if stack_id < 0: print("    Stage %d (%s): <Stack Capture Failed Error: %d>" % (i, stage_name, stack_id)); continue
        if stack_id == 0: print("    Stage %d (%s): <Stack ID is 0>" % (i, stage_name)); continue

        print("    Stage %d (%s): Stack ID %d" % (i, stage_name, stack_id))
        try:
            for addr in b.get_table("stack_traces").walk(stack_id):
                 sym = b.ksym(addr, show_offset=True)
                 print("      %s" % sym)
        except Exception as e: print("      <Error resolving stack: %s>" % e)
    print("")
# --- End Print Function ---

# --- Main Execution --- UPDATED ---
if __name__ == "__main__":
    if os.geteuid() != 0: print("Requires root privileges"); sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Trace ICMP Request TX Latency, filtering final stage by one of two physical interfaces.") # Updated desc
    parser.add_argument('--src-ip', type=str, required=True, help='Source IP of ICMP Request (where trace runs)')
    parser.add_argument('--dst-ip', type=str, required=True, help='Destination IP of ICMP Request')
    # Modify to accept two interface names
    parser.add_argument('--phy-iface1', type=str, required=True, help='First possible physical interface for final TX')
    parser.add_argument('--phy-iface2', type=str, required=True, help='Second possible physical interface for final TX')
    parser.add_argument('--latency-ms', type=float, default=0,
                        help='Minimum TX latency (TX Stage 0 -> TX Stage 6) in ms to report (default: 0, report all)')
    args = parser.parse_args()

    # --- Get target ifindexes for both interfaces ---
    try:
        target_ifindex1 = get_if_index(args.phy_iface1)
        print("Target physical interface 1: {} (ifindex: {})".format(args.phy_iface1, target_ifindex1))
    except OSError as e:
        print("Error getting index for interface '{}': {}".format(args.phy_iface1, e)); sys.exit(1)

    try:
        target_ifindex2 = get_if_index(args.phy_iface2)
        print("Target physical interface 2: {} (ifindex: {})".format(args.phy_iface2, target_ifindex2))
    except OSError as e:
        print("Error getting index for interface '{}': {}".format(args.phy_iface2, e)); sys.exit(1)

    # Check if indices are the same
    if target_ifindex1 == target_ifindex2:
        print("Warning: The two specified interfaces have the same index ({}).".format(target_ifindex1))
    # --- End Get ifindexes ---

    # --- Convert IPs and Threshold ---
    src_ip_filter_hex = ip_to_hex(args.src_ip)
    dst_ip_filter_hex = ip_to_hex(args.dst_ip)
    latency_threshold_ns = int(args.latency_ms * 1000000)

    print("Tracing ICMP TX Request (%s -> %s)" % (args.src_ip, args.dst_ip))
    # Update print statement for filtering
    if latency_threshold_ns > 0: print("Reporting only if TX latency [0->6] on ifindex {} or {} >= {:.3f} ms".format(target_ifindex1, target_ifindex2, args.latency_ms))

    # ... (OVS Check) ...

    # --- Prepare BPF text - Needs 5 arguments now (IPs, threshold, index1, index2) ---
    final_bpf_text = bpf_text % (src_ip_filter_hex, dst_ip_filter_hex, latency_threshold_ns, target_ifindex1, target_ifindex2)

    cflags = ["-Wno-unused-value", "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types"]
    try:
        global b
        b = BPF(text=final_bpf_text, cflags=cflags)
    except Exception as e:
        print("Error compiling/loading BPF: %s" % e); sys.exit(1)

    # --- Probe Attachment --- TX ONLY ---
    probe_points = [
        "ip_send_skb", "internal_dev_xmit", "ovs_dp_process_packet",
        "ovs_dp_upcall", "ovs_execute_actions", "ovs_vport_send", "dev_queue_xmit"
    ]
    probe_map = {
        "ip_send_skb": "kprobe__ip_send_skb",
        "internal_dev_xmit": "kprobe__internal_dev_xmit",
        "ovs_dp_process_packet": "kprobe__ovs_dp_process_packet",
        "ovs_dp_upcall": "kprobe__ovs_dp_upcall",
        "ovs_execute_actions": "kprobe__ovs_execute_actions",
        "ovs_vport_send": "kprobe__ovs_vport_send",
        "dev_queue_xmit": "kprobe__dev_queue_xmit",
    }

    print("Attaching probes...")
    attached_probes = 0
    for func in probe_points:
        try:
            if not b.ksymname(func):
                 print("Info: Kernel symbol '%s' not found, skipping." % func); continue
        except Exception:
            print("Warning: Could not check ksym '%s'. Assuming available." % func)

        bpf_func_name = probe_map.get(func)
        if not bpf_func_name:
            print("Warning: No BPF function mapping found for '%s'." % func); continue
        try:
            b.attach_kprobe(event=func, fn_name=bpf_func_name)
            attached_probes += 1
        except Exception as e:
            print("Failed attaching kprobe %s to %s: %s" % (bpf_func_name, func, e))
            if func in ["ip_send_skb", "dev_queue_xmit"]: # Critical TX probes
                 print("Critical probe failed, exiting."); sys.exit(1)

    print("Attached %d probes." % attached_probes)
    if attached_probes < len(probe_points):
         print("Warning: Not all TX probes attached successfully.")

    # Critical check
    if not b.ksymname("ip_send_skb") or not b.ksymname("dev_queue_xmit"):
        print("\nError: Critical TX start/end probes could not be probed. Exiting."); sys.exit(1)

    # --- Perf Buffer Setup --- UPDATED Wrapper ---
    def handle_perf_event_wrapper(cpu, data, size):
        event = cast(data, POINTER(EventData)).contents
        ts = event.data.ts
        tx_start_ts = ts[TX_STAGE_0_IP_SEND_SKB]
        tx_end_ts = ts[TX_STAGE_6_DEV_XMIT]

        if latency_threshold_ns > 0:
            if tx_start_ts > 0 and tx_end_ts > 0:
                 if (tx_end_ts - tx_start_ts) < latency_threshold_ns: return
            else: # Cannot calculate latency if start or end missing
                 return

        print_event_data(event) # Call actual print function

    try:
        b["events"].open_perf_buffer(handle_perf_event_wrapper, page_cnt=128)
    except Exception as e:
        print("Error opening perf buffer: %s" % e); sys.exit(1)

    print("\nTracing... Hit Ctrl-C to end.")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching..."); exit()
        except Exception as e:
            print("Error during poll: %s" % e); sleep(1)
