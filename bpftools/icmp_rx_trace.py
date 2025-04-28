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

# --- Function to get ifindex ---
def get_if_index(devname):
    """Python2 fallback for socket.if_nametoindex"""
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
# --- End get_if_index ---

# --- BPF C Code ---
# Focused on RX path only
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/flow.h> // For flowi4? Might not be needed for RX

// User Filters
#define USR_SRC_IP 0x%x // IP of original request source (Reply Destination)
#define USR_DST_IP 0x%x // IP of original request dest (Reply Source)
#define TARGET_IFINDEX %d // Physical interface for RX Stage 0
#define LATENCY_THRESHOLD_NS %d

// --- Stages --- RX ONLY ---
#define RX_STAGE_0_NETIF_RECV     0 // Filtered by TARGET_IFINDEX
#define RX_STAGE_1_NETDEV_FRAME   1
#define RX_STAGE_2_DP_PROCESS     2
#define RX_STAGE_3_DP_UPCALL      3
#define RX_STAGE_4_EXEC_ACTIONS   4
#define RX_STAGE_5_VPORT_SEND     5 // To internal port
#define RX_STAGE_6_ICMP_RCV       6
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

// --- Flow Data (Value in Map) --- RX FOCUS ---
struct flow_data_t {
    u64 ts[MAX_STAGES]; // Only RX stages
    int kstack_id[MAX_STAGES];
    struct packet_info_t rep_info; // Info from the reply packet
    u32 rx_start_pid;
    char rx_start_comm[TASK_COMM_LEN];
    // rx_start_ifname is implied by TARGET_IFINDEX filter
};

// --- Perf Event Data ---
struct event_t {
    struct session_key_t key;
    struct flow_data_t data;
};

// --- Maps ---
BPF_TABLE("lru_hash", struct session_key_t, struct flow_data_t, flow_sessions, 20480);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_t, 1);

// --- Helper: Parse SKB --- RX FOCUS ---
// Returns: 2=Reply(RX Path), 0=Ignore
static __always_inline int parse_skb(struct sk_buff *skb, struct session_key_t *key, struct packet_info_t *info, int stage_id)
{
    if (!skb) return 0;
    unsigned char *head = NULL;
    u16 network_header = 0;
    u16 transport_header = 0;
    u32 len = 0;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) return 0;

    if (network_header == 0) return 0;

    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) return 0;

    // --- Filter for specific Reply Packet ---
    if (iph.saddr != USR_DST_IP || iph.daddr != USR_SRC_IP || iph.protocol != IPPROTO_ICMP) {
        return 0;
    }

    if (transport_header == 0) {
        u8 ihl = iph.ihl & 0x0F;
        if (ihl < 5) return 0;
        transport_header = network_header + ihl * 4;
    }

    struct icmphdr icmph;
    void *data_end = (void *)(head + len);
     if ((void*)(head + transport_header + sizeof(icmph)) > data_end) return 0;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header) < 0) return 0;

    // Check if it's an Echo Reply
    if (icmph.type != ICMP_ECHOREPLY) {
        return 0;
    }

    // Populate info struct
    info->sip = iph.saddr;
    info->dip = iph.daddr;
    info->proto = iph.protocol;
    info->icmp_type = icmph.type;
    info->id = icmph.un.echo.id;

    // Populate session key (use defined order based on user input IPs)
    if (USR_SRC_IP < USR_DST_IP) {
        key->ip1 = USR_SRC_IP;
        key->ip2 = USR_DST_IP;
    } else {
        key->ip1 = USR_DST_IP;
        key->ip2 = USR_SRC_IP;
    }
    key->seq = icmph.un.echo.sequence;

    bpf_trace_printk("BPF DBG Parse: Stage %%d, icmp type: %%d", stage_id, info->icmp_type);
    bpf_trace_printk("BPF DBG Parse: Success, key.ip1=0x%%x key.ip2=0x%%x key.seq=%%d", key->ip1, key->ip2, key->seq); // 

    return 2; // It's the reply packet
}

// --- Main Event Handler --- RX FOCUS ---
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

    // --- Map Interaction: Init ONLY at Stage 0 ---
    if (stage_id == RX_STAGE_0_NETIF_RECV || stage_id == RX_STAGE_1_NETDEV_FRAME || stage_id == RX_STAGE_2_DP_PROCESS) {
        flow_ptr = flow_sessions.lookup_or_try_init(key, &zero);
        if (!flow_ptr) {
            // Map init failed
            bpf_trace_printk("BPF DBG: Map Init FAILED (Stage=0)");
            return; 
        }
        // If init successful, proceed to record data for Stage 0 below
    } else {
        flow_ptr = flow_sessions.lookup(key);
        if (!flow_ptr) {
            // Entry doesn't exist (Stage 0 missed or evicted), ignore this stage
            bpf_trace_printk("BPF DBG: Lookup FAILED (Stage=%%llu)", stage_id); // 
            return; 
        }
        // If lookup successful, proceed to record data below
    }
    bpf_trace_printk("BPF DBG handle_event: Stage %%d, ts=%%d, icmp type: %%d", stage_id, flow_ptr->ts[stage_id], info->icmp_type);
    bpf_trace_printk("BPF DBG handle_event: Success, key.ip1=0x%%x key.ip2=0x%%x key.seq=%%d", key->ip1, key->ip2, key->seq); // 

    // Record TS & Stack if not set
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->kstack_id[stage_id] = stack_id;

        // Store Initial RX Context (Only Once at stage 0)
        if (stage_id == RX_STAGE_0_NETIF_RECV && flow_ptr->rx_start_pid == 0) {
            flow_ptr->rx_start_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->rx_start_comm, sizeof(flow_ptr->rx_start_comm));
            flow_ptr->rep_info = *info; // Store reply info
        }
    }

    // --- Submit Event from Final RX Stage (index 6) ---
    if (stage_id == RX_STAGE_6_ICMP_RCV) {
        u32 zero_key = 0;
        struct event_t *event_data_ptr = event_scratch_map.lookup(&zero_key);
        if (!event_data_ptr) return;

        event_data_ptr->key = *key;
        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr) != 0) {
            flow_sessions.delete(key); return;
        }

        // Latency Threshold Check (RX Start -> RX End)
        u64 rx_start_ts = event_data_ptr->data.ts[RX_STAGE_0_NETIF_RECV];
        u64 rx_end_ts = current_ts;
        if (LATENCY_THRESHOLD_NS > 0 && rx_start_ts > 0) {
            if ((rx_end_ts - rx_start_ts) < LATENCY_THRESHOLD_NS) { return; }
        } else if (rx_start_ts == 0 && LATENCY_THRESHOLD_NS > 0) { return; }

        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
        flow_sessions.delete(key);
    }
}

// Helper to check ifindex
static __always_inline bool is_target_ifindex(struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        //bpf_trace_printk("BPF DBG: Failed reading skb->dev\n");
        return false; // Cannot determine
    }
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        //bpf_trace_printk("BPF DBG: Failed reading dev->ifindex\n");
        return false; // Cannot read index
    }
    return (ifindex == TARGET_IFINDEX);
}

// REINSTATE kprobe____netif_receive_skb as Stage 0 probe
int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    // --- ADDED Ifindex Filter --- 
    if (!is_target_ifindex(skb)) {
        return 0; // Not from the target physical interface
    }
    // If it IS the target interface, proceed to handle event
    handle_event(ctx, skb, RX_STAGE_0_NETIF_RECV, NULL, NULL); // Stage 0
    return 0;
}

// UPDATED: netdev_frame_hook is now Stage 1
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff *skb) {
    // --- ADDED Ifindex Filter --- 
    if (!is_target_ifindex(skb)) {
        // If the packet arrived here but *didn't* come from the target phy iface
        // (e.g., loopback, other virtual ports), we ignore it for latency tracking.
        return 0;
    }
    // If it IS the target interface, proceed to handle event
    handle_event(ctx, skb, RX_STAGE_1_NETDEV_FRAME, NULL, NULL); // Stage 1
    return 0;
}

// Subsequent probes call handle_event with their NEW stage IDs (2-5)
// Filter added to ovs_dp_process_packet
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb, void *item) {
    // --- ADDED Ifindex Filter --- 
    if (!is_target_ifindex((struct sk_buff *)skb)) { 
        return 0;
    }
    // If it IS the target interface, proceed to handle event
    handle_event(ctx, (struct sk_buff *)skb, RX_STAGE_2_DP_PROCESS, NULL, NULL);
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb, const void *upcall_info) {
    handle_event(ctx, (struct sk_buff *)skb, RX_STAGE_3_DP_UPCALL, NULL, NULL);
    return 0;
}

int kprobe__ovs_execute_actions(struct pt_regs *ctx, void *dp, struct sk_buff *skb) {
    handle_event(ctx, skb, RX_STAGE_4_EXEC_ACTIONS, NULL, NULL);
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    handle_event(ctx, skb, RX_STAGE_5_VPORT_SEND, NULL, NULL);
    return 0;
}

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (skb == NULL) return 0;

    struct packet_info_t key = {};
    if (!parse_skb(skb, &key, NULL, RX_STAGE_6_ICMP_RCV)) {
        return 0;
    }

    u64 final_ts = bpf_ktime_get_ns();
    int final_stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    struct flow_data_t *value_ptr = flow_sessions.lookup(&key);

    if (!value_ptr) {
        return 0; // Packet wasn't tracked or evicted
    }

    // Record final stage data BEFORE threshold check
    value_ptr->ts[RX_STAGE_6_ICMP_RCV] = final_ts;
    value_ptr->kstack_id[RX_STAGE_6_ICMP_RCV] = final_stack_id;

    // --- MODIFIED Latency Threshold Check ---
    if (LATENCY_THRESHOLD_NS > 0) {
        u64 start_ts = 0;
        // Find the first non-zero timestamp from stage 0 to 5
        #pragma unroll
        for (int i = 0; i < 6; i++) { // Check stages 0 through 5
            // Read timestamp safely - important if accessing array directly
            u64 current_stage_ts = 0;
            // Direct access should be okay here as value_ptr is valid,
            // but safer way would be array access if defined differently.
            // Let's assume direct access is fine based on struct definition:
            if (i == 0) current_stage_ts = value_ptr->ts[RX_STAGE_0_NETIF_RECV];
            else if (i == 1) current_stage_ts = value_ptr->ts[RX_STAGE_1_NETDEV_FRAME];
            else if (i == 2) current_stage_ts = value_ptr->ts[RX_STAGE_2_DP_PROCESS];
            else if (i == 3) current_stage_ts = value_ptr->ts[RX_STAGE_3_DP_UPCALL];
            else if (i == 4) current_stage_ts = value_ptr->ts[RX_STAGE_4_EXEC_ACTIONS];
            else if (i == 5) current_stage_ts = value_ptr->ts[RX_STAGE_5_VPORT_SEND];

            if (current_stage_ts > 0) {
                start_ts = current_stage_ts;
                break; // Found the first valid timestamp
            }
        }

        if (start_ts > 0) { // Check if a valid start timestamp was found
            u64 total_latency = final_ts - start_ts;
            if (total_latency < LATENCY_THRESHOLD_NS) {
                // Latency is below threshold, don't submit event.
                // We don't delete from LRU hash here.
                return 0;
            }
            // else: latency is >= threshold, proceed to submit.
        } else {
            // No valid start timestamp found (stages 0-5 were all 0).
            // This case is highly unlikely if we reached icmp_rcv.
            // Decide whether to submit or not. Let's not submit if threshold is set.
             bpf_trace_printk("BPF DBG: No valid start TS found for seq %%u, skipping submit due to threshold.", bpf_ntohs(key.id)); // Escape %
             return 0;
        }
    }
    // --- End MODIFIED Latency Threshold Check ---

    // If threshold is 0 OR latency is >= threshold, prepare and submit data
    struct event_t event_data = {};
    event_data.key = key;
    // Use bpf_probe_read_kernel for safety when copying struct
    if (bpf_probe_read_kernel(&event_data.data, sizeof(event_data.data), value_ptr) != 0) {
        // Handle potential read failure if needed, maybe return 0
        return 0;
    }
    event_data.data.rx_start_pid = value_ptr->rx_start_pid;
    bpf_get_current_comm(&event_data.data.rx_start_comm, sizeof(event_data.data.rx_start_comm));

    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev != NULL) bpf_probe_read_kernel_str(&event_data.data.rx_start_ifname, IFNAMSIZ, dev->name);
    else { char unk[] = "unknown"; __builtin_memcpy(event_data.data.rx_start_ifname, unk, sizeof(unk));}

    events.perf_submit(ctx, &event_data, sizeof(event_data));

    // Note: No explicit delete for LRU map
    return 0;
}

"""

# Python Code Starts Here
MAX_STAGES = 7 # 0-6 RX Stage
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# --- CTypes Structs --- RX FOCUS ---
class SessionKey(Structure):
    _fields_ = [ ("ip1", c_uint32), ("ip2", c_uint32), ("seq", c_uint16)]

class PacketInfo(Structure):
    _fields_ = [ ("sip", c_uint32), ("dip", c_uint32), ("proto", c_uint8), ("icmp_type", c_uint8), ("id", c_uint16)]

class FlowData(Structure): # Simplified for RX
    _fields_ = [
        ("ts", c_uint64 * MAX_STAGES),
        ("kstack_id", c_int * MAX_STAGES),
        ("rep_info", PacketInfo), # Reply info stored
        # Removed req_info
        ("rx_start_pid", c_uint32),
        ("rx_start_comm", c_char * TASK_COMM_LEN),
        # Removed tx_* fields
    ]

class EventData(Structure):
    _fields_ = [ ("key", SessionKey), ("data", FlowData) ]
# --- End CTypes ---

# --- Stage Names --- RX ONLY ---
stage_names = {
    0: "RX:NETIF_RECV", 1: "RX:NETDEV_FRAME", 2: "RX:DP_PROCESS",
    3: "RX:DP_UPCALL", 4: "RX:EXEC_ACTIONS", 5: "RX:VPORT_SEND(->int)",
    6: "RX:ICMP_RCV",
}
# Stage constants
RX_STAGE_0_NETIF_RECV     = 0
RX_STAGE_1_NETDEV_FRAME   = 1
RX_STAGE_2_DP_PROCESS     = 2
RX_STAGE_3_DP_UPCALL      = 3
RX_STAGE_4_EXEC_ACTIONS   = 4
RX_STAGE_5_VPORT_SEND     = 5
RX_STAGE_6_ICMP_RCV       = 6
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


# --- Main Print Function --- RX FOCUS ---
def print_event_data(event):
    flow = event.data
    skey = event.key
    rep = flow.rep_info # Only have reply info now

    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # Use key for session IPs if rep_info wasn't captured (shouldn't happen often with current logic)
    rep_sip_str = format_ip(rep.sip if rep.proto != 0 else skey.ip1) # Assuming ip1 is DST if key is ordered src<dst
    rep_dip_str = format_ip(rep.dip if rep.proto != 0 else skey.ip2) # Assuming ip2 is SRC
    seq_str = str(socket.ntohs(skey.seq))

    print("--- %s ---" % time_str)
    print("SESSION: %s <-> %s Seq=%s" % (rep_dip_str, rep_sip_str, seq_str)) # Show original src/dst from key perspective
    if rep.proto != 0:
        print("  Reply:   %s -> %s (ID: %d, Type: %d)" % (rep_sip_str, rep_dip_str, socket.ntohs(rep.id), rep.icmp_type))
    else:
        print("  Reply:   <Info Missed>") # Should be rare now

    print("  RX Start Context: PID=%-6d COMM=%-12s" % (
          flow.rx_start_pid, flow.rx_start_comm.decode('utf-8', 'replace')))


    # --- Latency Calculation & Printing --- RX ONLY ---
    ts = flow.ts
    latencies_rx = []
    # RX Path (Stages 0-6)
    latencies_rx.append(format_latency(ts[0], ts[1])) # 0->1 NETIF->FRAME
    latencies_rx.append(format_latency(ts[1], ts[2])) # 1->2 FRAME->DP_PROC
    if ts[RX_STAGE_3_DP_UPCALL] > 0: # RX Flow Miss path 2->3->4
        latencies_rx.append(format_latency(ts[2], ts[3])) # 2->3 DP_PROC->UPCALL
        latencies_rx.append(format_latency(ts[3], ts[4])) # 3->4 UPCALL->EXEC
    else: # RX Flow Hit path 2->4
        latencies_rx.append("   Skip   ".rjust(7))
        latencies_rx.append(format_latency(ts[2], ts[4])) # 2->4
    latencies_rx.append(format_latency(ts[4], ts[5])) # 4->5 EXEC->VPORT(int)
    latencies_rx.append(format_latency(ts[5], ts[6])) # 5->6 VPORT(int)->ICMP_RCV
    rx_total = format_latency(ts[RX_STAGE_0_NETIF_RECV], ts[RX_STAGE_6_ICMP_RCV])

    print("  Latencies RX (us): [0->1]:%s [1->2]:%s [2->3]:%s [3->4]:%s [4->5]:%s [5->6]:%s | Total[0->6]:%s" %
          (tuple(latencies_rx[0:6]) + (rx_total,)))
    if ts[RX_STAGE_3_DP_UPCALL] > 0: print("  (RX Path: Flow Miss)")

    # --- Stack Traces --- RX ONLY ---
    print("  Kernel Stack Traces:")
    kstack_id = flow.kstack_id
    for i in range(MAX_STAGES):
        stage_name = stage_names.get(i, "?")
        stack_id = kstack_id[i]
        timestamp = ts[i]
        # Skip / Error / Stack ID 0 / Valid Stack printing logic
        is_rx_upcall_stage = (i == RX_STAGE_3_DP_UPCALL)
        was_rx_upcall_skipped = (is_rx_upcall_stage and ts[RX_STAGE_3_DP_UPCALL] == 0 and ts[RX_STAGE_2_DP_PROCESS] != 0)

        if was_rx_upcall_skipped: print("    Stage %d (%s): <Skipped - RX Flow Hit>" % (i, stage_name)); continue

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

# --- Main Execution --- RX FOCUS ---
if __name__ == "__main__":
    if os.geteuid() != 0: print("Requires root privileges"); sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Trace ICMP Reply RX Latency through kernel/OVS stages.") # Updated
    parser.add_argument('--src-ip', type=str, required=True, help='Source IP of ORIGINAL ICMP Request') # Help clarifies role
    parser.add_argument('--dst-ip', type=str, required=True, help='Destination IP of ORIGINAL ICMP Request (where trace runs)')
    parser.add_argument('--phy-iface', type=str, required=True, help='Physical interface receiving ICMP Reply')
    parser.add_argument('--latency-ms', type=float, default=0,
                        help='Minimum RX latency (Stage 0 -> Stage 6) in ms to report (default: 0, report all)') # Updated help
    args = parser.parse_args()

    # --- Get target ifindex ---
    try:
        target_ifindex = get_if_index(args.phy_iface)
        print("Target physical interface for RX: %s (ifindex: %d)" % (args.phy_iface, target_ifindex))
    except OSError as e:
        print("Error getting index for interface '%s': %s" % (args.phy_iface, e)); sys.exit(1)

    # --- Convert IPs and Threshold ---
    src_ip_filter_hex = ip_to_hex(args.src_ip) # Original Request Source
    dst_ip_filter_hex = ip_to_hex(args.dst_ip) # Original Request Dest (Reply Source)
    latency_threshold_ns = int(args.latency_ms * 1000000)

    print("Tracing ICMP RX Reply (%s -> %s on ifindex %d)" %
          (args.dst_ip, args.src_ip, target_ifindex)) # Updated print
    if latency_threshold_ns > 0: print("Reporting only if RX latency [0->6] >= %.3f ms" % args.latency_ms) # Updated print

    # --- Load BPF --- Needs 4 arguments ---
    final_bpf_text = bpf_text % (src_ip_filter_hex, dst_ip_filter_hex, target_ifindex, latency_threshold_ns)
    cflags = ["-Wno-unused-value", "-Wno-pointer-sign", "-Wno-compare-distinct-pointer-types"]
    try:
        global b
        b = BPF(text=final_bpf_text, cflags=cflags)
    except Exception as e:
        print("Error compiling/loading BPF: %s" % e); sys.exit(1)

    # --- Probe Attachment --- RX ONLY ---
    probe_points = [
        "__netif_receive_skb", "netdev_frame_hook", "ovs_dp_process_packet",
        "ovs_dp_upcall", "ovs_execute_actions", "ovs_vport_send", "icmp_rcv"
    ]
    probe_map = {
        "__netif_receive_skb": "kprobe____netif_receive_skb",
        "netdev_frame_hook": "kprobe__netdev_frame_hook",
        "ovs_dp_process_packet": "kprobe__ovs_dp_process_packet",
        "ovs_dp_upcall": "kprobe__ovs_dp_upcall",
        "ovs_execute_actions": "kprobe__ovs_execute_actions",
        "ovs_vport_send": "kprobe__ovs_vport_send",
        "icmp_rcv": "kprobe__icmp_rcv",
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
        if not bpf_func_name: continue
        try:
            b.attach_kprobe(event=func, fn_name=bpf_func_name)
            attached_probes += 1
        except Exception as e:
            print("Failed attaching kprobe %s to %s: %s" % (bpf_func_name, func, e))
            if func in ["__netif_receive_skb", "icmp_rcv"]: # Critical RX probes
                 print("Critical probe failed, exiting."); sys.exit(1)

    print("Attached %d probes." % attached_probes)
    if attached_probes < len(probe_points):
         print("Warning: Not all RX probes attached successfully.")

    # Critical check
    if not b.ksymname("__netif_receive_skb") or not b.ksymname("icmp_rcv"):
        print("\\nError: Critical RX start/end probes could not be probed. Exiting."); sys.exit(1)


    # --- Perf Buffer Setup --- UPDATED Wrapper ---
    def handle_perf_event_wrapper(cpu, data, size):
        event = cast(data, POINTER(EventData)).contents
        print_event_data(event) # Call actual print function directly

    try:
        b["events"].open_perf_buffer(handle_perf_event_wrapper, page_cnt=128)
    except Exception as e:
        print("Error opening perf buffer: %s" % e); sys.exit(1)

    print("\\nTracing... Hit Ctrl-C to end.")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\\nDetaching..."); exit()
        except Exception as e:
            print("Error during poll: %s" % e); sleep(1)

