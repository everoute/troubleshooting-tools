#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# ovs_icmp_trace.py: Trace ICMP packets through OVS and stack stages.
#
# Usage: sudo ./dp_execute.py
#
# Monitors key functions and prints packet identifiers, timestamps, and interface
# at each stage for ICMP echo/reply packets.

from bcc import BPF
from time import sleep, strftime
import argparse
import ctypes as ct
import socket
import struct
import os
import sys
import datetime
import time # Needed for boot time calculation

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h> // For ETH_P_IP
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h> // For ethhdr
#include <linux/if_vlan.h>
#include <linux/sched.h> // For task_struct, TASK_COMM_LEN
#include <linux/netdevice.h> // For IFNAMSIZ, struct net_device

// Define constants for stages
#define STAGE_NETIF_RECV_SKB      0 // Packet received by stack
#define STAGE_NETDEV_FRAME_HOOK   1
#define STAGE_DP_PROCESS_PACKET 2
#define STAGE_DP_UPCALL           3
#define STAGE_PKT_CMD_EXECUTE     4
#define STAGE_VPORT_SEND          5
#define STAGE_ICMP_RCV            6 // ICMP layer processing

// --- Debounce Threshold ---
#define DEBOUNCE_NS 1000000 // 1 millisecond threshold

// Key to identify a specific ICMP packet flow
struct packet_key_t {
    u8  smac[6];
    u8  dmac[6];
    __be32 sip;
    __be32 dip;
    u8  proto; // Should always be IPPROTO_ICMP
    __be16 id;  // ICMP Echo ID
    __be16 seq; // ICMP Echo Sequence
};

// --- New Composite Key for Debounce Map ---
struct composite_key_t {
    struct packet_key_t pkt_key;
    u64 stage_id;
};

// Data structure for events pushed to userspace - Added ifname
struct event_data_t {
    u64 ts;         // Timestamp (ns)
    u64 stage_id;   // Stage identifier (from defines above)
    u32 pid;        // Process ID
    struct packet_key_t key;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ]; // Interface name
};

// --- New BPF Map for Debouncing ---
BPF_HASH(last_seen, struct composite_key_t, u64, 10240);

// Perf output channel
BPF_PERF_OUTPUT(events);

// Helper function to parse skb and fill packet key for ICMP Echo/Reply
// REMOVED IP Address Filtering logic
static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key)
{
    if (skb == NULL) return 0;

    // Pointers and offsets from skb
    unsigned char *head;
    u16 mac_header;
    u16 network_header;
    u16 transport_header;
    u32 len;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) {
        bpf_trace_printk("DBG: Failed read skb->head\\n");
        return 0;
    }
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) {
        bpf_trace_printk("DBG: Failed read skb->len\\n");
        return 0;
    }
    bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header);
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) {
        bpf_trace_printk("DBG: Failed read network_header\\n");
        return 0;
    }
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) {
        bpf_trace_printk("DBG: Failed read transport_header\\n");
        return 0;
    }
    void *data_end = head + len;

    // --- Ethernet Header ---
    struct ethhdr eth = {};
    int eth_parsed = 0;
    if (mac_header != (u16)~0U && (head + mac_header + sizeof(struct ethhdr)) <= data_end) {
        void *eth_ptr = head + mac_header;
        if (bpf_probe_read_kernel(&eth, sizeof(eth), eth_ptr) == 0) {
            eth_parsed = 1;
            if (eth.h_proto != bpf_htons(ETH_P_IP)) {
                bpf_trace_printk("DBG: Not an IP packet check failed\\n");
                return 0;
            }
            __builtin_memcpy(key->smac, eth.h_source, 6);
            __builtin_memcpy(key->dmac, eth.h_dest,   6);
        } else {
            bpf_trace_printk("DBG: Failed read eth header\\n");
             __builtin_memset(key->smac, 0, 6);
             __builtin_memset(key->dmac, 0, 6);
        }
    } else {
         bpf_trace_printk("DBG: Invalid mac_header or bounds\\n");
         __builtin_memset(key->smac, 0, 6);
         __builtin_memset(key->dmac, 0, 6);
    }


    // --- IP Header ---
    if (network_header == (u16)~0U || (head + network_header + sizeof(struct iphdr)) > data_end) {
        bpf_trace_printk("DBG: Invalid network_header or bounds\\n");
        return 0;
    }
    void *ip_ptr = head + network_header;
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_ptr) < 0) {
        bpf_trace_printk("DBG: Failed read ip header\\n");
        return 0;
    }

    // --- IP Address Filtering REMOVED ---
    /*
    if (!((SRC_IP_FILTER == 0 || ip.saddr == SRC_IP_FILTER) &&
          (DST_IP_FILTER == 0 || ip.daddr == DST_IP_FILTER))) {
         bpf_trace_printk("DBG: parse_key: IP Filter mismatch\\n");
        return 0;
    }
    */

    // Read ip->ihl safely
    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) {
        bpf_trace_printk("DBG: Invalid IP IHL\\n");
        return 0;
    }
    // --- Fill Key ---
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;

    // --- Protocol Check (ICMP) ---
    if (ip.protocol == IPPROTO_ICMP) {
        // --- ICMP Header ---
        void *icmp_ptr;
        if (transport_header != (u16)~0U && (head + transport_header + sizeof(struct icmphdr)) <= data_end) {
            icmp_ptr = head + transport_header;
        } else {
            void *calculated_icmp_ptr = ip_ptr + (ip_ihl * 4);
            if ((calculated_icmp_ptr + sizeof(struct icmphdr)) > data_end) {
                bpf_trace_printk("DBG: ICMP bounds check failed (calc)\\n");
                return 0;
            }
            icmp_ptr = calculated_icmp_ptr;
            bpf_trace_printk("DBG: Used calculated ICMP offset\\n");
        }

        struct icmphdr ic;
        if (bpf_probe_read_kernel(&ic, sizeof(ic), icmp_ptr) < 0) {
            bpf_trace_printk("DBG: Failed read icmphdr\\n");
            return 0;
        }

        // --- Check ICMP type ---
        if (ic.type != ICMP_ECHO && ic.type != ICMP_ECHOREPLY) {
            bpf_trace_printk("DBG: parse_key: Not ICMP Echo/Reply\\n");
            return 0;
        }

        key->id  = ic.un.echo.id;
        key->seq = ic.un.echo.sequence;
    }

    return 1; // Success!
}


// Generic trace function called by kprobes - MODIFIED FOR IFNAME & DEBOUNCE
static __always_inline int trace_event(struct pt_regs *ctx, struct sk_buff *skb, u64 stage) {
    if (skb == NULL) return 0;

    struct packet_key_t pkt_key = {};
    // 1. Parse packet key (NO LONGER FILTERS IPs INTERNALLY)
    if (!parse_packet_key(skb, &pkt_key)) {
        return 0; // Not the packet we are looking for or parse error
    }

    // 2. Construct composite key for debounce map
    struct composite_key_t comp_key = {};
    comp_key.stage_id = stage;
    __builtin_memcpy(&comp_key.pkt_key, &pkt_key, sizeof(pkt_key));

    // 3. Debounce Logic
    u64 current_ts = bpf_ktime_get_ns();
    u64 *last_ts_ptr = last_seen.lookup(&comp_key);

    if (last_ts_ptr != NULL) {
        u64 delta = current_ts - *last_ts_ptr;
        if (delta < DEBOUNCE_NS) {
            return 0; // Duplicate detected within threshold, ignore
        }
    }
    // Update map (or insert if new) with current timestamp
    last_seen.update(&comp_key, &current_ts);

    // 4. Prepare event data
    struct event_data_t data = {};
    data.ts = current_ts; // Use the current timestamp
    data.stage_id = stage;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.key, &pkt_key, sizeof(pkt_key)); // Copy packet key

    // 5. --- Get Interface Name ---
    struct net_device *dev;
    // Read the dev pointer from skb
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev != NULL) {
        // If dev pointer is valid, read the name string
        bpf_probe_read_kernel_str(&data.ifname, IFNAMSIZ, dev->name);
    } else {
        // If dev is NULL, set ifname to "unknown"
        char unknown[] = "unknown";
         __builtin_memcpy(data.ifname, unknown, sizeof(unknown));
    }

    // 6. Submit the event data
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// --- Kprobes ---


// OVS datapath upcall
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb, const void *upcall_info) { // Use void*
    return trace_event(ctx, (struct sk_buff *)skb, STAGE_DP_UPCALL);
}

// OVS command execution (signature may vary!)
// Trying a potentially common signature involving skb
int kprobe__ovs_packet_cmd_execute(struct pt_regs *ctx, struct sk_buff *skb) {
    // Keep printk commented out
    // bpf_trace_printk("DBG: ovs_packet_cmd_execute ENTERED\\n");
    int result = trace_event(ctx, skb, STAGE_PKT_CMD_EXECUTE);
    // if (result == 0) {
    //      bpf_trace_printk("DBG: ovs_packet_cmd_execute: trace_event returned 0\\n");
    // }
    return 0;
}

"""

# Define Python Structures corresponding to BPF structs

IFNAMSIZ = 16 # From linux/netdevice.h
TASK_COMM_LEN = 16 # linux/sched.h

class PacketKey(ct.Structure):
    _fields_ = [
        ("smac", ct.c_uint8 * 6),
        ("dmac", ct.c_uint8 * 6),
        ("sip", ct.c_uint32),
        ("dip", ct.c_uint32),
        ("proto", ct.c_uint8),
        ("id", ct.c_uint16),
        ("seq", ct.c_uint16)
    ]

class EventData(ct.Structure):
    _fields_ = [
        ("ts", ct.c_uint64),
        ("stage_id", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("key", PacketKey),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ifname", ct.c_char * IFNAMSIZ) # Added interface name
    ]

# Stage ID to Name mapping - Added new stages
stage_names = {
    0: "__NETIF_RECV_SKB_CORE",
    1: "NETDEV_FRAME_HOOK",
    2: "DP_PROCESS_PACKET",
    3: "DP_UPCALL",
    4: "PKT_CMD_EXECUTE",
    5: "VPORT_SEND",
    6: "ICMP_RCV",
}

# --- Calculate system boot time once ---
try:
    with open("/proc/uptime", "r") as f:
        uptime_seconds = float(f.readline().split()[0])
    boot_time_epoch = time.time() - uptime_seconds # System boot time in seconds since epoch
except Exception as e:
    print("Warning: Could not read /proc/uptime to calculate absolute time: %s" % e)
    print("Timestamps will be relative to boot.")
    boot_time_epoch = None # Indicate relative time will be used

# Helper to format MAC address
def format_mac(addr_array):
    return ':'.join('%02x' % b for b in addr_array)

# Helper to format IP address
def format_ip(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))


# Callback function for perf buffer - MODIFIED FOR IFNAME and ABS TIME
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents

    # Calculate absolute timestamp if possible
    if boot_time_epoch is not None:
        abs_seconds = boot_time_epoch + (event.ts / 1e9)
        # Handle potential timestamp errors if system time changed significantly
        try:
            ts_str = datetime.datetime.fromtimestamp(abs_seconds) \
                                     .strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except ValueError:
             ts_str = "InvalidTimestamp" # Or fallback to relative
             # ts_str = "%.6f" % (event.ts / 1e9)
    else:
        # Fallback to relative time (seconds since boot)
        ts_str = "%.6f" % (event.ts / 1e9)


    stage_name = stage_names.get(event.stage_id, "UNKNOWN({})".format(event.stage_id))
    comm = event.comm.decode('utf-8', 'replace')
    ifname = event.ifname.decode('utf-8', 'replace') # Decode ifname

    # Updated print format
    print("%s  IF:%-10s %-12s %-6d %-18s %s -> %s (%s -> %s) ICMP ID=%-5d Seq=%-5d" % (
        ts_str,
        ifname, # Added interface name
        comm,
        event.pid,
        stage_name,
        format_ip(event.key.sip),
        format_ip(event.key.dip),
        format_mac(event.key.smac),
        format_mac(event.key.dmac),
        socket.ntohs(event.key.id),
        socket.ntohs(event.key.seq)
    ))


# --- Main Execution ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Requires root privileges (or CAP_SYS_ADMIN)")
        sys.exit(1)

    print("Starting trace...")

    # Check if OVS kernel module is loaded (basic check)
    if os.system("lsmod | grep openvswitch > /dev/null") != 0:
         print("Warning: Open vSwitch kernel module does not appear to be loaded.")
         # Continue anyway, probes might fail if functions don't exist

    # Load BPF program, injecting the filter values
    cflags = [] # Add back specific cflags if needed
    try:
        b = BPF(text=bpf_text, cflags=cflags)
    except Exception as e:
        print("Error compiling or loading BPF program:")
        print(e)
        # Check /proc/kallsyms if specific functions are missing
        sys.exit(1) # Exit after BPF load error

    # --- Attach Kprobes ---
    # Added new probe points
    #probe_points = [
    #    "__netif_receive_skb",    # Added
    #    "netdev_frame_hook",
    #    "ovs_dp_process_packet",
    #    "ovs_dp_upcall",
    #    "ovs_packet_cmd_execute",
    #    "ovs_vport_send",
    #    "icmp_rcv",             # Added
    #]

    probe_points = [
        "ovs_packet_cmd_execute",
        "ovs_dp_upcall",
    ]
    attached_probes = 0
    for func in probe_points:
        # Construct the correct BPF function name to attach based on the probe point name
        bpf_func_name = "kprobe__" + func

        try:
            b.attach_kprobe(event=func, fn_name=bpf_func_name)
            print("Attached kprobe to %s" % func)
            attached_probes += 1
        except Exception as e:
            # Try common alternatives if initial attach fails
            alternatives = []
            if func == "__netif_receive_skb":
                alternatives = ["__netif_receive_skb"] # Common alternative
            # Add other alternatives here if needed

            if alternatives:
                 print("Failed to attach kprobe to %s (%s), trying alternatives..." % (func, e))
                 attached = False
                 for alt_func in alternatives:
                     try:
                         # Handler name (bpf_func_name) stays the same
                         b.attach_kprobe(event=alt_func, fn_name=bpf_func_name)
                         print("Attached kprobe to alternative %s (using handler for %s)" % (alt_func, func))
                         attached_probes += 1
                         attached = True
                         break # Stop trying alternatives on success
                     except Exception as e_alt:
                         print("  Failed to attach to alternative %s: %s" % (alt_func, e_alt))
                 if not attached:
                     print("Failed to attach kprobe to %s and alternatives." % func)
            else:
                 # No alternatives defined for this function
                 print("Failed to attach kprobe to %s: %s" % (func, e))
                 print("  (Function might not exist or signature mismatch?)")

    if attached_probes == 0:
        print("\nError: Failed to attach any kprobes. Exiting.")
        print("Verify functions exist (check /proc/kallsyms) and kernel headers are available.")
        sys.exit(1)
    elif attached_probes < len(probe_points):
         print("\nWarning: Not all probes could be attached. Tracing will be partial.")

    # --- Process Events ---
    # Updated print header
    print("\nTracing packet stages... Hit Ctrl-C to end.")
    print("%-25s %-11s %-12s %-6s %-18s %s" % ("TIMESTAMP", "IFACE", "COMM", "PID", "STAGE", "PACKET_INFO (SIP->DIP (SMAC->DMAC) ICMP ID/SEQ)"))

    # Setup perf buffer
    b["events"].open_perf_buffer(print_event)

    # Start polling
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching probes and exiting...")
            exit()

