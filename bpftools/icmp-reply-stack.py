#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from bcc import BPF
from time import sleep
import argparse
import ctypes
import socket
import struct
import os
import sys

# BPF C Code
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/flow.h> // Include in case ip_send_skb needs flowi4

// Placeholders for the IP pair
#define IP_A 0x%x
#define IP_B 0x%x

// Data structure for event - ADDED icmp_type
struct data_t {
    __be32 saddr;
    __be32 daddr;
    u16 seq;       // ICMP sequence (network byte order)
    u8 icmp_type; // Added
    __be16 icmp_id; // Added
    int kernel_stack_id;
};

BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);

// CHANGE Probe target to ip_send_skb
// Verify signature: int ip_send_skb(struct net *net, struct sk_buff *skb);
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    if (skb == NULL) return 0;

    // Read network header offset
    unsigned char *head = NULL;
    u16 network_header = 0;
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (network_header == 0) return 0;

    // Read IP header
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) {
        return 0;
    }

    // Check if ICMP
    if (iph.protocol != IPPROTO_ICMP) {
        return 0;
    }

    // --- MODIFIED IP Filter: Match pair in either direction ---
    __be32 ip_a = IP_A;
    __be32 ip_b = IP_B;
    bool ip_match = ((iph.saddr == ip_a && iph.daddr == ip_b) || (iph.saddr == ip_b && iph.daddr == ip_a));
    if (!ip_match) {
        return 0;
    }
    // --- End IP Filter ---

    // Calculate ICMP header offset
    u8 ip_ihl = iph.ihl & 0x0F;
    if (ip_ihl < 5) return 0;
    void *icmp_ptr = (void *)head + network_header + (ip_ihl * 4);

    // Read ICMP header
    struct icmphdr icmph;
    // Check boundary before reading ICMP header relative to skb length
    u32 len = 0;
    if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) < 0) return 0;
    void *data_end = (void *)(head + len);
     if ((icmp_ptr + sizeof(icmph)) > data_end) {
         return 0; // Cannot safely read ICMP header
    }
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), icmp_ptr) < 0) {
        return 0; // Failed reading ICMP header
    }

    // --- REMOVED ICMP type check ---

    // If IPs match, capture stack and send event
    struct data_t data = {};
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    // Read seq/id if possible (best effort for non-echo/reply)
    data.seq = icmph.un.echo.sequence;
    data.icmp_id = icmph.un.echo.id;
    data.icmp_type = icmph.type; // Store the type
    data.kernel_stack_id = stack_traces.get_stackid(ctx, 0); // Get kernel stack

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# CTypes Data Structure - Updated
class Data(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("seq", ctypes.c_uint16),
        ("icmp_type", ctypes.c_uint8), # Added
        ("icmp_id", ctypes.c_uint16), # Added
        ("kernel_stack_id", ctypes.c_int),
    ]

# Helper Functions
def ip_to_hex(ip_str):
    if not ip_str or ip_str == "0.0.0.0": return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '{}'".format(ip_str)); sys.exit(1)

def format_ip(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

# Process Event Function - Updated
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents

    print("--- ICMP Packet seen in ip_send_skb ---")
    print("  Packet: %s -> %s (Type: %d, ID: %d, Seq: %d)" % (
        format_ip(event.saddr),
        format_ip(event.daddr),
        event.icmp_type, # Print type
        socket.ntohs(event.icmp_id), # Print ID
        socket.ntohs(event.seq)
    ))
    print("  Kernel Stack Trace (Stack ID: %d):" % event.kernel_stack_id)
    if event.kernel_stack_id < 0:
         print("    <Stack Trace Failed: %d>" % event.kernel_stack_id)
    else:
        # Get stack trace symbols
        try:
            global b # Need global b
            stack_table = b.get_table("stack_traces")
            for addr in stack_table.walk(event.kernel_stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("    %s" % sym)
        except NameError: print("      <Error: BPF object 'b' not accessible>")
        except KeyError:
             print("    <Stack ID %d not found in table>" % event.kernel_stack_id)
        except Exception as e:
            print("    <Error resolving stack ID %d: %s>" % (event.kernel_stack_id, e))
    print("")

# Main Execution - Updated
if __name__ == "__main__":
    if os.geteuid() != 0: print("Requires root privileges"); sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace kernel stack for any ICMP packets between two IPs at ip_send_skb.") # Updated description
    parser.add_argument('--ipA', type=str, required=True, help='First IP address in the pair')
    parser.add_argument('--ipB', type=str, required=True, help='Second IP address in the pair')
    args = parser.parse_args()

    ip_a_hex = ip_to_hex(args.ipA)
    ip_b_hex = ip_to_hex(args.ipB)

    print("Tracing ICMP packets between %s and %s in ip_send_skb..." % (args.ipA, args.ipB)) # Updated print

    # Load BPF program (still takes 2 args)
    try:
        global b # Make b global for print_event
        b = BPF(text=bpf_text % (ip_a_hex, ip_b_hex))
        # Attach to ip_send_skb instead of internal_dev_xmit
        b.attach_kprobe(event="ip_send_skb", fn_name="kprobe__ip_send_skb")
        print("BPF program loaded and probe attached. Waiting for ICMP packets...") # Updated print
    except Exception as e:
        print("Error loading or attaching BPF: %s" % e)
        sys.exit(1)

    # Setup perf buffer
    b["events"].open_perf_buffer(print_event)

    # Loop and poll
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nExiting...")
            exit()
        except Exception as e:
            print("Error during poll: %s" % e)

