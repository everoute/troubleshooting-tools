#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from bcc import BPF
#from bpfcc import BPF # Uncomment for oe kernel if needed
from time import sleep
import argparse
import ctypes
import socket
import struct
import os
import sys
import fcntl # Needed for ioctl

IFNAMSIZ = 16

# --- Function to get ifindex (same as before) ---
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

# --- BPF C Code ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/inet_sock.h> // For inet_sk, needed? Maybe just net/sock.h
#include <net/sock.h>
#include <linux/ip.h>

#define TARGET_IFINDEX %d

// Data structure to pass to user space
struct pkt_data_t {
    u32 ifindex;
    __be32 saddr;
    __be32 daddr;
    u8 proto;
};

BPF_PERF_OUTPUT(events);

int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    if (skb == NULL) return 0;

    // 1. Get device struct pointer
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        // Cannot get device, cannot check index
        return 0;
    }

    // 2. Get ifindex
    int ifindex = 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        // Cannot read ifindex
        return 0;
    }

    // 3. Filter by ifindex
    if (ifindex != TARGET_IFINDEX) {
        return 0; // Not the target interface
    }

    // 4. If match, parse basic IP info and submit
    struct pkt_data_t data = {};
    data.ifindex = ifindex; // Store the matched index

    // Read headers offsets (add basic sanity check)
    unsigned char *head = NULL;
    u16 network_header = 0;
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;

    if (network_header == 0) { // Basic check if offset is initialized
         // bpf_trace_printk("BPF DBG: net_hdr 0 at stage 0 ifindex %%d\\n", ifindex);
         return 0;
    }

    // Read IP header
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) {
         // bpf_trace_printk("BPF DBG: IP read fail stage 0 ifindex %%d\\n", ifindex);
         return 0; // Cannot read IP header
    }

    // Populate data
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.proto = iph.protocol;

    // Submit data to user space
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# --- Ctypes Data Structure ---
class PktData(ctypes.Structure):
    _fields_ = [
        ("ifindex", ctypes.c_uint),
        ("saddr", ctypes.c_uint32), # Network byte order
        ("daddr", ctypes.c_uint32), # Network byte order
        ("proto", ctypes.c_uint8)
    ]

# --- Helper to format IP ---
def format_ip(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

# --- Process Event Function ---
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(PktData)).contents
    saddr_str = format_ip(event.saddr)
    daddr_str = format_ip(event.daddr)
    print("Packet seen on ifindex %d: Proto %d, %s -> %s" %
          (event.ifindex, event.proto, saddr_str, daddr_str))

# --- Main Execution ---
if __name__ == "__main__":
    if os.geteuid() != 0: print("Requires root privileges"); sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Test script to capture packets entering __netif_receive_skb on a specific interface index.")
    parser.add_argument('--iface', '-i', type=str, required=True, help='Interface name to monitor')
    args = parser.parse_args()

    # Get target ifindex
    try:
        target_ifindex = get_if_index(args.iface)
        print("Monitoring interface: %s (ifindex: %d)" % (args.iface, target_ifindex))
    except OSError as e:
        print("Error getting index for interface '%s': %s" % (args.iface, e))
        sys.exit(1)

    # Load BPF program
    try:
        b = BPF(text=bpf_text % target_ifindex)
        b.attach_kprobe(event="__netif_receive_skb", fn_name="kprobe____netif_receive_skb")
        print("BPF program loaded and probe attached. Waiting for packets...")
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