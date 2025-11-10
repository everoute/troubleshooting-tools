#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Minimal test - just capture any ICMP packet
"""

from bcc import BPF
import sys

bpf_code = """
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>

BPF_PERF_OUTPUT(events);

struct event_t {
    u32 sip;
    u32 dip;
    u8 type;
};

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    // Simple check
    bpf_trace_printk("netif_receive_skb triggered!\\n");

    struct event_t evt = {};
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    bpf_trace_printk("icmp_rcv triggered!\\n");
    return 0;
}
"""

print("Loading BPF program...")
try:
    b = BPF(text=bpf_code)
    print("[OK] BPF loaded")
except Exception as e:
    print("[ERROR] Failed to load BPF: %s" % e)
    sys.exit(1)

print("")
print("Tracing ICMP packets...")
print("Check trace_pipe: sudo cat /sys/kernel/debug/tracing/trace_pipe")
print("")

def print_event(cpu, data, size):
    print("Event captured!")

b["events"].open_perf_buffer(print_event)

try:
    print("Waiting for ICMP packets... (Ctrl-C to stop)")
    print("")
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopped")
