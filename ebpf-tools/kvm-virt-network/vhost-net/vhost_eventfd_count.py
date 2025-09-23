#!/usr/bin/env python
# -*- coding: utf-8 -*-

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

import time
import argparse

parser = argparse.ArgumentParser(description="Count vhost_virtqueue + eventfd_ctx combinations")
parser.add_argument("-i", "--interval", type=int, default=1,
                    help="output interval in seconds (default 1)")
parser.add_argument("-c", "--clear", action="store_true",
                    help="clear counters after each output")
args = parser.parse_args()

bpf_text = """
#include <linux/sched.h>

BPF_HASH(counts, u64, u64);

int trace_vhost_add_used_and_signal_n(struct pt_regs *ctx, void *dev, void *vq)
{
    u64 key = (u64)vq;
    u64 eventfd_ptr = 0;
    
    // Read eventfd_ctx pointer at offset 424 (0x1a8)
    bpf_probe_read(&eventfd_ptr, sizeof(eventfd_ptr), (char *)vq + 424);
    
    // Combine vq and eventfd_ctx as key
    key = ((u64)vq << 32) | (eventfd_ptr & 0xFFFFFFFF);
    
    u64 *val = counts.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 init_val = 1;
        counts.update(&key, &init_val);
    }
    
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_add_used_and_signal_n")

print("Counting vhost_virtqueue + eventfd_ctx combinations... Ctrl-C to stop")
print("Output interval: %d seconds" % args.interval)

def print_stats():
    print("\n%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("%-18s %-18s %8s" % ("VQ_PTR", "EVENTFD_PTR", "COUNT"))
    print("-" * 50)
    
    counts = b["counts"]
    if not counts:
        print("No data")
        return
        
    for k, v in sorted(counts.items(), key=lambda x: x[1].value, reverse=True):
        vq_ptr = k.value >> 32
        eventfd_ptr = k.value & 0xFFFFFFFF
        print("0x%016x 0x%016x %8d" % (vq_ptr, eventfd_ptr, v.value))
    
    if args.clear:
        counts.clear()

try:
    while True:
        time.sleep(args.interval)
        print_stats()
except KeyboardInterrupt:
    print("\nFinal statistics:")
    print_stats()