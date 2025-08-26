#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
kfree_skb Stack Statistics - Track kernel packet drop locations

This BCC program tracks kfree_skb calls and collects stack trace statistics
to identify where packets are being dropped in the kernel.

Usage: sudo python2 kfree_skb_stack_stats.py [-i INTERVAL] [-d DURATION] [-t TOP] [-n DEV]
       -i INTERVAL: reporting interval in seconds (default: 10)
       -d DURATION: total duration in seconds (default: unlimited)
       -t TOP: number of top stacks to show (default: 5)
       -n DEV: filter by device name (e.g., eth0, br-int)

Examples:
  sudo python2 kfree_skb_stack_stats.py -i 5 -d 60 -n eth0
  sudo python2 kfree_skb_stack_stats.py -t 10 -n br-int

"""

from __future__ import print_function
from bcc import BPF
import signal
import sys
import argparse
from ctypes import *
from time import sleep, strftime, time

# BPF program
bpf_text = """
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/netdevice.h>

#if IFNAMSIZ != 16 
#error "IFNAMSIZ != 16 is not supported"
#endif

union name_buf{
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    }name_int;
};

struct stack_key {
    int stack_id;
    union name_buf devname;
};

BPF_STACK_TRACE(stack_traces, 1024);
BPF_HASH(stack_counts, struct stack_key, u64);
BPF_HASH(failed_stacks, union name_buf, u64);  // Track stack failures by device
BPF_HASH(total_drops, u32, u64);
BPF_ARRAY(name_map, union name_buf, 1);

static inline int name_filter(struct sk_buff* skb){
    // Check if filtering is enabled
    int key = 0;
    union name_buf *leaf = name_map.lookup(&key);
    if (!leaf) {
        return 1; // No filter set, allow all
    }
    
    // Check if filter name is empty (all zeros)
    if (leaf->name_int.hi == 0 && leaf->name_int.lo == 0) {
        return 1; // Empty filter, allow all
    }
    
    // Get device name from skb
    union name_buf real_devname;
    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(struct sk_buff, dev)));
    if (!dev) {
        return 0;
    }
    bpf_probe_read(&real_devname, IFNAMSIZ, dev->name);
    
    // Compare device names
    if ((leaf->name_int).hi != real_devname.name_int.hi || 
        (leaf->name_int).lo != real_devname.name_int.lo) {
        return 0;
    }
    
    return 1;
}

int trace_kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    // Apply device name filter
    if (!name_filter(skb)) {
        return 0;
    }
    
    // Get device name
    union name_buf devname;
    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(struct sk_buff, dev)));
    if (!dev) {
        return 0;
    }
    bpf_probe_read(&devname, IFNAMSIZ, dev->name);
    
    u32 key = 0;
    u64 zero = 0;
    
    // Increment total drop counter
    u64 *total = total_drops.lookup_or_init(&key, &zero);
    (*total)++;
    
    // Get stack trace
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    if (stack_id >= 0) {
        // Success: count by stack + device
        struct stack_key skey = {};
        skey.stack_id = stack_id;
        skey.devname = devname;
        u64 *count = stack_counts.lookup_or_init(&skey, &zero);
        (*count)++;
    } else {
        // Failed: count failed stacks by device
        u64 *failed_count = failed_stacks.lookup_or_init(&devname, &zero);
        (*failed_count)++;
    }
    
    return 0;
}
"""

# Signal handler for graceful exit
exiting = False

def signal_handler(signal, frame):
    global exiting
    exiting = True

def print_stack_stats(b, top_n=5):
    """Print current stack statistics"""
    stack_counts = b["stack_counts"]
    stack_traces = b["stack_traces"]
    failed_stacks = b["failed_stacks"]
    
    if len(stack_counts) == 0 and len(failed_stacks) == 0:
        print("  No stack traces collected yet.")
        return
    
    # Show failed stacks if any
    if len(failed_stacks) > 0:
        print("\n  Stack trace failures by device:")
        for devname, count in failed_stacks.items():
            devname_str = devname.name.decode('utf-8', 'replace').rstrip('\x00')
            print("    %s: %d failed" % (devname_str, count.value))
    
    if len(stack_counts) == 0:
        return
        
    # Sort stacks by count (descending)
    sorted_stacks = sorted(stack_counts.items(), 
                          key=lambda x: x[1].value, reverse=True)
    
    print("  Found %d unique stacks, showing top %d:" % (len(sorted_stacks), min(top_n, len(sorted_stacks))))
    
    for i, (skey, count) in enumerate(sorted_stacks[:top_n]):
        devname_str = skey.devname.name.decode('utf-8', 'replace').rstrip('\x00')
        print("\n  #%d Count: %d calls [device: %s] [stack_id: %d]" % (i+1, count.value, devname_str, skey.stack_id))
        print("  Stack trace:")
        
        try:
            stack = list(stack_traces.walk(skey.stack_id))
            print("    Stack depth: %d frames" % len(stack))
            for j, addr in enumerate(stack[:5]):  # Show top 5 frames
                sym = b.sym(addr, -1, show_module=True, show_offset=True)
                print("    %s" % sym.decode('utf-8', 'replace'))
            if len(stack) > 5:
                print("    ... (%d more frames)" % (len(stack) - 5))
        except Exception as e:
            print("    [Error reading stack: %s]" % e)

def main():
    global exiting
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Track kfree_skb call stack statistics")
    parser.add_argument("-i", "--interval", type=int, default=10,
                        help="reporting interval in seconds (default: 10)")
    parser.add_argument("-d", "--duration", type=int, default=0,
                        help="total duration in seconds (default: unlimited)")
    parser.add_argument("-t", "--top", type=int, default=5,
                        help="number of top stacks to show (default: 5)")
    parser.add_argument("-n", "--name", type=str, default="",
                        help="filter by device name (e.g., eth0, br-int)")
    args = parser.parse_args()
    
    # Install signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    filter_info = " (device: %s)" % args.name if args.name else " (all devices)"
    print("Tracing kfree_skb calls with %ds intervals...%s" % (args.interval, filter_info))
    if args.duration > 0:
        print("Duration: %ds, Press Ctrl+C to stop early" % args.duration)
    else:
        print("Press Ctrl+C to stop")
    print("="*60)
    
    # Initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
    
    # Set device name filter if specified
    if args.name:
        if len(args.name) > 15:  # IFNAMSIZ-1
            print("Device name too long (max 15 chars)")
            return
            
        # Define ctypes structure for device name
        class Devname(Structure):
            _fields_ = [('name', c_char * 16)]  # IFNAMSIZ
            
        devname_map = b['name_map']
        _name = Devname()
        _name.name = args.name.encode()
        devname_map[0] = _name
        print("Filtering by device: %s" % args.name)
    else:
        print("No device filter - monitoring all interfaces")
    
    # Initialize timing
    start_time = time()
    last_total = 0
    cycle = 0
    
    try:
        while not exiting:
            sleep(args.interval)
            cycle += 1
            
            # Check duration limit
            if args.duration > 0 and (time() - start_time) >= args.duration:
                break
            
            # Get current total
            total_drops = b["total_drops"]
            try:
                key = b["total_drops"].Key(0)
                current_total = total_drops[key].value
            except KeyError:
                current_total = 0
            
            # Print periodic statistics
            current_time = strftime("%Y-%m-%d %H:%M:%S")
            new_drops = current_total - last_total
            print("\n[%s] Cycle %d - Total drops: %d (+%d in last %ds) [showing top %d]" % 
                  (current_time, cycle, current_total, new_drops, args.interval, args.top))
            print("-" * 60)
            
            # Print top stacks for this period
            print_stack_stats(b, args.top)
            print("=" * 60)
            
            last_total = current_total
            
    except KeyboardInterrupt:
        exiting = True
    
    # Print final statistics
    print("\n" + "="*60)
    print("%s kfree_skb Call Stack Statistics" % strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)
    
    # Get total drops
    total_drops = b["total_drops"]
    try:
        key = b["total_drops"].Key(0)
        total_count = total_drops[key].value
        print("Total packet drops: %d\n" % total_count)
    except KeyError:
        print("Total packet drops: 0\n")
        return
    
    # Get stack statistics
    stack_counts = b["stack_counts"]
    stack_traces = b["stack_traces"]
    failed_stacks = b["failed_stacks"]
    
    # Show failed stacks summary
    if len(failed_stacks) > 0:
        print("Stack trace failures by device:")
        failed_total = 0
        for devname, count in failed_stacks.items():
            devname_str = devname.name.decode('utf-8', 'replace').rstrip('\x00')
            print("  %s: %d failed" % (devname_str, count.value))
            failed_total += count.value
        print("Total failed stack traces: %d (%.1f%%)\n" % 
              (failed_total, 100.0 * failed_total / (total_count + failed_total)))
    
    if len(stack_counts) == 0:
        print("No successful stack traces collected.")
        return
    
    print("Top call stacks causing packet drops:")
    print("-" * 40)
    
    # Sort stacks by count (descending)
    sorted_stacks = sorted(stack_counts.items(), 
                          key=lambda x: x[1].value, reverse=True)
    
    for skey, count in sorted_stacks[:args.top * 2]:  # Show more in final summary
        devname_str = skey.devname.name.decode('utf-8', 'replace').rstrip('\x00')
        print("\nCount: %d calls (%.1f%%) [device: %s] [stack_id: %d]" % 
              (count.value, 100.0 * count.value / total_count, devname_str, skey.stack_id))
        print("Stack trace:")
        
        try:
            stack = stack_traces.walk(skey.stack_id)
            for addr in stack:
                sym = b.sym(addr, -1, show_module=True, show_offset=True)
                print("  %s" % sym.decode('utf-8', 'replace'))
        except Exception as e:
            print("  [Error reading stack: %s]" % e)
        
        print("-" * 40)
    
    print("\nTracing completed.")

if __name__ == "__main__":
    main()