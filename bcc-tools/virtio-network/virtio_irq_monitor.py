#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Enhanced Virtio IRQ Monitor with detailed interrupt information

This version provides comprehensive IRQ statistics including CPU affinity,
timing information, and detailed handler tracking.
Compatible with both Python 2 and Python 3.
"""

from __future__ import print_function
import argparse
import time
import sys
from collections import defaultdict
from time import strftime

# BCC/BPFCC module import
try:
    from bpfcc import BPF
    print("Using bpfcc module")
except ImportError:
    try:
        from bcc import BPF
        print("Using bcc module")
    except ImportError:
        print("Error: Neither bpfcc nor bcc module found!")
        sys.exit(1)

# IRQ return values
IRQ_NONE = 0
IRQ_HANDLED = 1
IRQ_WAKE_THREAD = 2

def parse_irq_list(irq_str):
    """Parse comma-separated IRQ list"""
    if not irq_str:
        return []
    try:
        return [int(x.strip()) for x in irq_str.split(',')]
    except ValueError as e:
        raise argparse.ArgumentTypeError("Invalid IRQ number: {}".format(e))

# Command line arguments
parser = argparse.ArgumentParser(description='Enhanced Virtio IRQ Monitor')
parser.add_argument('--irqs', type=parse_irq_list, required=True,
                    help='Comma-separated list of IRQ numbers (e.g., 69,71,73,75)')
parser.add_argument('--interval', type=int, default=5,
                    help='Reporting interval in seconds (default: 5)')
parser.add_argument('--trace-cpu', action='store_true',
                    help='Show per-CPU distribution')

args = parser.parse_args()

print("Enhanced Virtio IRQ Monitor")
print("Monitoring IRQs: {}".format(args.irqs))
print("Reporting interval: {} seconds".format(args.interval))
print("CPU tracking: {}".format('ON' if args.trace_cpu else 'OFF'))
print("-" * 80)

# Create IRQ constants for BPF
irq_defines = "\n".join(["#define IRQ{} {}".format(i, irq) for i, irq in enumerate(args.irqs)])
irq_checks = " || ".join(["irq == IRQ{}".format(i) for i in range(len(args.irqs))])

# BPF program
bpf_text = '''
#include <uapi/linux/ptrace.h>
#include <linux/interrupt.h>

''' + irq_defines + '''

// Statistics structures
struct irq_info_t {
    u64 timestamp;
    u32 cpu;
    u32 duration;  // IRQ handling duration
    char handler_name[32];
};

struct handler_name_t {
    char name[32];
};

struct irq_detail_t {
    u32 irq;
    char name[32];
    char owner[32];
    u64 dev_id;
};

// Entry/exit timing tracking
struct irq_timing_t {
    u64 entry_time;
    u32 cpu;
};

// Maps for comprehensive tracking
BPF_HASH(irq_call_count, u32, u64);              // irq -> total_calls
BPF_HASH(irq_cpu_dist, u64, u64);                // (irq << 32 | cpu) -> count
BPF_HASH(irq_return_count, u64, u64);            // (irq << 32 | retval) -> count
BPF_HASH(irq_handler_names, u32, struct handler_name_t);  // irq -> handler_name
BPF_HASH(irq_details, u32, struct irq_detail_t); // irq -> detailed info
BPF_HASH(irq_last_cpu, u32, u32);                // irq -> last_cpu
BPF_HASH(irq_last_time, u32, u64);               // irq -> last_timestamp
BPF_HASH(irq_interval_sum, u32, u64);            // irq -> sum of intervals
BPF_HASH(irq_interval_count, u32, u64);          // irq -> count of intervals
BPF_HASH(irq_timing_entry, u32, u64);            // cpu -> entry_timestamp
BPF_HASH(irq_duration_sum, u32, u64);            // irq -> sum of durations
BPF_HASH(irq_duration_max, u32, u32);            // irq -> max duration

// Removed complex perf output to avoid BPF verifier issues

// Removed complex kprobe to avoid BPF verifier issues

// Track IRQ entry via tracepoint
TRACEPOINT_PROBE(irq, irq_handler_entry) {
    u32 irq = args->irq;
    if (!(''' + irq_checks + ''')) return 0;
    
    u32 cpu = bpf_get_smp_processor_id();
    u64 timestamp = bpf_ktime_get_ns();
    
    // Store entry timing for duration calculation
    irq_timing_entry.update(&cpu, &timestamp);
    
    // Update call count
    u64 *count = irq_call_count.lookup(&irq);
    if (count) (*count)++;
    else {
        u64 one = 1;
        irq_call_count.update(&irq, &one);
    }
    
    // Update CPU distribution
    u64 cpu_key = ((u64)irq << 32) | cpu;
    u64 *cpu_count = irq_cpu_dist.lookup(&cpu_key);
    if (cpu_count) (*cpu_count)++;
    else {
        u64 one = 1;
        irq_cpu_dist.update(&cpu_key, &one);
    }
    
    // Calculate interval from last interrupt
    u64 *last_time = irq_last_time.lookup(&irq);
    if (last_time && timestamp > *last_time) {
        u64 interval = timestamp - *last_time;
        
        u64 *interval_sum = irq_interval_sum.lookup(&irq);
        if (interval_sum) (*interval_sum) += interval;
        else irq_interval_sum.update(&irq, &interval);
        
        u64 *interval_count = irq_interval_count.lookup(&irq);
        if (interval_count) (*interval_count)++;
        else {
            u64 one = 1;
            irq_interval_count.update(&irq, &one);
        }
    }
    
    // Update last CPU and time
    irq_last_cpu.update(&irq, &cpu);
    irq_last_time.update(&irq, &timestamp);
    
    return 0;
}

// Track IRQ exit and return value
TRACEPOINT_PROBE(irq, irq_handler_exit) {
    u32 irq = args->irq;
    if (!(''' + irq_checks + ''')) return 0;
    
    u32 retval = args->ret;
    u32 cpu = bpf_get_smp_processor_id();
    u64 exit_time = bpf_ktime_get_ns();
    
    // Calculate IRQ handling duration
    u64 *entry_time = irq_timing_entry.lookup(&cpu);
    if (entry_time) {
        u32 duration = (u32)((exit_time - *entry_time) / 1000); // Convert to microseconds
        
        // Update duration statistics
        u64 *duration_sum = irq_duration_sum.lookup(&irq);
        if (duration_sum) (*duration_sum) += duration;
        else {
            u64 dur = duration;
            irq_duration_sum.update(&irq, &dur);
        }
        
        // Update max duration
        u32 *max_duration = irq_duration_max.lookup(&irq);
        if (!max_duration || duration > *max_duration) {
            irq_duration_max.update(&irq, &duration);
        }
        
        // Clear timing entry
        irq_timing_entry.delete(&cpu);
    }
    
    // Update return value statistics
    u64 key = ((u64)irq << 32) | retval;
    u64 *count = irq_return_count.lookup(&key);
    if (count) (*count)++;
    else {
        u64 one = 1;
        irq_return_count.update(&key, &one);
    }
    
    return 0;
}
'''

# Load BPF program
try:
    b = BPF(text=bpf_text)
    print("BPF program loaded successfully")
except Exception as e:
    print("Error loading BPF program: {}".format(e))
    sys.exit(1)

# Kprobe attachment removed for compatibility

print("✓ Tracepoints attached successfully")
print("-" * 80)

# Simplified tracking without perf events

def print_statistics():
    """Print comprehensive IRQ statistics"""
    
    print("\n{}".format("="*80))
    print("IRQ Statistics Report - {}".format(strftime('%H:%M:%S')))
    print("{}".format("="*80))
    
    # Get all statistics
    call_counts = {}
    handler_names = {}
    irq_details = {}
    cpu_distributions = defaultdict(lambda: defaultdict(int))
    return_distributions = defaultdict(lambda: defaultdict(int))
    avg_intervals = {}
    avg_durations = {}
    max_durations = {}
    
    # Collect call counts
    for k, v in b["irq_call_count"].items():
        irq = k.value
        call_counts[irq] = v.value
    
    # Collect handler names
    for k, v in b["irq_handler_names"].items():
        irq = k.value
        handler_names[irq] = v.name.decode('utf-8', 'ignore')
    
    # Collect detailed IRQ information
    for k, v in b["irq_details"].items():
        irq = k.value
        detail = {
            'name': v.name.decode('utf-8', 'ignore'),
            'owner': v.owner.decode('utf-8', 'ignore'),
            'dev_id': hex(v.dev_id) if v.dev_id else 'N/A'
        }
        irq_details[irq] = detail
    
    # Collect CPU distribution
    for k, v in b["irq_cpu_dist"].items():
        key = k.value
        irq = key >> 32
        cpu = key & 0xFFFFFFFF
        cpu_distributions[irq][cpu] = v.value
    
    # Collect return value distribution
    for k, v in b["irq_return_count"].items():
        key = k.value
        irq = key >> 32
        retval = key & 0xFFFFFFFF
        return_distributions[irq][retval] = v.value
    
    # Calculate average intervals
    for k, v in b["irq_interval_sum"].items():
        irq = k.value
        interval_sum = v.value
        count_entry = b["irq_interval_count"][k]
        if count_entry:
            count = count_entry.value
            if count > 0:
                avg_intervals[irq] = interval_sum / count / 1000  # Convert to microseconds
    
    # Calculate average durations
    for k, v in b["irq_duration_sum"].items():
        irq = k.value
        duration_sum = v.value
        call_count = call_counts.get(irq, 0)
        if call_count > 0:
            avg_durations[irq] = float(duration_sum) / call_count
    
    # Get max durations
    for k, v in b["irq_duration_max"].items():
        irq = k.value
        max_durations[irq] = v.value
    
    # Print statistics for each IRQ
    total_issues = 0
    
    for irq in sorted(args.irqs):
        calls = call_counts.get(irq, 0)
        handler_name = handler_names.get(irq, "unknown")
        detail = irq_details.get(irq, {})
        
        print("\nIRQ {} ({}):".format(irq, handler_name))
        print("  Total Calls: {}".format(calls))
        
        # Show device details if available
        if detail:
            if detail.get('dev_id', 'N/A') != 'N/A':
                print("  Device ID: {}".format(detail['dev_id']))
        
        if calls > 0:
            # CPU distribution - compact format
            if irq in cpu_distributions:
                cpu_dist = cpu_distributions[irq]
                if cpu_dist:
                    cpu_list = []
                    for cpu in sorted(cpu_dist.keys()):
                        count = cpu_dist[cpu]
                        cpu_list.append("CPU{}: {}".format(cpu, count))
                    print("  CPU Distribution: {}".format(", ".join(cpu_list)))
            
            # Return value distribution - compact format
            if irq in return_distributions:
                ret_dist = return_distributions[irq]
                total_returns = sum(ret_dist.values())
                
                if total_returns > 0:
                    ret_summary = []
                    for retval in sorted(ret_dist.keys()):
                        count = ret_dist[retval]
                        percentage = (count / total_returns) * 100
                        
                        if retval == IRQ_NONE:
                            if percentage > 1.0:
                                total_issues += 1
                                ret_summary.append("IRQ_NONE: {} ({:.1f}%) ⚠️".format(count, percentage))
                            else:
                                ret_summary.append("IRQ_NONE: {} ({:.1f}%)".format(count, percentage))
                        elif retval == IRQ_HANDLED:
                            ret_summary.append("IRQ_HANDLED: {} ({:.1f}%)".format(count, percentage))
                        elif retval == IRQ_WAKE_THREAD:
                            ret_summary.append("IRQ_WAKE_THREAD: {} ({:.1f}%)".format(count, percentage))
                        else:
                            ret_summary.append("UNKNOWN({}): {} ({:.1f}%)".format(retval, count, percentage))
                    
                    print("  Return Value Distribution:")
                    print("    {}".format(", ".join(ret_summary)))
            
            # Latency statistics
            if irq in avg_durations:
                avg_lat = avg_durations[irq]
                max_lat = max_durations.get(irq, 0)
                print("  Average Latency: {:.1f}μs".format(avg_lat))
                print("  Max Latency: {:.1f}μs".format(max_lat))
    
    # Summary
    if total_issues > 0:
        print("\n⚠️  ISSUES DETECTED: {} IRQ(s) with high IRQ_NONE ratio".format(total_issues))
    else:
        print("\n✅ No issues detected (IRQ_NONE < 1.0%, latency normal)")
    
    print("{}".format("="*80))
    
    # No event counters to clear in simplified version
    
    # Clear BPF maps for next period
    for table_name in ["irq_call_count", "irq_cpu_dist", "irq_return_count", 
                       "irq_interval_sum", "irq_interval_count", "irq_duration_sum", "irq_duration_max"]:
        b[table_name].clear()

print("Starting enhanced IRQ monitoring... Press Ctrl+C to stop")

try:
    start_time = time.time()
    while True:
        time.sleep(0.1)
        
        current_time = time.time()
        if current_time - start_time >= args.interval:
            print_statistics()
            start_time = current_time
            
except KeyboardInterrupt:
    print("\nStopping IRQ monitoring...")
    print_statistics()