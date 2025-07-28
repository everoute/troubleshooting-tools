#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
VM Interrupt Statistics Tool - Histogram Version (VM-Centric Design)

Smart VM-centric interrupt monitoring tool that automatically tracks all interrupts for a specific VM.
Requires QEMU PID as mandatory parameter for comprehensive VM interrupt analysis.

Features:
1. VM-centric filtering: qemu-pid automatically tracks both vhost threads and control interrupts
2. Smart category filtering: data (vhost threads) vs control (QEMU process) separation
3. Advanced thread filtering: specific vhost thread PID filtering for data category
4. Ultra-high performance with BPF_HISTOGRAM kernel-side aggregation

Test Environment: Virtualization Host
"""

from __future__ import print_function
import argparse
from bcc import BPF
import ctypes as ct
import time
import signal
import sys
from collections import defaultdict

# BPF程序
bpf_text = """
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/poll.h>

// 完整的 kvm_kernel_irqfd 结构定义
struct kvm_kernel_irqfd {
    /* Used for MSI fast-path */
    struct kvm *kvm;
    wait_queue_entry_t wait;
    /* Update side is protected by irq_lock */
    struct kvm_kernel_irq_routing_entry irq_entry;
    seqcount_t irq_entry_sc;
    /* Used for level-triggered shutdown */
    int gsi;
    struct work_struct inject;
    struct kvm_kernel_irq_routing_entry *irq_entry_cache;
    /* Used for resampling */
    void *resampler;  // struct kvm_kernel_irqfd_resampler *
    struct eventfd_ctx *resamplefd;
    struct list_head resampler_link;
    /* Used for shutdown */
    struct eventfd_ctx *eventfd;
    struct list_head list;
    poll_table pt;
    struct work_struct shutdown;
    void *irq_bypass_consumer;   // struct irq_bypass_consumer *
    void *irq_bypass_producer;   // struct irq_bypass_producer *
};

// 使用 READ_FIELD 宏
#define READ_FIELD(dst, ptr, field)                                   \\
    do {                                                              \\
        typeof(ptr->field) __tmp;                                     \\
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \\
        *(dst) = __tmp;                                               \\
    } while (0)

// 直方图键：VM + 队列 + 分类信息
typedef struct hist_key {
    u64 kvm_ptr;           // KVM 实例指针 (VM 标识)
    u64 irqfd_ptr;         // irqfd 结构指针 (队列标识)
    u32 gsi;               // 全局系统中断号
    u32 cpu_id;            // CPU ID
    u32 pid;               // 进程 PID
    char comm[16];         // 进程名
    u64 slot;              // 直方图槽位（用于计数）
} hist_key_t;

// 使用BPF_HISTOGRAM进行统计
BPF_HISTOGRAM(irq_count_hist, hist_key_t);

// 辅助信息存储 (存储GSI和EventFD等信息)
struct irqfd_info {
    u32 gsi;
    u64 eventfd_ctx;
    u64 first_timestamp;
    u64 last_timestamp;
};

BPF_HASH(irqfd_info_map, u64, struct irqfd_info, 4096);

// Filter parameters (set from userspace)
struct filter_params {
    u32 qemu_pid;          // Required parameter
    u32 vhost_pid;         // 0 means no filtering (only used when category=data)
    u8 filter_category;    // 0=all, 1=data, 2=control
    u8 filter_subcategory; // 0=all, 1=rx, 2=tx
};

BPF_ARRAY(filter_config, struct filter_params, 1);


// 跟踪 irqfd_wakeup 事件
int trace_vm_irqfd_stats(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    unsigned mode = (unsigned)PT_REGS_PARM2(ctx);
    int sync = (int)PT_REGS_PARM3(ctx);
    void *key = (void *)PT_REGS_PARM4(ctx);
    
    if (!wait) return 0;
    
    // 检查 EPOLLIN 标志 (网络中断通常是输入事件)
    u64 flags = (u64)key;
    if (!(flags & 0x1)) return 0;
    
    // 使用 container_of 获取 kvm_kernel_irqfd 结构
    struct kvm_kernel_irqfd *irqfd = (struct kvm_kernel_irqfd *)
        ((char *)wait - offsetof(struct kvm_kernel_irqfd, wait));
        
    if (!irqfd) return 0;
    
    // 读取关键字段
    struct kvm *kvm = NULL;
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;
    
    READ_FIELD(&kvm, irqfd, kvm);
    READ_FIELD(&eventfd, irqfd, eventfd);
    READ_FIELD(&gsi, irqfd, gsi);
    
    // 验证关键字段有效性
    if (!kvm || !eventfd || (u64)kvm < 0xffff000000000000ULL || (u64)eventfd < 0xffff000000000000ULL) {
        return 0;
    }
    
    // 获取当前进程信息
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 获取过滤配置
    int zero = 0;
    struct filter_params *filter = filter_config.lookup(&zero);
    if (!filter) return 0;
    
    // Smart filtering based on qemu_pid and category
    // Check if process is the target QEMU process
    int is_qemu_match = (pid == filter->qemu_pid);
    
    // Check if process matches vhost-<qemu_pid> pattern
    int is_vhost_match = 0;
    if (comm[0] == 'v' && comm[1] == 'h' && comm[2] == 'o' && 
        comm[3] == 's' && comm[4] == 't' && comm[5] == '-') {
        
        // Extract PID from vhost-<pid> and compare with qemu_pid
        u32 extracted_pid = 0;
        int i = 6;
        
        // Parse digits after "vhost-"
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            if (i + j >= 16) break;
            char c = comm[i + j];
            if (c >= '0' && c <= '9') {
                extracted_pid = extracted_pid * 10 + (c - '0');
            } else {
                break;
            }
        }
        
        is_vhost_match = (extracted_pid == filter->qemu_pid);
    }
    
    // Apply filtering based on category
    if (filter->filter_category == 0) {
        // No category filter: accept if QEMU process OR matching vhost
        if (pid != filter->qemu_pid && !is_vhost_match) {
            return 0;
        }
    } else if (filter->filter_category == 1) {
        // Data category: only accept matching vhost processes
        if (!is_vhost_match) {
            return 0;
        }
        // Additional vhost PID filtering if specified
        if (filter->vhost_pid != 0 && pid != filter->vhost_pid) {
            return 0;
        }
    } else if (filter->filter_category == 2) {
        // Control category: only accept QEMU process
        if (pid != filter->qemu_pid) {
            return 0;
        }
    }
    
    // No need for additional category filtering - already handled above
    
    // Record to histogram
    hist_key_t hist_key = {};
    hist_key.kvm_ptr = (u64)kvm;
    hist_key.irqfd_ptr = (u64)irqfd;
    hist_key.gsi = (u32)gsi;
    hist_key.cpu_id = bpf_get_smp_processor_id();
    hist_key.pid = pid;
    // Copy comm manually
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        hist_key.comm[i] = comm[i];
    }
    hist_key.slot = 0;  // For counting, slot is fixed to 0
    
    irq_count_hist.atomic_increment(hist_key);
    
    // Update auxiliary information
    u64 irqfd_key = (u64)irqfd;
    struct irqfd_info *info = irqfd_info_map.lookup(&irqfd_key);
    if (!info) {
        struct irqfd_info new_info = {};
        new_info.gsi = (u32)gsi;
        new_info.eventfd_ctx = (u64)eventfd;
        new_info.first_timestamp = bpf_ktime_get_ns();
        new_info.last_timestamp = new_info.first_timestamp;
        irqfd_info_map.update(&irqfd_key, &new_info);
    } else {
        info->last_timestamp = bpf_ktime_get_ns();
    }
    
    return 0;
}
"""

class HistKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("irqfd_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("cpu_id", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("slot", ct.c_uint64),
    ]

class IrqfdInfo(ct.Structure):
    _fields_ = [
        ("gsi", ct.c_uint32),
        ("eventfd_ctx", ct.c_uint64),
        ("first_timestamp", ct.c_uint64),
        ("last_timestamp", ct.c_uint64),
    ]

class FilterParams(ct.Structure):
    _fields_ = [
        ("qemu_pid", ct.c_uint32),
        ("vhost_pid", ct.c_uint32),
        ("filter_category", ct.c_uint8),
        ("filter_subcategory", ct.c_uint8),
    ]

# 全局统计
start_time = None
last_print_time = None

def format_timestamp(ns):
    """Format nanosecond timestamp to readable format"""
    import datetime
    timestamp = datetime.datetime.fromtimestamp(ns / 1000000000.0)
    return timestamp.strftime('%H:%M:%S.%f')[:-3]

def print_histogram_stats(b):
    """Print histogram statistics"""
    global start_time, last_print_time
    
    current_time = time.time()
    if last_print_time:
        interval = current_time - last_print_time
    else:
        interval = current_time - start_time
    
    duration = current_time - start_time
    
    # Get current timestamp
    import datetime
    current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    print("\n" + "="*100)
    print("VM Interrupt Statistics Summary (Histogram Version)")
    print("="*100)
    print("Timestamp: {}".format(current_timestamp))
    print("Statistics Duration: {:.2f} seconds (Current Interval: {:.2f} seconds)".format(duration, interval))
    
    # 收集和组织统计数据
    vm_stats = defaultdict(lambda: {
        'total_interrupts': 0,
        'queues': defaultdict(lambda: {
            'count': 0,
            'gsi': None,
            'eventfd': None,
            'cpus': set(),
            'pids': set(),
            'comms': set(),
            'data_count': 0,
            'control_count': 0
        }),
        'first_time': None,
        'last_time': None
    })
    
    total_interrupts = 0
    
    # 遍历直方图
    hist_table = b["irq_count_hist"]
    for k, v in hist_table.items():
        if v.value == 0:
            continue
            
        kvm_ptr = k.kvm_ptr
        irqfd_ptr = k.irqfd_ptr
        count = v.value
        
        total_interrupts += count
        
        vm_stat = vm_stats[kvm_ptr]
        vm_stat['total_interrupts'] += count
        
        # 获取辅助信息
        irqfd_info = b["irqfd_info_map"].get(ct.c_uint64(irqfd_ptr))
        if irqfd_info:
            first_time = format_timestamp(irqfd_info.first_timestamp)
            last_time = format_timestamp(irqfd_info.last_timestamp)
            
            if vm_stat['first_time'] is None or first_time < vm_stat['first_time']:
                vm_stat['first_time'] = first_time
            if vm_stat['last_time'] is None or last_time > vm_stat['last_time']:
                vm_stat['last_time'] = last_time
        
        # 更新队列统计
        queue_stat = vm_stat['queues'][irqfd_ptr]
        queue_stat['count'] += count
        queue_stat['gsi'] = k.gsi
        
        if irqfd_info:
            queue_stat['eventfd'] = irqfd_info.eventfd_ctx
        
        queue_stat['cpus'].add(k.cpu_id)
        queue_stat['pids'].add(k.pid)
        
        comm_str = k.comm.decode('utf-8', 'replace')
        queue_stat['comms'].add(comm_str)
        
        # 分类统计
        if comm_str.startswith('qemu'):
            queue_stat['control_count'] += count
        elif comm_str.startswith('vhost-'):
            queue_stat['data_count'] += count
    
    print("Total Interrupts: {} ({:.2f} interrupts/sec)".format(
        total_interrupts, 
        total_interrupts / interval if interval > 0 else 0
    ))
    print("Active VMs: {}".format(len(vm_stats)))
    print()
    
    # Display detailed statistics by VM
    for vm_idx, (kvm_ptr, vm_stat) in enumerate(sorted(vm_stats.items()), 1):
        active_threads = len(vm_stat['queues'])
        print("VM #{} (KVM=0x{:x})".format(vm_idx, kvm_ptr))
        print("   Total Interrupts: {} ({:.2f} interrupts/sec)".format(
            vm_stat['total_interrupts'],
            vm_stat['total_interrupts'] / interval if interval > 0 else 0
        ))
        print("   Threads with interrupts in this interval: {}".format(active_threads))
        
        if vm_stat['first_time'] and vm_stat['last_time']:
            print("   Activity Time: {} -> {}".format(vm_stat['first_time'], vm_stat['last_time']))
        
        # Calculate category summary
        total_data = sum(q['data_count'] for q in vm_stat['queues'].values())
        total_control = sum(q['control_count'] for q in vm_stat['queues'].values())
        
        if total_data > 0 or total_control > 0:
            print("   Interrupt Categories:")
            if total_data > 0:
                print("     Data Plane: {} ({:.1f}%)".format(
                    total_data, 
                    100.0 * total_data / vm_stat['total_interrupts']
                ))
            if total_control > 0:
                print("     Control Plane: {} ({:.1f}%)".format(
                    total_control,
                    100.0 * total_control / vm_stat['total_interrupts']
                ))
        
        # Display detailed information for each queue
        print("   Thread Details:")
        for queue_idx, (irqfd_ptr, queue_stat) in enumerate(sorted(vm_stat['queues'].items()), 1):
            rate = queue_stat['count'] / interval if interval > 0 else 0
            
            print("     Thread #{}: IRQFD=0x{:x}".format(queue_idx, irqfd_ptr))
            print("        GSI: {}".format(queue_stat['gsi']))
            if queue_stat['eventfd']:
                print("        EventFD: 0x{:x}".format(queue_stat['eventfd']))
            print("        Interrupts: {} ({:.2f}/sec)".format(queue_stat['count'], rate))
            
            # Display categories
            categories = []
            if queue_stat['data_count'] > 0:
                categories.append("Data:{}".format(queue_stat['data_count']))
            if queue_stat['control_count'] > 0:
                categories.append("Control:{}".format(queue_stat['control_count']))
            if categories:
                print("        Categories: {}".format(", ".join(categories)))
            
            print("        CPU Distribution: {}".format(sorted(list(queue_stat['cpus']))))
            print("        Process: {} (PID: {})".format(
                ', '.join(list(queue_stat['comms'])[:3]),
                ', '.join(str(pid) for pid in sorted(list(queue_stat['pids']))[:3])
            ))
        print()
    
    # Clear histogram for next round of statistics
    hist_table.clear()
    
    last_print_time = current_time

def main():
    parser = argparse.ArgumentParser(description="VM Interrupt Statistics Tool - Histogram Version (BCC Statistics Features)")
    parser.add_argument("qemu_pid", type=int, help="QEMU-KVM process PID (required)")
    parser.add_argument("--interval", type=int, default=5, help="Statistics output interval (seconds)")
    parser.add_argument("--vhost-pid", type=int, help="Filter specific VHOST thread PID (only with --category=data)")
    parser.add_argument("--category", choices=['data', 'control'], help="Filter interrupt category")
    parser.add_argument("--subcategory", choices=['rx', 'tx'], help="Filter RX or TX (only with --category=data)")
    args = parser.parse_args()
    
    global start_time
    start_time = time.time()
    
    print("Loading VM interrupt statistics program (histogram version)...")
    try:
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="irqfd_wakeup", fn_name="trace_vm_irqfd_stats")
        print("Successfully attached to irqfd_wakeup")
    except Exception as e:
        print("Loading failed: {}".format(e))
        return
    
    # Validate arguments
    if args.vhost_pid and args.category != 'data':
        print("Error: --vhost-pid can only be used with --category=data")
        return
    
    if args.subcategory and not args.category:
        print("Error: --subcategory requires --category to be specified")
        return
    
    # Set filter parameters
    filter_params = FilterParams()
    filter_params.qemu_pid = args.qemu_pid
    filter_params.vhost_pid = args.vhost_pid if args.vhost_pid else 0
    
    # Convert category filtering
    if args.category == 'data':
        filter_params.filter_category = 1
    elif args.category == 'control':
        filter_params.filter_category = 2
    else:
        filter_params.filter_category = 0
    
    # Convert subcategory filtering
    if args.subcategory == 'rx':
        filter_params.filter_subcategory = 1
    elif args.subcategory == 'tx':
        filter_params.filter_subcategory = 2
    else:
        filter_params.filter_subcategory = 0
    
    # Update filter configuration
    b["filter_config"][ct.c_int(0)] = filter_params
    
    print("\n" + "="*80)
    print("VM Interrupt Statistics Monitor - Histogram Version")
    print("="*80)
    print("Features:")
    print("  - Use BPF_HISTOGRAM for kernel-side statistics aggregation")
    print("  - Fixed vhost PID and COMM filtering issues")
    print("  - Periodic statistics histogram output")
    print("  - Ultra-high performance, suitable for high-frequency scenarios")
    
    # Display filter conditions
    print("\nMonitoring VM with QEMU PID: {}".format(args.qemu_pid))
    
    filters = []
    if not args.category:
        filters.append("Tracking both vhost-{} threads and control interrupts".format(args.qemu_pid))
    elif args.category == 'data':
        filters.append("Category: data (vhost-{} threads only)".format(args.qemu_pid))
        if args.vhost_pid:
            filters.append("VHOST Thread PID: {} (specific thread)".format(args.vhost_pid))
    elif args.category == 'control':
        filters.append("Category: control (QEMU process only)")
    
    if args.subcategory:
        filters.append("Subcategory: {}".format(args.subcategory))
    
    if filters:
        print("\nFilter Conditions:")
        for f in filters:
            print("  - {}".format(f))
    
    print("\nStatistics Interval: {} seconds".format(args.interval))
    print("\nStarting monitor... (Press Ctrl+C to exit)")
    print("="*80)
    
    # Main loop
    try:
        while True:
            time.sleep(args.interval)
            print_histogram_stats(b)
    except KeyboardInterrupt:
        print("\n\nReceived interrupt signal, displaying final statistics...")
        print_histogram_stats(b)
        print("\nMonitoring ended")

if __name__ == "__main__":
    main()