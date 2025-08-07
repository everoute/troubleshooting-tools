#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
VM Interrupt Statistics Tool - Aggregated irqfd_wakeup Statistics by VM

Aggregates interrupt statistics for each VM by using the kvm pointer in kvm_kernel_irqfd,
displaying interrupts for multiple RX queues per VM.
Supports multi-queue network devices; a single KVM instance may have multiple irqfd interrupt data structures.

Features:
1. Aggregates interrupt statistics by VM (KVM pointer)
2. Displays interrupt information for all queues of each VM
3. No filtering, outputs all irqfd_wakeup events
4. Real-time display of interrupt frequency and distribution

Test Environment: Virtualization Host
"""

from __future__ import print_function
import argparse
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
import ctypes as ct
import time
import signal
import sys
from collections import defaultdict, OrderedDict

bpf_text = """
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/poll.h>

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

#define member_address(source_struct, source_member)            \\
        ({                                                      \\
                void* __ret;                                    \\
                __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \\
                __ret;                                          \\
})

#define member_read(destination, source_struct, source_member)  \\
        do{                                                      \\
                bpf_probe_read_kernel(                           \\
                destination,                                     \\
                sizeof(source_struct->source_member),            \\
                member_address(source_struct, source_member)     \\
                );                                               \\
        } while(0)

#define READ_FIELD(dst, ptr, field)                                   \\
    do {                                                              \\
        typeof(ptr->field) __tmp;                                     \\
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \\
        *(dst) = __tmp;                                               \\
    } while (0)

struct vm_irqfd_event {
    u64 timestamp;
    u32 cpu_id;
    u32 pid;
    char comm[16];
    
    u64 kvm_ptr;
    u64 irqfd_ptr;
    u64 eventfd_ctx;
    u32 gsi;
    
    u64 wait_ptr;
    u64 resampler_ptr;
    u64 resamplefd_ptr;
    
    u8 stack_enabled;
    int stack_id;
};

BPF_PERF_OUTPUT(vm_irqfd_events);
BPF_STACK_TRACE(stack_traces, 4096);

int trace_vm_irqfd_stats(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    unsigned mode = (unsigned)PT_REGS_PARM2(ctx);
    int sync = (int)PT_REGS_PARM3(ctx);
    void *key = (void *)PT_REGS_PARM4(ctx);
    
    if (!wait) return 0;
    
    u64 flags = (u64)key;
    if (!(flags & 0x1)) return 0;
    
    struct kvm_kernel_irqfd *irqfd = (struct kvm_kernel_irqfd *)
        ((char *)wait - offsetof(struct kvm_kernel_irqfd, wait));
        
    if (!irqfd) return 0;
    
    struct kvm *kvm = NULL;
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;
    void *resampler = NULL;
    struct eventfd_ctx *resamplefd = NULL;
    
    READ_FIELD(&kvm, irqfd, kvm);
    READ_FIELD(&eventfd, irqfd, eventfd);
    READ_FIELD(&gsi, irqfd, gsi);
    READ_FIELD(&resampler, irqfd, resampler);
    READ_FIELD(&resamplefd, irqfd, resamplefd);
    
    if (!kvm || !eventfd || (u64)kvm < 0xffff000000000000ULL || (u64)eventfd < 0xffff000000000000ULL) {
        return 0;
    }
    
    struct vm_irqfd_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.cpu_id = bpf_get_smp_processor_id();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.kvm_ptr = (u64)kvm;
    event.irqfd_ptr = (u64)irqfd;
    event.eventfd_ctx = (u64)eventfd;
    event.gsi = (u32)gsi;
    event.wait_ptr = (u64)wait;
    event.resampler_ptr = (u64)resampler;
    event.resamplefd_ptr = (u64)resamplefd;
    
    event.stack_enabled = STACK_ENABLED;
    if (STACK_ENABLED) {
        event.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    } else {
        event.stack_id = -1;
    }
    
    vm_irqfd_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class VMIrqfdEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("cpu_id", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        
        ("kvm_ptr", ct.c_uint64),
        ("irqfd_ptr", ct.c_uint64),
        ("eventfd_ctx", ct.c_uint64),
        ("gsi", ct.c_uint32),
        
        ("wait_ptr", ct.c_uint64),
        ("resampler_ptr", ct.c_uint64),
        ("resamplefd_ptr", ct.c_uint64),
        
        ("stack_enabled", ct.c_uint8),
        ("stack_id", ct.c_int32),
    ]

vm_stats = defaultdict(lambda: {
    'total_interrupts': 0,
    'queues': defaultdict(lambda: {
        'count': 0,
        'gsi': None,
        'eventfd': None,
        'first_time': None,
        'last_time': None,
        'cpus': set(),
        'pids': set(),
        'comms': set()
    }),
    'first_seen': None,
    'last_seen': None
})

total_events = 0
start_time = None

filter_vhost_pid = None
filter_vhost_comm = None
filter_rx_only = False
filter_tx_only = False
enable_stack_trace = False
filter_category = None  # 'data', 'control', or None for all
filter_subcategory = None  # 'vhost-rx', 'vhost-tx', 'qemu', or None for all

bpf_instance = None
stack_cache = {}

def get_stack_trace(stack_id):
    """Get and format call stack"""
    global bpf_instance, stack_cache
    
    if stack_id < 0 or not bpf_instance:
        return []
    
    if stack_id in stack_cache:
        return stack_cache[stack_id]
    
    try:
        stack = list(bpf_instance["stack_traces"].walk(stack_id))
        formatted_stack = []
        
        for addr in stack:
            sym = bpf_instance.ksym(addr, show_module=True, show_offset=True)
            if sym:
                formatted_stack.append(sym)
            else:
                formatted_stack.append("0x{:x}".format(addr))
        
        stack_cache[stack_id] = formatted_stack
        return formatted_stack
        
    except Exception as e:
        return ["Failed to get stack: {}".format(str(e))]

def classify_interrupt(comm_str, stack_trace):
    """Classify interrupt based on process name and call stack
    Returns: (category, subcategory) tuple
    category: 'data' or 'control'
    subcategory: 'vhost-rx', 'vhost-tx', or 'qemu'
    """
    if comm_str.startswith('qemu'):
        return ('control', 'qemu')
    
    if comm_str.startswith('vhost-'):
        if stack_trace:
            stack_str = ' '.join(stack_trace)
            
            if 'handle_rx' in stack_str:
                return ('data', 'vhost-rx')
            
            if 'handle_tx' in stack_str or 'handle_tx_copy' in stack_str:
                return ('data', 'vhost-tx')
            
            if 'vhost_net_tx' in stack_str or 'vhost_tx' in stack_str:
                return ('data', 'vhost-tx')
            
            if 'vhost_net_rx' in stack_str or 'vhost_rx' in stack_str:
                return ('data', 'vhost-rx')
        
        return ('data', 'vhost-unknown')
    
    return ('unknown', 'unknown')

def process_event(cpu, data, size):
    global total_events, start_time, filter_vhost_pid, filter_vhost_comm, filter_rx_only, filter_tx_only, enable_stack_trace, filter_category, filter_subcategory
    
    event = ct.cast(data, ct.POINTER(VMIrqfdEvent)).contents
    
    if start_time is None:
        start_time = time.time()
    
    import datetime
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    comm_str = event.comm.decode('utf-8', 'replace')
    
    stack_trace = []
    if event.stack_enabled and event.stack_id >= 0:
        stack_trace = get_stack_trace(event.stack_id)
    
    category, subcategory = classify_interrupt(comm_str, stack_trace)
    
    should_show = True
    
    if filter_vhost_pid and event.pid != filter_vhost_pid:
        should_show = False
    
    if filter_vhost_comm and filter_vhost_comm not in comm_str:
        should_show = False
    
    if filter_category and category != filter_category:
        should_show = False
    
    if filter_subcategory and subcategory != filter_subcategory:
        should_show = False
    
    if filter_rx_only and subcategory != 'vhost-rx':
        should_show = False
    
    if filter_tx_only and subcategory != 'vhost-tx':
        should_show = False
    
    if not should_show:
        return
    
    total_events += 1
    kvm_ptr = event.kvm_ptr
    irqfd_ptr = event.irqfd_ptr
    
    vm_stat = vm_stats[kvm_ptr]
    vm_stat['total_interrupts'] += 1
    
    if vm_stat['first_seen'] is None:
        vm_stat['first_seen'] = timestamp_str
    vm_stat['last_seen'] = timestamp_str
    
    queue_stat = vm_stat['queues'][irqfd_ptr]
    queue_stat['count'] += 1
    queue_stat['gsi'] = event.gsi
    queue_stat['eventfd'] = event.eventfd_ctx
    
    if queue_stat['first_time'] is None:
        queue_stat['first_time'] = timestamp_str
    queue_stat['last_time'] = timestamp_str
    
    queue_stat['cpus'].add(event.cpu_id)
    queue_stat['pids'].add(event.pid)
    queue_stat['comms'].add(comm_str)
    
    if subcategory == 'vhost-rx':
        type_label = "[Data Plane-RX]"
    elif subcategory == 'vhost-tx':
        type_label = "[Data Plane-TX]"
    elif subcategory == 'qemu':
        type_label = "[Control Plane]"
    else:
        type_label = "[{}]".format(subcategory)
    
    print("{} VM=0x{:x} Queue=0x{:x} GSI={} EventFD=0x{:x} Time={} CPU={} PID={} COMM={}".format(
        type_label, kvm_ptr, irqfd_ptr, event.gsi, event.eventfd_ctx,
        timestamp_str, event.cpu_id, event.pid, comm_str))
    
    if enable_stack_trace and stack_trace:
        print("   Call Stack:")
        for i, frame in enumerate(stack_trace[:10]):
            if 'handle_rx' in frame:
                print("    #{}: {}  RXHandler Function".format(i, frame))
            elif 'handle_tx' in frame or 'handle_tx_copy' in frame:
                print("    #{}: {}  TXHandler Function".format(i, frame))
            else:
                print("    #{}: {}".format(i, frame))
        print()

def print_summary():
    current_time = time.time()
    duration = current_time - start_time if start_time else 0
    
    print("\n" + "="*100)
    print("VM Interrupt Statistics Summary (Aggregated by KVM Instance)")
    print("="*100)
    print("Monitor Duration: {:.2f} seconds".format(duration))
    print("Total Interrupts: {}".format(total_events))
    print("VMs Found: {}".format(len(vm_stats)))
    
    if duration > 0:
        print("Total Interrupt Rate: {:.2f} Interrupt/sec".format(total_events / duration))
    print()
    
    for vm_idx, (kvm_ptr, vm_stat) in enumerate(sorted(vm_stats.items()), 1):
        print("  VM #{} (KVM=0x{:x})".format(vm_idx, kvm_ptr))
        print("   Total Interrupts: {}".format(vm_stat['total_interrupts']))
        print("   Queue Count: {}".format(len(vm_stat['queues'])))
        print("   Active Time: {} -> {}".format(vm_stat['first_seen'], vm_stat['last_seen']))
        
        if duration > 0:
            vm_rate = vm_stat['total_interrupts'] / duration
            print("   Interrupt Rate: {:.2f} Interrupt/sec".format(vm_rate))
        
        print("   Queue Details:")
        for queue_idx, (irqfd_ptr, queue_stat) in enumerate(sorted(vm_stat['queues'].items()), 1):
            queue_rate = ""
            if duration > 0:
                rate = queue_stat['count'] / duration
                queue_rate = " ({:.2f}/sec)".format(rate)
            
            print("      Queue #{}: IRQFD=0x{:x}".format(queue_idx, irqfd_ptr))
            print("        GSI: {}".format(queue_stat['gsi']))
            print("        EventFD: 0x{:x}".format(queue_stat['eventfd']))
            print("        Interrupt Count: {}{}".format(queue_stat['count'], queue_rate))
            print("        Active Time: {} -> {}".format(queue_stat['first_time'], queue_stat['last_time']))
            print("        CPU Distribution: {}".format(sorted(list(queue_stat['cpus']))))
            print("        Process: {} (PID: {})".format(
                ', '.join(list(queue_stat['comms'])[:3]),
                ', '.join(str(pid) for pid in sorted(list(queue_stat['pids']))[:3])
            ))
        print()
    
    print(" Queue Distribution Analysis:")
    single_queue_vms = sum(1 for vm_stat in vm_stats.values() if len(vm_stat['queues']) == 1)
    multi_queue_vms = len(vm_stats) - single_queue_vms
    
    print("   Single Queue VM: {} items".format(single_queue_vms))
    print("   Multi Queue VM: {} items".format(multi_queue_vms))
    
    if multi_queue_vms > 0:
        max_queues = max(len(vm_stat['queues']) for vm_stat in vm_stats.values())
        print("   Max Queue Count: {}".format(max_queues))

def signal_handler(sig, frame):
    print("\n\nReceived interrupt signal, generating summary...")
    print_summary()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="VM Interrupt Statistics Tool - irqfd_wakeup statistics aggregated by VM")
    parser.add_argument("--timeout", type=int, default=60, help="Monitor time (seconds)")
    parser.add_argument("--summary-interval", type=int, default=10, help="Summary display interval (seconds)")
    parser.add_argument("--vhost-pid", type=int, help="Filter specific VHOST process PID")
    parser.add_argument("--vhost-comm", type=str, help="Filter specific VHOST process name (e.g. vhost-12345)")
    parser.add_argument("--rx-only", action="store_true", help="Show only data plane RX interrupts (vhost-rx)")
    parser.add_argument("--tx-only", action="store_true", help="Show only data plane TX interrupts (vhost-tx)")
    parser.add_argument("--category", choices=['data', 'control'], help="Filter interrupt category: data(data plane) or control(control plane)")
    parser.add_argument("--subcategory", choices=['vhost-rx', 'vhost-tx', 'qemu'], help="Filter interrupt subcategory")
    parser.add_argument("--stack-trace", action="store_true", help="Enable call stack tracing (analyze module interaction and data path)")
    args = parser.parse_args()
    
    global filter_vhost_pid, filter_vhost_comm, filter_rx_only, filter_tx_only, enable_stack_trace, bpf_instance, filter_category, filter_subcategory
    filter_vhost_pid = args.vhost_pid
    filter_vhost_comm = args.vhost_comm
    filter_rx_only = args.rx_only
    filter_tx_only = args.tx_only
    enable_stack_trace = args.stack_trace
    filter_category = args.category
    filter_subcategory = args.subcategory
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("Loading VM Interrupt Statistics Program...")
    try:
        bpf_text_with_macro = "#define STACK_ENABLED %d\n\n%s" % (
            1 if enable_stack_trace else 0,
            bpf_text
        )
        
        b = BPF(text=bpf_text_with_macro)
        bpf_instance = b
        b.attach_kprobe(event="irqfd_wakeup", fn_name="trace_vm_irqfd_stats")
        print(" Successfully attached to irqfd_wakeup")
        if enable_stack_trace:
            print(" Call Stack Tracing Enabled")
    except Exception as e:
        print(" Loading Failed: {}".format(e))
        return
    
    print("\n" + "="*80)
    print("VM Interrupt Statistics Monitor (Aggregated by KVM Instance)")
    print("="*80)
    print(" Features:")
    print("   Aggregate Interrupt Statistics by VM (KVM Pointer)")
    print("   Display Multiple RX/TX Queue Interrupt Info for Each VM")
    print("   Support Multi-Queue Network Device Analysis")
    print("   Real-time Display of Interrupt Frequency and Distribution")
    
    filters = []
    if filter_vhost_pid:
        filters.append("VHOST PID: {}".format(filter_vhost_pid))
    if filter_vhost_comm:
        filters.append("VHOST COMM: {}".format(filter_vhost_comm))
    if filter_category:
        filters.append("Category: {} ({})".format(filter_category, 'Data Plane' if filter_category == 'data' else 'Control Plane'))
    if filter_subcategory:
        subcategory_desc = {
            'vhost-rx': 'Data Plane RX (Host->Guest)',
            'vhost-tx': 'Data Plane TX Completion',
            'qemu': 'Control Plane Interrupt'
        }
        filters.append("Subcategory: {} ({})".format(filter_subcategory, subcategory_desc.get(filter_subcategory, filter_subcategory)))
    if filter_rx_only:
        filters.append("Data plane RX interrupts only")
    if filter_tx_only:
        filters.append("Data plane TX interrupts only")
    
    if filters:
        print("\n Filter Conditions:")
        for f in filters:
            print("   {}".format(f))
    
    if enable_stack_trace:
        print("\n Call Stack Analysis:")
        print("   Will display complete call chain triggered by interrupt")
        print("   Auto-classify interrupt types based on functions in call stack:")
        print("    - Data Plane RX: Contains handle_rx function (Host->Guest data reception)")
        print("    - Data Plane TX: Contains handle_tx/handle_tx_copy function (TX completion notification)")
        print("    - Control Plane: QEMU process triggered (configuration and control operations)")
    
    print("\nStarting monitor... (Press Ctrl+C to generate summary report)")
    print("\nInterrupt Classification Description:")
    print("  [Data-RX] = Host->Guest data reception interrupt (vhost process, handle_rx)")
    print("  [Data-TX] = TX completion notification interrupt (vhost process, handle_tx)")
    print("  [Control Plane] = Configuration and control interrupt (qemu-kvm process)")
    print("="*80)
    print()
    
    b["vm_irqfd_events"].open_perf_buffer(process_event)
    
    try:
        last_summary = time.time()
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)
                
                current_time = time.time()
                if current_time - last_summary >= args.summary_interval and total_events > 0:
                    print("\n" + "-"*50 + " Intermediate Summary " + "-"*50)
                    print_summary()
                    print("-"*100 + "\n")
                    last_summary = current_time
                    
            except KeyboardInterrupt:
                break
                
    except KeyboardInterrupt:
        pass
    
    print_summary()

if __name__ == "__main__":
    main()