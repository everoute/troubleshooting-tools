#!/usr/bin/env python
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
5. Call source analysis: detailed tracking of irqfd_wakeup parameters to identify different interrupt sources

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
from collections import defaultdict

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

#define READ_FIELD(dst, ptr, field)                                   \\
    do {                                                              \\
        typeof(ptr->field) __tmp;                                     \\
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \\
        *(dst) = __tmp;                                               \\
    } while (0)

typedef struct hist_key {
    u64 kvm_ptr;
    u64 irqfd_ptr;
    u32 gsi;
    u32 cpu_id;            // CPU ID
    u32 pid;
    char comm[16];
    // irqfd_wakeup function parameters
    u64 wait_ptr;          // wait_queue_entry_t *wait parameter
    u32 mode;              // unsigned mode parameter
    u32 sync;              // int sync parameter  
    u64 key_flags;         // void *key parameter (as flags)
    u64 slot;
} hist_key_t;

BPF_HISTOGRAM(irq_count_hist, hist_key_t);

struct irqfd_info {
    u32 gsi;
    u64 eventfd_ctx;
    u64 first_timestamp;
    u64 last_timestamp;
};

BPF_HASH(irqfd_info_map, u64, struct irqfd_info, 4096);

// Track KVM+GSI seen in irqfd_wakeup for comparison
struct kvm_gsi_key {
    u64 kvm_ptr;
    u32 gsi;
    u32 pad;
};
BPF_HASH(active_kvm_gsi, struct kvm_gsi_key, u8, 1024);

// Track active KVM pointers from irqfd_wakeup for filtering vgic_queue_irq_unlock
BPF_HASH(active_kvm_ptrs, u64, u8, 256);

// kvm_arch_set_irq_inatomic histogram key
typedef struct arch_set_irq_hist_key {
    u64 kvm_ptr;
    u32 gsi;
    u32 pad;
    u64 slot;
} arch_set_irq_hist_key_t;

BPF_HISTOGRAM(arch_set_irq_hist, arch_set_irq_hist_key_t);

// kvm_set_msi histogram key (slow path MSI injection)
typedef struct kvm_set_msi_hist_key {
    u64 kvm_ptr;
    u32 gsi;
    u32 pad;
    u64 slot;
} kvm_set_msi_hist_key_t;

BPF_HISTOGRAM(kvm_set_msi_hist, kvm_set_msi_hist_key_t);

// vgic_queue_irq_unlock histogram key (actual interrupt injection)
typedef struct vgic_queue_hist_key {
    u64 kvm_ptr;
    u32 intid;
    u32 pad;
    u64 slot;
} vgic_queue_hist_key_t;

BPF_HISTOGRAM(vgic_queue_hist, vgic_queue_hist_key_t);

// kvm_vcpu_kick histogram key (VCPU kick tracking)
typedef struct kvm_vcpu_kick_hist_key {
    u64 kvm_ptr;
    u32 vcpu_id;
    u32 pad;
    u64 slot;
} kvm_vcpu_kick_hist_key_t;

BPF_HISTOGRAM(kvm_vcpu_kick_hist, kvm_vcpu_kick_hist_key_t);

// Track return values of kvm_arch_set_irq_inatomic
struct arch_set_irq_ret_key {
    u64 kvm_ptr;
    u32 gsi;
    u32 pad;
};

struct arch_set_irq_ret_val {
    u64 total_calls;
    u64 success_count;    // ret > 0
    u64 fail_count;       // ret <= 0
    u64 total_delivered;  // sum of positive returns
};

BPF_HASH(arch_set_irq_ret_stats, struct arch_set_irq_ret_key, struct arch_set_irq_ret_val, 1024);
BPF_HASH(arch_set_irq_args, u64, struct arch_set_irq_ret_key, 1024);

// Filter parameters (set from userspace)
struct filter_params {
    u32 qemu_pid;          // Required parameter
    u32 vhost_pid;         // 0 means no filtering (only used when category=data)
    u8 filter_category;    // 0=all, 1=data, 2=control
    u8 filter_subcategory; // 0=all, 1=rx, 2=tx
};

BPF_ARRAY(filter_config, struct filter_params, 1);


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
    
    READ_FIELD(&kvm, irqfd, kvm);
    READ_FIELD(&eventfd, irqfd, eventfd);
    READ_FIELD(&gsi, irqfd, gsi);
    
    if (!kvm || !eventfd || (u64)kvm < 0xffff000000000000ULL || (u64)eventfd < 0xffff000000000000ULL) {
        return 0;
    }
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
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
    // Record irqfd_wakeup function parameters
    hist_key.wait_ptr = (u64)wait;
    hist_key.mode = mode;
    hist_key.sync = sync;
    hist_key.key_flags = flags;
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
    
    // Track this KVM+GSI combination for comparison
    struct kvm_gsi_key kvm_gsi_key = {};
    kvm_gsi_key.kvm_ptr = (u64)kvm;
    kvm_gsi_key.gsi = (u32)gsi;
    u8 active = 1;
    active_kvm_gsi.update(&kvm_gsi_key, &active);
    
    // Also track the KVM pointer for vgic_queue_irq_unlock filtering
    u64 kvm_ptr_key = (u64)kvm;
    active_kvm_ptrs.update(&kvm_ptr_key, &active);
    
    return 0;
}

// Trace kvm_arch_set_irq_inatomic with filtering based on active_kvm_gsi
int trace_kvm_arch_set_irq_inatomic(struct pt_regs *ctx) {
    struct kvm_kernel_irq_routing_entry *e = (struct kvm_kernel_irq_routing_entry *)PT_REGS_PARM1(ctx);
    struct kvm *kvm = (struct kvm *)PT_REGS_PARM2(ctx);
    
    if (!e || !kvm || (u64)kvm < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Extract GSI from routing entry
    u32 gsi = 0;
    bpf_probe_read_kernel(&gsi, sizeof(gsi), &e->gsi);
    
    // Apply filtering based on active_kvm_gsi from irqfd_wakeup
    struct kvm_gsi_key filter_key = {};
    filter_key.kvm_ptr = (u64)kvm;
    filter_key.gsi = gsi;
    
    u8 *is_active = active_kvm_gsi.lookup(&filter_key);
    if (!is_active) {
        // This KVM+GSI was not seen in irqfd_wakeup, skip it
        return 0;
    }
    
    // Record to arch_set_irq histogram
    arch_set_irq_hist_key_t hist_key = {};
    hist_key.kvm_ptr = (u64)kvm;
    hist_key.gsi = gsi;
    hist_key.slot = 0;
    
    arch_set_irq_hist.atomic_increment(hist_key);
    
    // Store parameters for return probe
    struct arch_set_irq_ret_key ret_key = {};
    ret_key.kvm_ptr = (u64)kvm;
    ret_key.gsi = gsi;
    
    u64 tid = bpf_get_current_pid_tgid();
    arch_set_irq_args.update(&tid, &ret_key);
    
    return 0;
}

int trace_kvm_arch_set_irq_inatomic_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 tid = bpf_get_current_pid_tgid();
    
    struct arch_set_irq_ret_key *key_ptr = arch_set_irq_args.lookup(&tid);
    if (!key_ptr) return 0;
    
    struct arch_set_irq_ret_key key = *key_ptr;
    arch_set_irq_args.delete(&tid);
    
    // Update return value statistics
    struct arch_set_irq_ret_val *val = arch_set_irq_ret_stats.lookup(&key);
    if (!val) {
        struct arch_set_irq_ret_val new_val = {};
        new_val.total_calls = 1;
        if (ret > 0) {
            new_val.success_count = 1;
            new_val.total_delivered = ret;
        } else {
            new_val.fail_count = 1;
        }
        arch_set_irq_ret_stats.update(&key, &new_val);
    } else {
        val->total_calls++;
        if (ret > 0) {
            val->success_count++;
            val->total_delivered += ret;
        } else {
            val->fail_count++;
        }
    }
    
    return 0;
}

// Trace kvm_set_msi for slow path MSI injection
int trace_kvm_set_msi(struct pt_regs *ctx) {
    struct kvm_kernel_irq_routing_entry *e = (struct kvm_kernel_irq_routing_entry *)PT_REGS_PARM1(ctx);
    struct kvm *kvm = (struct kvm *)PT_REGS_PARM2(ctx);
    
    if (!e || !kvm || (u64)kvm < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Extract GSI from routing entry
    u32 gsi = 0;
    bpf_probe_read_kernel(&gsi, sizeof(gsi), &e->gsi);
    
    // Apply filtering based on active_kvm_gsi from irqfd_wakeup
    struct kvm_gsi_key filter_key = {};
    filter_key.kvm_ptr = (u64)kvm;
    filter_key.gsi = gsi;
    
    u8 *is_active = active_kvm_gsi.lookup(&filter_key);
    if (!is_active) {
        // This KVM+GSI was not seen in irqfd_wakeup, skip it
        return 0;
    }
    
    // Record to kvm_set_msi histogram
    kvm_set_msi_hist_key_t hist_key = {};
    hist_key.kvm_ptr = (u64)kvm;
    hist_key.gsi = gsi;
    hist_key.slot = 0;
    
    kvm_set_msi_hist.atomic_increment(hist_key);
    
    return 0;
}

// Trace vgic_queue_irq_unlock for actual interrupt injection
int trace_vgic_queue_irq_unlock(struct pt_regs *ctx) {
    struct kvm *kvm = (struct kvm *)PT_REGS_PARM1(ctx);
    struct vgic_irq *irq = (struct vgic_irq *)PT_REGS_PARM2(ctx);
    
    if (!kvm || !irq || (u64)kvm < 0xffff000000000000ULL || (u64)irq < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Apply filtering based on active KVM pointers from irqfd_wakeup
    u64 kvm_ptr_key = (u64)kvm;
    u8 *is_active = active_kvm_ptrs.lookup(&kvm_ptr_key);
    if (!is_active) {
        // This KVM was not seen in irqfd_wakeup, skip it
        return 0;
    }
    
    // Extract intid from vgic_irq
    u32 intid = 0;
    bpf_probe_read_kernel(&intid, sizeof(intid), &irq->intid);
    
    // Record to vgic_queue histogram  
    vgic_queue_hist_key_t hist_key = {};
    hist_key.kvm_ptr = (u64)kvm;
    hist_key.intid = intid;
    hist_key.slot = 0;
    
    vgic_queue_hist.atomic_increment(hist_key);
    
    return 0;
}

// Trace kvm_vcpu_kick for VCPU kick tracking
int trace_kvm_vcpu_kick(struct pt_regs *ctx) {
    struct kvm_vcpu *vcpu = (struct kvm_vcpu *)PT_REGS_PARM1(ctx);
    
    if (!vcpu || (u64)vcpu < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Extract KVM pointer and VCPU ID from kvm_vcpu structure
    struct kvm *kvm = NULL;
    u32 vcpu_id = 0;
    
    // Read kvm pointer from vcpu->kvm (offset 0 in kvm_vcpu structure)
    bpf_probe_read_kernel(&kvm, sizeof(kvm), &vcpu->kvm);
    if (!kvm || (u64)kvm < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Read vcpu_id from vcpu->vcpu_id
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), &vcpu->vcpu_id);
    
    // Apply filtering based on active KVM pointers from irqfd_wakeup
    u64 kvm_ptr_key = (u64)kvm;
    u8 *is_active = active_kvm_ptrs.lookup(&kvm_ptr_key);
    if (!is_active) {
        // This KVM was not seen in irqfd_wakeup, skip it
        return 0;
    }
    
    // Record to kvm_vcpu_kick histogram
    kvm_vcpu_kick_hist_key_t hist_key = {};
    hist_key.kvm_ptr = (u64)kvm;
    hist_key.vcpu_id = vcpu_id;
    hist_key.slot = 0;
    
    kvm_vcpu_kick_hist.atomic_increment(hist_key);
    
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
        # irqfd_wakeup function parameters
        ("wait_ptr", ct.c_uint64),
        ("mode", ct.c_uint32),
        ("sync", ct.c_uint32),
        ("key_flags", ct.c_uint64),
        ("slot", ct.c_uint64),
    ]

class IrqfdInfo(ct.Structure):
    _fields_ = [
        ("gsi", ct.c_uint32),
        ("eventfd_ctx", ct.c_uint64),
        ("first_timestamp", ct.c_uint64),
        ("last_timestamp", ct.c_uint64),
    ]

class ArchSetIrqHistKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("pad", ct.c_uint32),
        ("slot", ct.c_uint64),
    ]

class ArchSetIrqRetKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("pad", ct.c_uint32),
    ]

class ArchSetIrqRetVal(ct.Structure):
    _fields_ = [
        ("total_calls", ct.c_uint64),
        ("success_count", ct.c_uint64),
        ("fail_count", ct.c_uint64),
        ("total_delivered", ct.c_uint64),
    ]

class KvmSetMsiHistKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("pad", ct.c_uint32),
        ("slot", ct.c_uint64),
    ]

class VgicQueueHistKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("intid", ct.c_uint32),
        ("pad", ct.c_uint32),
        ("slot", ct.c_uint64),
    ]

class KvmVcpuKickHistKey(ct.Structure):
    _fields_ = [
        ("kvm_ptr", ct.c_uint64),
        ("vcpu_id", ct.c_uint32),
        ("pad", ct.c_uint32),
        ("slot", ct.c_uint64),
    ]

class FilterParams(ct.Structure):
    _fields_ = [
        ("qemu_pid", ct.c_uint32),
        ("vhost_pid", ct.c_uint32),
        ("filter_category", ct.c_uint8),
        ("filter_subcategory", ct.c_uint8),
    ]

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
    
    import datetime
    current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    print("\n" + "="*100)
    print("VM Interrupt Statistics Summary (Histogram Version)")
    print("="*100)
    print("Timestamp: {}".format(current_timestamp))
    print("Statistics Duration: {:.2f} seconds (Current Interval: {:.2f} seconds)".format(duration, interval))
    
    vm_stats = defaultdict(lambda: {
        'total_interrupts': 0,
        'total_arch_set_irq': 0,
        'total_kvm_set_msi': 0,
        'total_vgic_queue': 0,
        'total_vcpu_kick': 0,
        'queues': defaultdict(lambda: {
            'count': 0,
            'arch_set_irq_count': 0,
            'kvm_set_msi_count': 0,
            'vgic_queue_count': 0,
            'gsi': None,
            'eventfd': None,
            'cpus': set(),
            'pids': set(),
            'comms': set(),
            'data_count': 0,
            'control_count': 0,
            'call_sources': defaultdict(int)  # Track different call sources for same GSI
        }),
        'first_time': None,
        'last_time': None,
        'arch_set_irq_ret_stats': defaultdict(lambda: {
            'total': 0,
            'success': 0,
            'fail': 0,
            'total_delivered': 0
        }),
        'kvm_set_msi_by_gsi': defaultdict(int),
        'vgic_queue_by_intid': defaultdict(int),
        'vcpu_kick_by_vcpuid': defaultdict(int)
    })
    
    total_interrupts = 0
    
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
        
        irqfd_info = b["irqfd_info_map"].get(ct.c_uint64(irqfd_ptr))
        if irqfd_info:
            first_time = format_timestamp(irqfd_info.first_timestamp)
            last_time = format_timestamp(irqfd_info.last_timestamp)
            
            if vm_stat['first_time'] is None or first_time < vm_stat['first_time']:
                vm_stat['first_time'] = first_time
            if vm_stat['last_time'] is None or last_time > vm_stat['last_time']:
                vm_stat['last_time'] = last_time
        
        queue_stat = vm_stat['queues'][irqfd_ptr]
        queue_stat['count'] += count
        queue_stat['gsi'] = k.gsi
        
        if irqfd_info:
            queue_stat['eventfd'] = irqfd_info.eventfd_ctx
        
        queue_stat['cpus'].add(k.cpu_id)
        queue_stat['pids'].add(k.pid)
        
        comm_str = k.comm.decode('utf-8', 'replace')
        queue_stat['comms'].add(comm_str)
        
        # Track call sources with irqfd_wakeup parameters as unique identifier
        call_source_key = "wait:0x{:x}_mode:{}_sync:{}_flags:0x{:x}".format(
            k.wait_ptr, k.mode, k.sync, k.key_flags)
        queue_stat['call_sources'][call_source_key] += count
        
        if comm_str.startswith('qemu'):
            queue_stat['control_count'] += count
        elif comm_str.startswith('vhost-'):
            queue_stat['data_count'] += count
    
    # Process kvm_arch_set_irq_inatomic histogram
    arch_set_irq_table = b["arch_set_irq_hist"]
    total_arch_set_irq = 0
    
    for k, v in arch_set_irq_table.items():
        if v.value == 0:
            continue
        kvm_ptr = k.kvm_ptr
        irqfd_ptr = 0  # We don't have irqfd_ptr in this trace
        gsi = k.gsi
        count = v.value
        
        total_arch_set_irq += count
        
        vm_stat = vm_stats[kvm_ptr]
        vm_stat['total_arch_set_irq'] += count
        
        # Find matching queue by GSI
        for queue_irqfd_ptr, queue_stat in vm_stat['queues'].items():
            if queue_stat['gsi'] == gsi:
                queue_stat['arch_set_irq_count'] += count
                break
    
    # Process kvm_set_msi histogram (slow path MSI injection)
    kvm_set_msi_table = b["kvm_set_msi_hist"]
    total_kvm_set_msi = 0
    
    for k, v in kvm_set_msi_table.items():
        if v.value == 0:
            continue
        kvm_ptr = k.kvm_ptr
        gsi = k.gsi
        count = v.value
        
        total_kvm_set_msi += count
        
        vm_stat = vm_stats[kvm_ptr]
        vm_stat['total_kvm_set_msi'] += count
        vm_stat['kvm_set_msi_by_gsi'][gsi] += count
        
        # Find matching queue by GSI
        for queue_irqfd_ptr, queue_stat in vm_stat['queues'].items():
            if queue_stat['gsi'] == gsi:
                queue_stat['kvm_set_msi_count'] += count
                break
    
    # Process vgic_queue_irq_unlock histogram (actual interrupt injection)
    vgic_queue_table = b["vgic_queue_hist"]
    total_vgic_queue = 0
    
    for k, v in vgic_queue_table.items():
        if v.value == 0:
            continue
        kvm_ptr = k.kvm_ptr
        intid = k.intid
        count = v.value
        
        total_vgic_queue += count
        
        vm_stat = vm_stats[kvm_ptr]
        vm_stat['total_vgic_queue'] += count
        vm_stat['vgic_queue_by_intid'][intid] += count
        
        # For vgic_queue, we track by intid which may differ from GSI
        # We'll aggregate to VM level for now
    
    # Process kvm_vcpu_kick histogram (VCPU kick tracking)
    vcpu_kick_table = b["kvm_vcpu_kick_hist"]
    total_vcpu_kick = 0
    
    for k, v in vcpu_kick_table.items():
        if v.value == 0:
            continue
        kvm_ptr = k.kvm_ptr
        vcpu_id = k.vcpu_id
        count = v.value
        
        total_vcpu_kick += count
        
        vm_stat = vm_stats[kvm_ptr]
        vm_stat['total_vcpu_kick'] += count
        vm_stat['vcpu_kick_by_vcpuid'][vcpu_id] += count
    
    # Process kvm_arch_set_irq_inatomic return statistics
    arch_ret_table = b["arch_set_irq_ret_stats"]
    for k, v in arch_ret_table.items():
        if v.total_calls == 0:
            continue
            
        kvm_ptr = k.kvm_ptr
        gsi = k.gsi
        
        vm_stat = vm_stats[kvm_ptr]
        ret_stats = vm_stat['arch_set_irq_ret_stats'][gsi]
        ret_stats['total'] += v.total_calls
        ret_stats['success'] += v.success_count
        ret_stats['fail'] += v.fail_count
        ret_stats['total_delivered'] += v.total_delivered
    
    print("DEBUG: Interrupt chain analysis:")
    print("  Total irqfd_wakeup calls: {}".format(total_interrupts))
    print("  Total kvm_arch_set_irq_inatomic calls: {}".format(total_arch_set_irq))
    print("  Total kvm_set_msi calls: {}".format(total_kvm_set_msi))
    print("  Total vgic_queue_irq_unlock calls: {}".format(total_vgic_queue))
    print("  Total kvm_vcpu_kick calls: {}".format(total_vcpu_kick))
    
    # Show target VM analysis
    target_kvm = 0xffffb28da688d000
    target_vm_stat = vm_stats.get(target_kvm)
    if target_vm_stat:
        print("  Target VM (0x{:x}):".format(target_kvm))
        print("    Wakeups: {}".format(target_vm_stat['total_interrupts']))
        print("    Arch set_irq: {}".format(target_vm_stat['total_arch_set_irq']))
        print("    kvm_set_msi: {}".format(target_vm_stat['total_kvm_set_msi']))
        print("    vgic_queue: {}".format(target_vm_stat['total_vgic_queue']))
        print("    vcpu_kick: {}".format(target_vm_stat['total_vcpu_kick']))
        
        if target_vm_stat['arch_set_irq_ret_stats']:
            print("    Arch set_irq results by GSI:")
            for gsi, stats in sorted(target_vm_stat['arch_set_irq_ret_stats'].items()):
                if stats['total'] > 0:
                    success_rate = 100.0 * stats['success'] / stats['total'] if stats['total'] > 0 else 0
                    avg_delivered = stats['total_delivered'] / stats['success'] if stats['success'] > 0 else 0
                    print("      GSI {}: total={}, success={} ({:.1f}%), fail={}, avg_delivered={:.1f}".format(
                        gsi, stats['total'], stats['success'], success_rate, stats['fail'], avg_delivered))
        
        print("    Per-queue breakdown:")
        for irqfd_ptr, queue_stat in target_vm_stat['queues'].items():
            if queue_stat['count'] > 0:
                injection_rate = queue_stat['arch_set_irq_count'] / queue_stat['count'] if queue_stat['count'] > 0 else 0
                msi_rate = queue_stat['kvm_set_msi_count'] / queue_stat['count'] if queue_stat['count'] > 0 else 0
                print("      GSI {}: wakeups={}, arch_injections={} ({:.1f}%), msi_injections={} ({:.1f}%)".format(
                    queue_stat['gsi'], queue_stat['count'], queue_stat['arch_set_irq_count'], 
                    100.0 * injection_rate, queue_stat['kvm_set_msi_count'], 100.0 * msi_rate))
    
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
        print("   Arch set_irq calls: {} ({:.2f}/sec)".format(
            vm_stat['total_arch_set_irq'],
            vm_stat['total_arch_set_irq'] / interval if interval > 0 else 0
        ))
        print("   kvm_set_msi calls: {} ({:.2f}/sec)".format(
            vm_stat['total_kvm_set_msi'],
            vm_stat['total_kvm_set_msi'] / interval if interval > 0 else 0
        ))
        print("   vgic_queue calls: {} ({:.2f}/sec)".format(
            vm_stat['total_vgic_queue'],
            vm_stat['total_vgic_queue'] / interval if interval > 0 else 0
        ))
        print("   vcpu_kick calls: {} ({:.2f}/sec)".format(
            vm_stat['total_vcpu_kick'],
            vm_stat['total_vcpu_kick'] / interval if interval > 0 else 0
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
            
            # Display call sources for this GSI
            if len(queue_stat['call_sources']) > 1:
                print("        Call Sources for GSI {}:".format(queue_stat['gsi']))
                for source_idx, (call_source, source_count) in enumerate(sorted(queue_stat['call_sources'].items(), key=lambda x: x[1], reverse=True), 1):
                    source_rate = source_count / interval if interval > 0 else 0
                    percentage = 100.0 * source_count / queue_stat['count'] if queue_stat['count'] > 0 else 0
                    print("          Source #{}: {} ({:.2f}/sec, {:.1f}%)".format(
                        source_idx, call_source, source_rate, percentage))
            elif len(queue_stat['call_sources']) == 1:
                call_source = list(queue_stat['call_sources'].keys())[0]
                print("        Single Call Source: {}".format(call_source))
        
        # Display vgic_queue_irq_unlock statistics by intid
        if vm_stat['vgic_queue_by_intid']:
            print("   vgic_queue_irq_unlock breakdown by intid:")
            for intid, count in sorted(vm_stat['vgic_queue_by_intid'].items()):
                if count > 0:
                    rate = count / interval if interval > 0 else 0
                    print("     intid {}: {} calls ({:.2f}/sec)".format(intid, count, rate))
        
        # Display kvm_vcpu_kick statistics by vcpu_id
        if vm_stat['vcpu_kick_by_vcpuid']:
            print("   kvm_vcpu_kick breakdown by VCPU ID:")
            for vcpu_id, count in sorted(vm_stat['vcpu_kick_by_vcpuid'].items()):
                if count > 0:
                    rate = count / interval if interval > 0 else 0
                    print("     VCPU {}: {} kicks ({:.2f}/sec)".format(vcpu_id, count, rate))
        
        print()
    
    # Clear histograms for next round of statistics
    hist_table.clear()
    arch_set_irq_table.clear()
    arch_ret_table.clear()
    kvm_set_msi_table.clear()
    vgic_queue_table.clear()
    vcpu_kick_table.clear()
    # Keep active_kvm_gsi and active_kvm_ptrs for cross-reference
    
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
        b.attach_kprobe(event="kvm_arch_set_irq_inatomic", fn_name="trace_kvm_arch_set_irq_inatomic")
        b.attach_kretprobe(event="kvm_arch_set_irq_inatomic", fn_name="trace_kvm_arch_set_irq_inatomic_ret")
        print("Successfully attached to kvm_arch_set_irq_inatomic")
        b.attach_kprobe(event="kvm_set_msi", fn_name="trace_kvm_set_msi")
        print("Successfully attached to kvm_set_msi")
        b.attach_kprobe(event="vgic_queue_irq_unlock", fn_name="trace_vgic_queue_irq_unlock")
        print("Successfully attached to vgic_queue_irq_unlock")
        b.attach_kprobe(event="kvm_vcpu_kick", fn_name="trace_kvm_vcpu_kick")
        print("Successfully attached to kvm_vcpu_kick")
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
    
    b["filter_config"][ct.c_int(0)] = filter_params
    
    print("\n" + "="*80)
    print("VM Interrupt Statistics Monitor - Histogram Version")
    print("="*80)
    print("Features:")
    print("  - Use BPF_HISTOGRAM for kernel-side statistics aggregation")
    print("  - Fixed vhost PID and COMM filtering issues")
    print("  - Periodic statistics histogram output")
    print("  - Call source analysis with irqfd_wakeup parameter tracking")
    print("  - Complete interrupt chain tracking: irqfd_wakeup -> kvm_arch_set_irq_inatomic -> kvm_set_msi -> vgic_queue_irq_unlock -> kvm_vcpu_kick")
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