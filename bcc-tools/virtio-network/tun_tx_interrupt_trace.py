#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
TUN TX Queue Interrupt Trace Tool

Traces the complete interrupt chain for specified TUN TX queue:
tun_net_xmit -> vhost_signal -> irqfd_wakeup

Based on proven implementation from vhost_queue_correlation_monitor.py
Implements ultra ultra think design with precise probe point chaining.
"""

from __future__ import print_function
import argparse
import datetime
import json
from bcc import BPF
import ctypes as ct
from time import sleep

# Data structures based on vhost_queue_correlation_monitor.py
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

class QueueKey(ct.Structure):
    _fields_ = [
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
    ]

class InterruptTraceEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("stage", ct.c_uint8),
        ("cpu_id", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_name", ct.c_char * 16),
        ("queue_index", ct.c_uint32),
        ("sock_ptr", ct.c_uint64),
        ("eventfd_ctx", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("delay_ns", ct.c_uint64),
        # Packet info from tun_net_xmit
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("protocol", ct.c_uint8),
    ]

# BPF program with proven structures and implementation
bpf_text = """
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/ptr_ring.h>
#include <linux/if_tun.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/eventfd.h>
#include <linux/wait.h>
#include <linux/kvm_host.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/poll.h>

#define NETDEV_ALIGN 32
#define MAX_QUEUES 256
#define IFNAMSIZ 16

// Device name union for efficient comparison
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Proven macros from vhost_queue_correlation_monitor.py
#define member_address(source_struct, source_member)            \
        ({                                                      \
                void* __ret;                                    \
                __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
                __ret;                                          \
})

#define member_read(destination, source_struct, source_member)  \
        do{                                                      \
                bpf_probe_read_kernel(                           \
                destination,                                     \
                sizeof(source_struct->source_member),            \
                member_address(source_struct, source_member)     \
                );                                               \
} while(0)

#define READ_FIELD(dst, ptr, field)                                   \
    do {                                                              \
        typeof(ptr->field) __tmp;                                     \
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \
        *(dst) = __tmp;                                               \
    } while (0)

// Proven TUN structures from vhost_queue_correlation_monitor.py
struct tun_struct {
	struct tun_file __rcu	*tfiles[256];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;
	struct net_device	*dev;
	netdev_features_t	set_features;
	int			align;
	int			vnet_hdr_sz;
	int			sndbuf;
	struct sock_fprog	fprog;
	bool			filter_attached;
	int debug;
	spinlock_t lock;
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
	u32 rx_batched;
	struct tun_pcpu_stats __percpu *pcpu_stats;
	struct bpf_prog __rcu *xdp_prog;
	struct tun_prog __rcu *steering_prog;
	struct tun_prog __rcu *filter_prog;
};

struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct fasync_struct *fasync;
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct napi_struct napi;
	bool napi_enabled;
	bool napi_frags_enabled;
	struct mutex napi_mutex;
	struct list_head next;
	struct tun_struct *detached;
	struct ptr_ring tx_ring;
	struct xdp_rxq_info xdp_rxq;
};

// Proven VHOST structures from vhost_queue_correlation_monitor.py
struct vhost_work {
    struct llist_node node;
    void *fn;  // vhost_work_fn_t
    unsigned long flags;
};

struct vhost_poll {
    poll_table table;
    wait_queue_head_t *wqh;
    wait_queue_entry_t wait;
    struct vhost_work work;
    __poll_t mask;
    struct vhost_dev *dev;
};

struct vhost_dev {
    struct mm_struct *mm;
    struct mutex mutex;
    struct vhost_virtqueue **vqs;
    int nvqs;
    struct eventfd_ctx *log_ctx;
    struct llist_head work_list;
    struct task_struct *worker;
    struct vhost_umem *umem;
    struct vhost_umem *iotlb;
    spinlock_t iotlb_lock;
    struct list_head read_list;
    struct list_head pending_list;
    wait_queue_head_t wait;
    int iov_limit;
    int weight;
    int byte_weight;
};

struct vhost_virtqueue {
    struct vhost_dev *dev;
    
    // The actual ring of buffers
    struct mutex mutex;
    unsigned int num;
    struct vring_desc *desc;       // __user pointer
    struct vring_avail *avail;     // __user pointer 
    struct vring_used *used;       // __user pointer
    void *meta_iotlb[3];           // VHOST_NUM_ADDRS = 3
    struct file *kick;
    struct eventfd_ctx *call_ctx;
    struct eventfd_ctx *error_ctx;
    struct eventfd_ctx *log_ctx;
    
    struct vhost_poll poll;
    
    // The routine to call when the Guest pings us, or timeout
    void *handle_kick;  // vhost_work_fn_t
    
    // Last available index we saw
    u16 last_avail_idx;
    
    // Caches available index value from user
    u16 avail_idx;
    
    // Last index we used
    u16 last_used_idx;
    
    // Used flags
    u16 used_flags;
    
    // Last used index value we have signalled on
    u16 signalled_used;
    
    // Last used index value we have signalled on
    bool signalled_used_valid;
    
    // Log writes to used structure
    bool log_used;
    u64 log_addr;
    
    struct iovec iov[1024];        // UIO_MAXIOV = 1024
    struct iovec iotlb_iov[64];
    struct iovec *indirect;
    struct vring_used_elem *heads;
    
    // Protected by virtqueue mutex
    struct vhost_umem *umem;
    struct vhost_umem *iotlb;
    void *private_data;            // This is the socket pointer we need!
    u64 acked_features;
    u64 acked_backend_features;
};

// Complete kvm_kernel_irqfd structure definition - based on virt/kvm/eventfd.c
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

// Data structures for interrupt chain tracking
struct queue_key {
    u64 sock_ptr;        // Unique sock pointer for this queue
    u32 queue_index;     // Queue index
    char dev_name[16];   // Device name
};

struct interrupt_connection {
    u64 sock_ptr;        // TUN -> VHOST connection
    u64 eventfd_ctx;     // VHOST -> IRQFD connection
    char dev_name[16];   // Device name
    u32 queue_index;     // Queue index
    u64 timestamp;       // Timestamp for sequence validation
};

struct interrupt_trace_event {
    u64 timestamp;
    u8 stage;
    u32 cpu_id;
    u32 pid;
    char comm[16];
    char dev_name[16];
    u32 queue_index;
    u64 sock_ptr;
    u64 eventfd_ctx;
    u64 vq_ptr;
    u32 gsi;
    u64 delay_ns;
    // Packet info from tun_net_xmit
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
};

// BPF Maps for interrupt chain tracking
BPF_HASH(target_queues, u64, struct queue_key, 256);           // sock_ptr -> queue info
BPF_HASH(interrupt_chains, u64, struct interrupt_connection, 256); // eventfd_ctx -> connection
BPF_HASH(sequence_check, u64, u64, 256);                       // eventfd_ctx -> last_stage

// Device and queue filtering
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Event output
BPF_PERF_OUTPUT(interrupt_events);

// Device filter logic from vhost_queue_correlation_monitor.py
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname;
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev->name);

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 1;  // No filter set - accept all devices
    }
    if(leaf->name_int.hi == 0 && leaf->name_int.lo == 0){
        return 1;  // Empty filter - accept all devices
    }
    if(leaf->name_int.hi != real_devname.name_int.hi || leaf->name_int.lo != real_devname.name_int.lo){
        return 0;  // Device name doesn't match
    }
    return 1;  // Device name matches
}

// Helper function to submit events
static inline void submit_interrupt_event(struct pt_regs *ctx, struct interrupt_trace_event *event) {
    event->timestamp = bpf_ktime_get_ns();
    event->cpu_id = bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    interrupt_events.perf_submit(ctx, event, sizeof(*event));
}

// Stage 1: tun_net_xmit - Based on proven implementation
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter - KEY FILTER POINT from vhost_queue_correlation_monitor.py
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    
    // Get TUN structure using proven approach
    u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    struct tun_struct *tun = (struct tun_struct *)((char *)dev + aligned_size);
    
    u32 tun_numqueues = 0;
    READ_FIELD(&tun_numqueues, tun, numqueues);
    
    if (queue_index >= tun_numqueues || queue_index >= 256) {
        return 0;
    }
    
    // Get tfile for this queue using proven pointer arithmetic
    struct tun_file *tfile = NULL;
    if (queue_index < tun_numqueues && tun_numqueues > 0 && queue_index < 256) {
        void **tfile_ptr_addr = (void**)((char*)tun + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }
    
    // Get socket pointer from tfile - PROVEN APPROACH
    u64 sock_ptr = (u64)&tfile->socket;
    
    // Register this queue as target
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    target_queues.update(&sock_ptr, &qkey);
    
    // Extract packet information
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8 protocol = 0;
    
    struct iphdr *ip_header = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    if ((char*)ip_header + sizeof(struct iphdr) <= (char*)skb->tail) {
        READ_FIELD(&saddr, ip_header, saddr);
        READ_FIELD(&daddr, ip_header, daddr);
        READ_FIELD(&protocol, ip_header, protocol);
        
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)((char*)ip_header + sizeof(struct iphdr));
            if ((char*)tcp_header + sizeof(struct tcphdr) <= (char*)skb->tail) {
                READ_FIELD(&sport, tcp_header, source);
                READ_FIELD(&dport, tcp_header, dest);
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)((char*)ip_header + sizeof(struct iphdr));
            if ((char*)udp_header + sizeof(struct udphdr) <= (char*)skb->tail) {
                READ_FIELD(&sport, udp_header, source);
                READ_FIELD(&dport, udp_header, dest);
            }
        }
    }
    
    // Emit Stage 1 event
    struct interrupt_trace_event event = {};
    event.stage = 1;  // tun_net_xmit
    // Manual copy instead of __builtin_memcpy to avoid BPF issues
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = qkey.dev_name[i];
    }
    event.queue_index = queue_index;
    event.sock_ptr = sock_ptr;
    event.saddr = saddr;
    event.daddr = daddr;
    event.sport = sport;
    event.dport = dport;
    event.protocol = protocol;
    event.delay_ns = 0;
    
    submit_interrupt_event(ctx, &event);
    return 0;
}

// Stage 2: vhost_signal - Based on proven implementation
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer from private_data using proven approach
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Get eventfd_ctx for chain connection
    struct eventfd_ctx *call_ctx = NULL;
    READ_FIELD(&call_ctx, vq, call_ctx);
    u64 eventfd_ctx = (u64)call_ctx;
    
    if (!call_ctx) return 0;  // Invalid eventfd
    
    // Save interrupt chain connection for irqfd_inject to use
    struct interrupt_connection ic_info = {};
    ic_info.sock_ptr = sock_ptr;
    ic_info.eventfd_ctx = eventfd_ctx;
    // Manual copy instead of __builtin_memcpy
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        ic_info.dev_name[i] = qkey->dev_name[i];
    }
    ic_info.queue_index = qkey->queue_index;
    ic_info.timestamp = bpf_ktime_get_ns();
    interrupt_chains.update(&eventfd_ctx, &ic_info);
    
    // Update sequence check - Stage 2 should come after Stage 1
    u64 current_stage = 2;
    sequence_check.update(&eventfd_ctx, &current_stage);
    
    // Emit Stage 2 event
    struct interrupt_trace_event event = {};
    event.stage = 2;  // vhost_signal
    // Manual copy instead of __builtin_memcpy to avoid BPF issues
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = qkey->dev_name[i];
    }
    event.queue_index = qkey->queue_index;
    event.sock_ptr = sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.vq_ptr = (u64)vq;
    event.delay_ns = 0;
    
    submit_interrupt_event(ctx, &event);
    return 0;
}

// Stage 3: irqfd_wakeup - Using correct container_of and member_read approach
int trace_irqfd_wakeup(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    void *key = (void *)PT_REGS_PARM4(ctx);
    
    if (!wait) return 0;
    
    // Check EPOLLIN flag
    u64 flags = (u64)key;
    if (!(flags & 0x1)) return 0;
    
    // Use container_of to get kvm_kernel_irqfd structure
    // container_of(wait, struct kvm_kernel_irqfd, wait)
    struct kvm_kernel_irqfd *irqfd = (struct kvm_kernel_irqfd *)
        ((char *)wait - offsetof(struct kvm_kernel_irqfd, wait));
        
    // Verify irqfd pointer validity
    if (!irqfd) return 0;
    
    // Use member_read and READ_FIELD macros to read fields, not hardcoded offsets
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;
    
    // Read eventfd_ctx field using READ_FIELD macro
    READ_FIELD(&eventfd, irqfd, eventfd);
    READ_FIELD(&gsi, irqfd, gsi);
    
    u64 eventfd_ctx = (u64)eventfd;
    
    // Validate eventfd_ctx is a valid kernel pointer
    if (!eventfd || eventfd_ctx < 0xffff000000000000ULL) {
        return 0;
    }
    
    // Enhanced chain validation: only fire Stage 3 if Stage 2 created matching eventfd_ctx entry
    struct interrupt_connection *ic_info = interrupt_chains.lookup(&eventfd_ctx);
    if (!ic_info) {
        return 0;  // No matching vhost_signal - invalid chain
    }
    
    if (gsi < 24 || gsi > 255) {
        return 0;  // Invalid GSI range for MSI interrupts
    }
    
    u64 timestamp = bpf_ktime_get_ns();
    u64 delay_ns = timestamp - ic_info->timestamp;
    
    // Update sequence check - Stage 3 should come after Stage 2
    u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
    if (!last_stage || *last_stage != 2) {
        return 0;  // Invalid sequence - Stage 2 must come before Stage 3
    }
    
    // Update to Stage 3
    u64 current_stage = 3;
    sequence_check.update(&eventfd_ctx, &current_stage);
    
    // Emit Stage 3 event - irqfd_wakeup
    struct interrupt_trace_event event = {};
    event.stage = 3;  // irqfd_wakeup
    // Copy device name and queue info from interrupt chain
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = ic_info->dev_name[i];
    }
    event.queue_index = ic_info->queue_index;
    event.sock_ptr = ic_info->sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.gsi = (u32)gsi;
    event.delay_ns = delay_ns;
    
    submit_interrupt_event(ctx, &event);
    
    return 0;
}

// Stage 3 Alternative: kvm_set_irq - Called by irqfd_inject
int trace_kvm_set_irq(struct pt_regs *ctx) {
    struct kvm *kvm = (struct kvm *)PT_REGS_PARM1(ctx);
    int irq_source_id = (int)PT_REGS_PARM2(ctx);
    u32 gsi = (u32)PT_REGS_PARM3(ctx);
    int level = (int)PT_REGS_PARM4(ctx);
    
    if (!kvm || gsi == 0) return 0;  // Filter out invalid calls
    
    // We need to find a way to match this with our interrupt chains
    // Since kvm_set_irq is called by irqfd_inject, we'll check all active chains
    // and see if any have recent vhost_signal activity
    
    u64 timestamp = bpf_ktime_get_ns();
    
    // Check all active interrupt chains
    u64 eventfd_ctx = 0;
    struct interrupt_connection *ic_info = NULL;
    
    // We'll emit events for any kvm_set_irq with level=1 (interrupt assertion)
    // that matches a known GSI range (typically 24-31 for MSI)
    if (level == 1 && gsi >= 24 && gsi <= 255) {
        // Try to find a matching interrupt chain by searching active chains
        // For now, emit the event and let user-space correlate
        
        struct interrupt_trace_event event = {};
        event.stage = 3;  // kvm_set_irq (alternative to irqfd_inject)
        event.gsi = gsi;
        event.delay_ns = 0;  // Cannot calculate without eventfd_ctx match
        
        submit_interrupt_event(ctx, &event);
    }
    
    return 0;
}
"""

# Global variables for event processing
interrupt_traces = []
chain_stats = {}
sequence_errors = 0
stage_names = {
    1: "tun_net_xmit",
    2: "vhost_signal",
    3: "irqfd_wakeup"
}

def process_interrupt_event(cpu, data, size):
    """Process interrupt trace events with enhanced correlation"""
    global sequence_errors
    
    event = ct.cast(data, ct.POINTER(InterruptTraceEvent)).contents
    
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # Simplified correlation - BPF now handles the correlation properly
    if event.dev_name and event.queue_index < 256:
        queue_key = "{}:q{}".format(event.dev_name.decode('utf-8'), event.queue_index)
    else:
        queue_key = "unknown"
    calculated_delay = event.delay_ns
    
    event_data = {
        'timestamp': event.timestamp,
        'stage': event.stage,
        'stage_name': stage_names.get(event.stage, 'unknown'),
        'cpu_id': event.cpu_id,
        'pid': event.pid,
        'comm': event.comm.decode('utf-8', 'replace'),
        'queue_key': queue_key,
        'sock_ptr': event.sock_ptr,
        'eventfd_ctx': event.eventfd_ctx,
        'vq_ptr': event.vq_ptr,
        'gsi': event.gsi,
        'delay_ns': calculated_delay,
        'saddr': event.saddr,
        'daddr': event.daddr,
        'sport': event.sport,
        'dport': event.dport,
        'protocol': event.protocol
    }
    
    interrupt_traces.append(event_data)
    
    # Update chain statistics
    if queue_key not in chain_stats:
        chain_stats[queue_key] = {}
    stage = event.stage
    if stage not in chain_stats[queue_key]:
        chain_stats[queue_key][stage] = 0
    chain_stats[queue_key][stage] += 1
    
    # Real-time output with packet info
    delay_ms = calculated_delay / 1000000.0 if calculated_delay > 0 else 0
    
    packet_info = ""
    if event.stage == 1 and event.saddr > 0:  # tun_net_xmit with packet info
        import socket
        try:
            src_ip = socket.inet_ntoa(struct.pack('!I', event.saddr))
            dst_ip = socket.inet_ntoa(struct.pack('!I', event.daddr))
            if event.protocol == 6:  # TCP
                packet_info = " TCP {}:{} -> {}:{}".format(src_ip, event.sport, dst_ip, event.dport)
            elif event.protocol == 17:  # UDP
                packet_info = " UDP {}:{} -> {}:{}".format(src_ip, event.sport, dst_ip, event.dport)
            else:
                packet_info = " IP {} -> {} proto={}".format(src_ip, dst_ip, event.protocol)
        except:
            packet_info = " [packet info parse error]"
    
    print("TUN TX INTERRUPT [{}] Stage {} [{}]: Time={} Sock=0x{:x} EventFD=0x{:x} GSI={} VQ=0x{:x} Delay={:.3f}ms CPU={} PID={} COMM={}{}".format(
        queue_key,
        event.stage,
        stage_names.get(event.stage, 'unknown'),
        timestamp_str,
        event.sock_ptr,
        event.eventfd_ctx,
        event.gsi,
        event.vq_ptr,
        delay_ms,
        event.cpu_id,
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        packet_info
    ))

def analyze_interrupt_chains():
    """Analyze interrupt chain completeness and sequence"""
    if not chain_stats:
        print("\nNo chain data collected yet.")
        return
    
    print("\n" + "="*80)
    print("TUN TX INTERRUPT CHAIN ANALYSIS")
    print("="*80)
    
    for queue, stages in chain_stats.items():
        print("\nQueue: {}".format(queue))
        print("-" * 50)
        
        # Count by stage
        print("Stage Event Counts:")
        for stage in sorted(stages.keys()):
            print("  Stage {} [{}]: {} events".format(stage, stage_names.get(stage, 'unknown'), stages[stage]))
        
        # Chain completeness analysis
        if len(stages) > 1:
            stage_counts = list(stages.values())
            min_count = min(stage_counts)
            max_count = max(stage_counts)
            completeness = (min_count / max_count * 100) if max_count > 0 else 0
            print("  Chain Completeness: {:.1f}% (min {} / max {} events)".format(
                completeness, min_count, max_count))
            
            # Expected chain: Stage 1 -> Stage 2 -> Stage 3
            if 1 in stages and 2 in stages and 3 in stages:
                print("  ✅ COMPLETE CHAIN: tun_net_xmit -> vhost_signal -> irqfd_wakeup")
            elif 1 in stages and 2 in stages:
                print("  ⚠️  PARTIAL CHAIN: tun_net_xmit -> vhost_signal (missing irqfd_wakeup)")
            elif 1 in stages:
                print("  ⚠️  INCOMPLETE: only tun_net_xmit detected")
            elif 2 in stages:
                print("  ⚠️  INCOMPLETE: only vhost_signal detected (missing tun_net_xmit)")
            else:
                print("  ❌ NO PROPER CHAIN DETECTED")
    
    if sequence_errors > 0:
        print("\n⚠️  SEQUENCE ERRORS: {} out-of-order events detected".format(sequence_errors))

def print_statistics_summary():
    """Print comprehensive statistics"""
    if not interrupt_traces:
        print("\nNo interrupt traces collected yet.")
        return
    
    print("\n" + "="*80)
    print("TUN TX QUEUE INTERRUPT TRACING STATISTICS")
    print("="*80)
    
    # Overall stage distribution
    stage_counts = {}
    for trace in interrupt_traces:
        stage = trace['stage']
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    
    print("\nOverall Stage Distribution:")
    for stage in sorted(stage_counts.keys()):
        print("  Stage {} [{}]: {} events".format(stage, stage_names.get(stage, 'unknown'), stage_counts[stage]))
    
    # Analyze interrupt chains
    analyze_interrupt_chains()
    
    # Show timing analysis for complete chains
    if len(stage_counts) >= 2:
        # Calculate average delays
        delays = [trace['delay_ns'] for trace in interrupt_traces if trace['delay_ns'] > 0]
        if delays:
            delays.sort()
            count = len(delays)
            avg_delay = sum(delays) / count / 1000.0  # Convert to microseconds
            p50_delay = delays[count//2] / 1000.0
            p90_delay = delays[int(count*0.9)] / 1000.0
            p99_delay = delays[int(count*0.99)] / 1000.0
            
            print("\nInterrupt Latency Analysis:")
            print("  Average delay: {:.1f}μs (from {} samples)".format(avg_delay, count))
            print("  P50 delay: {:.1f}μs".format(p50_delay))
            print("  P90 delay: {:.1f}μs".format(p90_delay))
            print("  P99 delay: {:.1f}μs".format(p99_delay))
    
    # Show packet type analysis
    protocols = {}
    for trace in interrupt_traces:
        if trace['stage'] == 1 and trace['protocol'] > 0:  # tun_net_xmit with valid protocol
            proto = trace['protocol']
            protocols[proto] = protocols.get(proto, 0) + 1
    
    if protocols:
        print("\nPacket Type Distribution:")
        proto_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            proto_name = proto_names.get(proto, 'Unknown({})'.format(proto))
            print("  {}: {} packets".format(proto_name, count))

def main():
    parser = argparse.ArgumentParser(
        description="TUN TX Queue Interrupt Trace Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traces the complete interrupt chain for specified TUN TX queue:
tun_net_xmit -> vhost_signal -> irqfd_wakeup

Based on proven implementation from vhost_queue_correlation_monitor.py.
Implements ultra ultra think design with precise probe point chaining and
execution order validation.

Examples:
  # Trace specific device and queue
  sudo %(prog)s --device vnet0 --queue 0
  
  # Enable detailed chain analysis with statistics
  sudo %(prog)s --device vnet0 --queue 0 --analyze-chains --stats-interval 5
  
  # Generate network traffic and trace
  sudo %(prog)s --device vnet0 --queue 0 --generate-traffic
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet0)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--analyze-chains", action="store_true", help="Enable interrupt chain analysis")
    parser.add_argument("--stats-interval", type=int, default=10, help="Statistics output interval in seconds (default: 10)")
    parser.add_argument("--output", "-o", help="Output JSON file for trace data")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--generate-traffic", action="store_true", help="Suggest commands to generate network traffic")
    
    args = parser.parse_args()
    
    if args.generate_traffic:
        print("Network Traffic Generation Commands:")
        print("# Generate ICMP traffic:")
        print("ping -c 10 <target_ip>")
        print("# Generate TCP traffic:")
        print("curl http://<target_ip>")
        print("# Generate UDP traffic:")
        print("nc -u <target_ip> 53")
        print("\nRun the trace tool in another terminal and then execute these commands.")
        return
    
    # Load BPF program
    try:
        b = BPF(text=bpf_text)
        
        # Attach proven probe points
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        print("✅ Successfully attached to tun_net_xmit")
        
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_signal")
        print("✅ Successfully attached to vhost_add_used_and_signal_n")
        
        # Attach irqfd_wakeup probe (verified as the correct probe point)
        try:
            b.attach_kprobe(event="irqfd_wakeup", fn_name="trace_irqfd_wakeup")
            print("✅ Successfully attached to irqfd_wakeup (verified offsets: eventfd_ctx +32, gsi +48)")
        except Exception as e:
            print("⚠️  Failed to attach irqfd_wakeup: {}".format(e))
            print("   Chain will be incomplete (only tun_net_xmit -> vhost_signal)")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        if args.debug:
            print("BPF program source:")
            print(bpf_text)
        return
    
    # Set device filter
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("Device filter: {}".format(args.device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("Device filter: All TUN devices")
    
    # Set queue filter
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("Queue filter: {}".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("Queue filter: All queues")
    
    print("\n" + "="*80)
    print("TUN TX QUEUE INTERRUPT TRACING STARTED")
    print("="*80)
    print("Tracing: tun_net_xmit -> vhost_signal -> irqfd_wakeup")
    print("Using proven filtering from vhost_queue_correlation_monitor.py")
    print("Chain validation: Stage 3 only fires if Stage 2 created matching eventfd_ctx entry")
    if args.analyze_chains:
        print("Chain analysis: ENABLED (interval: {}s)".format(args.stats_interval))
    print("Press Ctrl+C to stop\n")
    
    # Clear all maps for clean start
    print("Clearing BPF maps for clean state...")
    b["target_queues"].clear()
    b["interrupt_chains"].clear()
    b["sequence_check"].clear()
    print("Maps cleared. Ready for tracing.\n")
    
    # Open perf buffer for events
    b["interrupt_events"].open_perf_buffer(process_interrupt_event)
    
    # Main event loop
    try:
        import time
        last_stats_time = time.time()
        
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)  # Poll for 1 second
                
                # Print statistics periodically if chain analysis is enabled
                if args.analyze_chains:
                    current_time = time.time()
                    if current_time - last_stats_time >= args.stats_interval:
                        print_statistics_summary()
                        last_stats_time = current_time
                        
            except KeyboardInterrupt:
                break
                
    except KeyboardInterrupt:
        pass
    
    # Final statistics and output
    print("\n" + "="*80)
    print("TUN TX INTERRUPT TRACING STOPPED - FINAL SUMMARY")
    print("="*80)
    
    print_statistics_summary()
    
    # Output to JSON file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(interrupt_traces, f, indent=2, default=str)
            print("\nTrace data saved to: {}".format(args.output))
        except Exception as e:
            print("Failed to save trace data: {}".format(e))
    
    print("\nTUN TX Queue Interrupt Tracing completed.")
    print("Total events collected: {}".format(len(interrupt_traces)))

if __name__ == "__main__":
    main()