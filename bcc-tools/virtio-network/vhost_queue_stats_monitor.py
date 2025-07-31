#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
import ctypes as ct
from time import sleep, strftime

# Devname structure for device filtering
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

# BPF program for queue statistics using histograms
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

// Key structure for histograms - includes queue identification
typedef struct hist_key {
    u32 queue_index;
    char dev_name[16];
    u64 slot;
} hist_key_t;

// Use proven macros from tun_ring_monitor.py (avoiding BCC macro expansion issues)
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

// Proven TUN structures from tun_ring_monitor.py
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

// Complete vhost structures from kernel headers (drivers/vhost/vhost.h)
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
    
    // Is this vq being used by a worker?
    bool is_le;
    
    // Eventfd file descriptor
    bool log_used_valid;
    
    // Last time we wrote to used flags
    u64 log_used_offset;
    
    // Used ring length
    u16 used_idx;
    
    // Used ring shadow
    u16 shadow_used_idx;
    
    // Callback to handle notifications
    int busyloop_timeout;
    
    // Callback to handle notifications
    struct task_struct *worker;
    
    // Memory mapping
    struct mm_struct *mm;
};

// Complete vhost_net structures from kernel headers
struct vhost_net_buf {
    void **queue;
    int tail;
    int head;
};

struct vhost_net_virtqueue {
    struct vhost_virtqueue vq;
    size_t vhost_hlen;
    size_t sock_hlen;
    
    // vhost zerocopy support fields
    int upend_idx;
    int done_idx;
    struct vhost_net_ubuf_ref *ubufs;
    struct ptr_ring *rx_ring;
    struct vhost_net_buf rxq;
};

#define VHOST_NET_VQ_MAX 2

struct vhost_net {
    struct vhost_dev dev;
    struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
    struct vhost_poll poll[VHOST_NET_VQ_MAX];
    unsigned tx_packets;
    unsigned tx_zcopy_err;
    bool tx_flush;
};

// Key structure to track queue using sock pointer
struct queue_key {
    u64 sock_ptr;        // Unique sock pointer for this queue
    u32 queue_index;     // Queue index
    char dev_name[16];   // Device name
};

// Last signal state tracking structure
struct last_signal_state {
    u16 last_used_idx;      // Last seen last_used_idx value
    u32 signal_count;       // Count of signals with this value
    u64 first_timestamp;    // First occurrence timestamp
    u64 last_timestamp;     // Most recent occurrence timestamp
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);  // Track target queue sock pointers
BPF_HASH(handle_rx_vqs, u64, u64, 256);  // Track handle_rx VQ pointers for signal filtering
BPF_HASH(last_signal_states, u64, struct last_signal_state, 256);  // Track last signal state per sock
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Histograms for statistics
BPF_HISTOGRAM(vq_consumption_progress_handle_rx, hist_key_t);    // avail_idx - last_avail_idx at handle_rx
BPF_HISTOGRAM(vq_processing_delay_handle_rx, hist_key_t);       // last_avail_idx - last_used_idx at handle_rx
BPF_HISTOGRAM(vq_consumption_progress_vhost_signal, hist_key_t); // avail_idx - last_avail_idx at vhost_signal  
BPF_HISTOGRAM(vq_processing_delay_vhost_signal, hist_key_t);    // last_avail_idx - last_used_idx at vhost_signal
BPF_HISTOGRAM(vq_last_used_idx_handle_rx, hist_key_t);         // last_used_idx value distribution at handle_rx
BPF_HISTOGRAM(vq_last_used_idx_vhost_signal, hist_key_t);      // last_used_idx value distribution at vhost_signal
BPF_HISTOGRAM(duplicate_signal_count, hist_key_t);             // Count of duplicate signals with same last_used_idx
BPF_HISTOGRAM(ptr_ring_depth_xmit, hist_key_t);       // PTR ring depth at tun_net_xmit
BPF_HISTOGRAM(ptr_ring_depth_recv, hist_key_t);       // PTR ring depth at tun_recvmsg

// Device filter logic - fixed to use bpf_probe_read_kernel like iface_netstat.c
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname = {};  // Initialize to zero
    bpf_probe_read_kernel(&real_devname, IFNAMSIZ, dev->name);  // Read full 16 bytes

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

// Check if this sock pointer belongs to our target queue
static inline int is_target_queue_sock(u64 sock_ptr) {
    struct queue_key *key = target_queues.lookup(&sock_ptr);
    return key ? 1 : 0;
}

// Extract ptr_ring state using proven member_read approach from tun_ring_monitor.py
static inline u32 get_ptr_ring_depth(struct tun_file *tfile) {
    if (!tfile) return 0;
    
    struct ptr_ring *tx_ring = &tfile->tx_ring;
    
    u32 producer, consumer_head, consumer_tail, size;
    
    member_read(&producer, tx_ring, producer);
    member_read(&consumer_head, tx_ring, consumer_head);
    member_read(&consumer_tail, tx_ring, consumer_tail);
    member_read(&size, tx_ring, size);
    
    if (size == 0) return 0;
    
    // Calculate ring utilization
    u32 used;
    if (producer >= consumer_tail) {
        used = producer - consumer_tail;
    } else {
        used = size - consumer_tail + producer;
    }
    
    return used;
}

// Stage 1: tun_net_xmit - Track PTR ring depth
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    // Get queue index from skb
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    
    // Get TUN structure using proven approach from tun_ring_monitor.py
    u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    struct tun_struct *tun = (struct tun_struct *)((char *)dev + aligned_size);
    
    u32 tun_numqueues = 0;
    READ_FIELD(&tun_numqueues, tun, numqueues);
    
    if (queue_index >= tun_numqueues || queue_index >= 256) {
        return 0;
    }
    
    // Get tfile for this queue
    struct tun_file *tfile = NULL;
    if (queue_index < tun_numqueues && tun_numqueues > 0 && queue_index < 256) {
        // Access tun->tfiles[queue_index] - tfiles array starts at offset 0 of tun_struct
        void **tfile_ptr_addr = (void**)((char*)tun + offsetof(struct tun_struct, tfiles) + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }
    
    // Get socket pointer from tfile
    u64 sock_ptr = (u64)&tfile->socket;
    
    // Track this queue's sock pointer
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    target_queues.update(&sock_ptr, &qkey);
    
    // Get PTR ring depth and record in histogram
    u32 depth = get_ptr_ring_depth(tfile);
    hist_key_t hist_key = {};
    hist_key.queue_index = queue_index;
    bpf_probe_read_kernel_str(hist_key.dev_name, sizeof(hist_key.dev_name), dev->name);
    
    // Handle depth=0 case properly - bpf_log2l(0) returns a large value
    if (depth == 0) {
        hist_key.slot = 0;  // Put 0 in slot 0
    } else {
        hist_key.slot = bpf_log2l(depth);  // Use log2 scale for histogram
    }
    
    ptr_ring_depth_xmit.atomic_increment(hist_key);
    
    return 0;
}

// Stage 2: handle_rx - Track VQ state
int trace_handle_rx(struct pt_regs *ctx) {
    struct vhost_net *net = (struct vhost_net *)PT_REGS_PARM1(ctx);
    if (!net) return 0;
    
    // Get RX virtqueue (vqs[0].vq) using member_read
    struct vhost_net_virtqueue *nvq = &net->vqs[0];
    struct vhost_virtqueue *vq = &nvq->vq;
    
    // Get sock pointer from private_data using READ_FIELD  
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Track this VQ for signal filtering
    u64 vq_addr = (u64)vq;
    handle_rx_vqs.update(&sock_ptr, &vq_addr);
    
    // Get VQ indices
    u16 last_avail_idx, avail_idx, last_used_idx;
    READ_FIELD(&last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&avail_idx, vq, avail_idx);
    READ_FIELD(&last_used_idx, vq, last_used_idx);
    
    // Calculate consumption progress (how much is available to consume)
    u16 consumption_progress = 0;
    if (avail_idx >= last_avail_idx) {
        consumption_progress = avail_idx - last_avail_idx;
    } else {
        // Handle wraparound - assuming 16-bit indices
        consumption_progress = (u16)(65536 + avail_idx - last_avail_idx);
    }
    
    // Calculate processing delay (how much is in-flight)
    u16 processing_delay = 0;
    if (last_avail_idx >= last_used_idx) {
        processing_delay = last_avail_idx - last_used_idx;
    } else {
        // Handle wraparound
        processing_delay = (u16)(65536 + last_avail_idx - last_used_idx);
    }
    
    // Record in histograms for handle_rx
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // VQ consumption progress histogram at handle_rx
    hist_key.slot = bpf_log2l(consumption_progress);
    vq_consumption_progress_handle_rx.atomic_increment(hist_key);
    
    // VQ processing delay histogram at handle_rx
    hist_key.slot = bpf_log2l(processing_delay);
    vq_processing_delay_handle_rx.atomic_increment(hist_key);
    
    // VQ last_used_idx value histogram at handle_rx
    // Use original u16 value (0-65535) as slot to track exact index values
    hist_key.slot = last_used_idx;  // Use original u16 value
    vq_last_used_idx_handle_rx.atomic_increment(hist_key);
    
    return 0;
}

// Stage 3: tun_recvmsg - Track PTR ring depth
int trace_tun_recvmsg_entry(struct pt_regs *ctx, struct socket *sock, struct msghdr *m, size_t total_len, int flags) {
    if (!sock) return 0;
    
    // Get tun_file from socket using proper calculation
    struct tun_file *tfile = (struct tun_file *)((char *)sock - offsetof(struct tun_file, socket));
    if (!tfile) return 0;
    
    // Get socket pointer directly from parameter
    u64 sock_ptr = (u64)sock;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Get PTR ring depth and record in histogram
    u32 depth = get_ptr_ring_depth(tfile);
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // Handle depth=0 case properly - bpf_log2l(0) returns a large value
    if (depth == 0) {
        hist_key.slot = 0;  // Put 0 in slot 0
    } else {
        hist_key.slot = bpf_log2l(depth);  // Use log2 scale for histogram
    }
    
    ptr_ring_depth_recv.atomic_increment(hist_key);
    
    return 0;
}

// Stage 4: vhost_signal - Track VQ state at signal time
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer from private_data using READ_FIELD  
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Filter VQ: only allow signals from handle_rx VQs
    u64 expected_vq_addr = 0;
    u64 *expected_vq_ptr = handle_rx_vqs.lookup(&sock_ptr);
    if (expected_vq_ptr) {
        expected_vq_addr = *expected_vq_ptr;
    }
    
    u64 current_vq_addr = (u64)vq;
    if (expected_vq_addr != 0 && current_vq_addr != expected_vq_addr) {
        return 0;  // Filter out signals from different VQ (likely TX direction)
    }
    
    // Get VQ indices for additional statistics
    u16 last_avail_idx, avail_idx, last_used_idx;
    READ_FIELD(&last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&avail_idx, vq, avail_idx);
    READ_FIELD(&last_used_idx, vq, last_used_idx);
    
    // Calculate consumption progress and processing delay at signal time
    u16 consumption_progress = 0;
    if (avail_idx >= last_avail_idx) {
        consumption_progress = avail_idx - last_avail_idx;
    } else {
        // Handle wraparound
        consumption_progress = (u16)(65536 + avail_idx - last_avail_idx);
    }
    
    u16 processing_delay = 0;
    if (last_avail_idx >= last_used_idx) {
        processing_delay = last_avail_idx - last_used_idx;
    } else {
        // Handle wraparound
        processing_delay = (u16)(65536 + last_avail_idx - last_used_idx);
    }
    
    // Record in histograms for vhost_signal
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // VQ consumption progress histogram at vhost_signal
    hist_key.slot = bpf_log2l(consumption_progress);
    vq_consumption_progress_vhost_signal.atomic_increment(hist_key);
    
    // VQ processing delay histogram at vhost_signal
    hist_key.slot = bpf_log2l(processing_delay);
    vq_processing_delay_vhost_signal.atomic_increment(hist_key);
    
    // VQ last_used_idx value histogram at vhost_signal
    // Use original u16 value (0-65535) as slot to track exact index values
    hist_key.slot = last_used_idx;  // Use original u16 value
    vq_last_used_idx_vhost_signal.atomic_increment(hist_key);
    
    // Track duplicate signals with same last_used_idx
    u64 current_time = bpf_ktime_get_ns();
    struct last_signal_state *prev_state = last_signal_states.lookup(&sock_ptr);
    struct last_signal_state new_state = {};
    
    if (prev_state) {
        if (prev_state->last_used_idx == last_used_idx) {
            // Same last_used_idx as previous signal - this is a duplicate
            new_state.last_used_idx = last_used_idx;
            new_state.signal_count = prev_state->signal_count + 1;
            new_state.first_timestamp = prev_state->first_timestamp;
            new_state.last_timestamp = current_time;
            
            // Record duplicate signal count in histogram
            hist_key_t dup_hist_key = {};
            dup_hist_key.queue_index = qkey->queue_index;
            __builtin_memcpy(dup_hist_key.dev_name, qkey->dev_name, sizeof(dup_hist_key.dev_name));
            dup_hist_key.slot = new_state.signal_count;  // Use signal count as slot
            duplicate_signal_count.atomic_increment(dup_hist_key);
        } else {
            // Different last_used_idx - start new tracking
            new_state.last_used_idx = last_used_idx;
            new_state.signal_count = 1;
            new_state.first_timestamp = current_time;
            new_state.last_timestamp = current_time;
        }
    } else {
        // First signal for this queue
        new_state.last_used_idx = last_used_idx;
        new_state.signal_count = 1;
        new_state.first_timestamp = current_time;
        new_state.last_timestamp = current_time;
    }
    
    last_signal_states.update(&sock_ptr, &new_state);
    
    return 0;
}
"""

def print_index_histogram(hist_table):
    """Print histogram for u16 index values (0-65535)"""
    if len(hist_table) == 0:
        print("    No data")
        return
    
    # Group by queue and device
    queue_data = {}
    for k, v in hist_table.items():
        dev_name = k.dev_name.decode('utf-8', 'replace')
        queue_index = k.queue_index
        queue_key = "{}:q{}".format(dev_name, queue_index)
        if queue_key not in queue_data:
            queue_data[queue_key] = {}
        slot = k.slot  # This is now the original u16 value (0-65535)
        queue_data[queue_key][slot] = v.value
    
    for queue_name in sorted(queue_data.keys()):
        print("  Queue: {}".format(queue_name))
        slots = queue_data[queue_name]
        if not slots:
            print("    No data")
            continue
            
        total_count = sum(slots.values())
        print("    Total: {} events".format(total_count))
        
        # Find min and max slot values (original u16 values)
        min_slot = min(slots.keys())
        max_slot = max(slots.keys())
        
        # Show distribution range for u16 values (0-65535)
        print("    Index value distribution (u16 range 0-65535):")
        print("    Min: {}, Max: {}, Range: {}".format(min_slot, max_slot, max_slot - min_slot))
        
        # Count how many index values appeared more than once (duplicates)
        duplicate_count = sum(1 for count in slots.values() if count > 1)
        unique_count = len(slots)
        print("    Unique indices: {}, Duplicate indices: {} ({:.1f}%)".format(
            unique_count, duplicate_count, 
            (duplicate_count * 100.0 / unique_count) if unique_count > 0 else 0))
        
        # Only show top list if there are duplicate indices
        if duplicate_count > 0:
            # Show top 20 most frequent values (focus on duplicates)
            sorted_slots = sorted(slots.items(), key=lambda x: x[1], reverse=True)[:20]
            print("    Top 20 most frequent index values:")
            for slot, count in sorted_slots:
                pct = (count * 100.0 / total_count) if total_count > 0 else 0
                status = "DUPLICATE" if count > 1 else "normal"
                print("      idx {:>5}: {:>3} times ({:>5.1f}%) [{}]".format(slot, count, pct, status))

def print_histogram(hist_table, unit):
    """Print histogram with queue information"""
    if len(hist_table) == 0:
        print("    No data")
        return
    
    # Group by queue and device - kernel filtering already applied
    queue_data = {}
    for k, v in hist_table.items():
        dev_name = k.dev_name.decode('utf-8', 'replace')
        queue_index = k.queue_index
        queue_key = "{}:q{}".format(dev_name, queue_index)
        if queue_key not in queue_data:
            queue_data[queue_key] = {}
        slot = k.slot
        queue_data[queue_key][slot] = v.value
    
    for queue_name in sorted(queue_data.keys()):
        print("  Queue: {}".format(queue_name))
        slots = queue_data[queue_name]
        if not slots:
            print("    No data")
            continue
            
        max_slot = max(slots.keys())
        total_count = sum(slots.values())
        
        print("    Total: {}".format(total_count))
        
        for slot in range(max_slot + 1):
            count = slots.get(slot, 0)
            if count > 0:
                low = 1 << slot
                high = (1 << (slot + 1)) - 1
                if slot == 0:
                    range_str = "0-1"
                else:
                    range_str = "{}-{}".format(low, high)
                
                pct = (count * 100) // total_count if total_count > 0 else 0
                print("    {:>10} : {:>8} ({}%)".format(range_str, count, pct))

def main():
    parser = argparse.ArgumentParser(
        description="VHOST-NET Queue Statistics Monitor with periodic distribution output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues with 1-second interval
  sudo %(prog)s
  
  # Monitor specific device with 5-second interval
  sudo %(prog)s --device vnet33 --interval 5
  
  # Monitor specific device and queue with 10 outputs
  sudo %(prog)s --device vnet33 --queue 0 --interval 1 10
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet33)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--interval", "-i", type=int, default=1, help="Output interval in seconds (default: 1)")
    parser.add_argument("outputs", nargs="?", type=int, default=99999999, help="Number of outputs (default: unlimited)")
    parser.add_argument("--timestamp", "-T", action="store_true", help="Include timestamp on output")
    
    args = parser.parse_args()
    countdown = args.outputs
    
    # Load BPF program
    try:
        b = BPF(text=bpf_text)
        
        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        b.attach_kprobe(event="handle_rx", fn_name="trace_handle_rx")
        b.attach_kprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_entry")
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_signal")
        
    except Exception as e:
        print("Failed to load BPF program: {}".format(e))
        return
    
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
    
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("Queue filter: {}".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("Queue filter: All queues")
    
    print("VHOST-NET Queue Statistics Monitor Started")
    print("Interval: {}s | Outputs: {}".format(args.interval, "unlimited" if args.outputs == 99999999 else args.outputs))
    print("Collecting statistics... Press Ctrl+C to stop\n")
    
    # Clear maps to avoid stale entries - CRITICAL for correct filtering
    target_queues_map = b["target_queues"]
    handle_rx_vqs_map = b["handle_rx_vqs"]
    last_signal_states_map = b["last_signal_states"]
    
    print("Clearing all maps to ensure clean state...")
    target_queues_map.clear()
    handle_rx_vqs_map.clear()
    last_signal_states_map.clear()
    
    # Also clear histogram maps to ensure clean start
    vq_consumption_handle_rx = b.get_table("vq_consumption_progress_handle_rx")
    vq_delay_handle_rx = b.get_table("vq_processing_delay_handle_rx")
    vq_consumption_vhost_signal = b.get_table("vq_consumption_progress_vhost_signal")
    vq_delay_vhost_signal = b.get_table("vq_processing_delay_vhost_signal")
    vq_last_used_idx_handle_rx = b.get_table("vq_last_used_idx_handle_rx")
    vq_last_used_idx_vhost_signal = b.get_table("vq_last_used_idx_vhost_signal")
    duplicate_signal_count = b.get_table("duplicate_signal_count")
    ptr_xmit = b.get_table("ptr_ring_depth_xmit")
    ptr_recv = b.get_table("ptr_ring_depth_recv")
    
    vq_consumption_handle_rx.clear()
    vq_delay_handle_rx.clear()
    vq_consumption_vhost_signal.clear()
    vq_delay_vhost_signal.clear()
    vq_last_used_idx_handle_rx.clear()
    vq_last_used_idx_vhost_signal.clear()
    duplicate_signal_count.clear()
    ptr_xmit.clear()
    ptr_recv.clear()
    
    print("All maps cleared.")
    
# Maps already obtained above
    
    exiting = 0
    try:
        while countdown > 0:
            try:
                sleep(args.interval)
            except KeyboardInterrupt:
                exiting = 1
            
            print("\n" + "="*80)
            if args.timestamp:
                import datetime
                now = datetime.datetime.now()
                print("Time: {}".format(now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]))
            
            # Print VQ Consumption Progress Distribution from handle_rx
            print("\nVQ Consumption Progress Distribution at handle_rx (avail_idx - last_avail_idx):")
            print("Shows how many descriptors are available for consumption when VHOST handles RX")
            print_histogram(vq_consumption_handle_rx, "descriptors")
            
            # Print VQ Processing Delay Distribution from handle_rx
            print("\nVQ Processing Delay Distribution at handle_rx (last_avail_idx - last_used_idx):")
            print("Shows how many descriptors are in-flight when VHOST handles RX")
            print_histogram(vq_delay_handle_rx, "descriptors")
            
            # Print VQ Consumption Progress Distribution from vhost_signal
            print("\nVQ Consumption Progress Distribution at vhost_signal (avail_idx - last_avail_idx):")
            print("Shows how many descriptors are available for consumption when VHOST signals guest")
            print_histogram(vq_consumption_vhost_signal, "descriptors")
            
            # Print VQ Processing Delay Distribution from vhost_signal
            print("\nVQ Processing Delay Distribution at vhost_signal (last_avail_idx - last_used_idx):")
            print("Shows how many descriptors are in-flight when VHOST signals guest")
            print_histogram(vq_delay_vhost_signal, "descriptors")
            
            # Print VQ last_used_idx Value Distribution from handle_rx
            print("\nVQ last_used_idx Value Distribution at handle_rx:")
            print("Shows last_used_idx values (u16: 0-65535) and their occurrence frequency when VHOST handles RX")
            print_index_histogram(vq_last_used_idx_handle_rx)
            
            # Print VQ last_used_idx Value Distribution from vhost_signal
            print("\nVQ last_used_idx Value Distribution at vhost_signal:")
            print("Shows last_used_idx values (u16: 0-65535) and their occurrence frequency when VHOST signals guest")
            print_index_histogram(vq_last_used_idx_vhost_signal)
            
            # Print Duplicate Signal Count Distribution
            print("\nDuplicate Signal Count Distribution at vhost_signal:")
            print("Shows how many times the same last_used_idx triggered multiple signals (ring not advancing)")
            print_histogram(duplicate_signal_count, "signals")
            
            # Print PTR Ring Depth at tun_net_xmit
            print("\nPTR Ring Depth Distribution at tun_net_xmit:")
            print("Shows ring buffer utilization when packets are transmitted")
            print_histogram(ptr_xmit, "entries")
            
            # Print PTR Ring Depth at tun_recvmsg
            print("\nPTR Ring Depth Distribution at tun_recvmsg:")
            print("Shows ring buffer utilization when packets are received")
            print_histogram(ptr_recv, "entries")
            
            # Clear histograms for next interval
            vq_consumption_handle_rx.clear()
            vq_delay_handle_rx.clear()
            vq_consumption_vhost_signal.clear()
            vq_delay_vhost_signal.clear()
            vq_last_used_idx_handle_rx.clear()
            vq_last_used_idx_vhost_signal.clear()
            duplicate_signal_count.clear()
            ptr_xmit.clear()
            ptr_recv.clear()
            
            countdown -= 1
            if exiting:
                break
                
    except KeyboardInterrupt:
        pass
    
    print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()