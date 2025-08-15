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
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
import ctypes as ct

# Devname structure for device filtering
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

# BPF program for simple queue monitoring
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
#include <linux/virtio_ring.h>

#define NETDEV_ALIGN 32
#define MAX_QUEUES 256
#define IFNAMSIZ 16
#define VIRTIO_RING_F_EVENT_IDX 29

// Device name union for efficient comparison
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Use proven macros from tun_ring_monitor.py (avoiding BCC macro expansion issues)
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
// Need complete definition for correct field offsets

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

// Key structure to track queue
struct queue_key {
    u64 sock_ptr;
    u32 queue_index;
    char dev_name[16];
};

// Event data structure
struct queue_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    u64 sock_ptr;
    u32 queue_index;
    char dev_name[16];
    
    u8 event_type;  // 1=vhost_signal, 2=vhost_notify
    
    // VQ state
    u64 vq_ptr;
    u16 last_avail_idx;
    u16 avail_idx;
    u16 last_used_idx;
    u16 used_flags;
    u16 signalled_used;
    bool signalled_used_valid;
    bool log_used;
    u64 log_addr;
    u64 acked_features;
    u64 acked_backend_features;
    
    // vhost_notify specific
    int ret_val;
    bool has_event_idx_feature;
    u16 avail_flags;
    u16 used_event_idx;
    bool guest_flags_valid;
    bool guest_event_valid;
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);
BPF_HASH(vhost_notify_params, u64, struct vhost_virtqueue*, 256);

// Device filter logic
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname = {};
    bpf_probe_read_kernel(&real_devname, IFNAMSIZ, dev->name);

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 1;
    }
    if(leaf->name_int.hi == 0 && leaf->name_int.lo == 0){
        return 1;
    }
    if(leaf->name_int.hi != real_devname.name_int.hi || leaf->name_int.lo != real_devname.name_int.lo){
        return 0;
    }
    return 1;
}

// Get vhost_virtqueue state
static inline void get_vhost_vq_state(struct vhost_virtqueue *vq, struct queue_event *event) {
    if (!vq) return;
    
    READ_FIELD(&event->last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&event->avail_idx, vq, avail_idx);
    READ_FIELD(&event->last_used_idx, vq, last_used_idx);
    READ_FIELD(&event->used_flags, vq, used_flags);
    READ_FIELD(&event->signalled_used, vq, signalled_used);
    READ_FIELD(&event->signalled_used_valid, vq, signalled_used_valid);
    READ_FIELD(&event->log_used, vq, log_used);
    READ_FIELD(&event->log_addr, vq, log_addr);
    READ_FIELD(&event->acked_features, vq, acked_features);
    READ_FIELD(&event->acked_backend_features, vq, acked_backend_features);
}

// Stage 1: tun_net_xmit - Only track queue, no output
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;
        }
    }
    
    // Get TUN structure
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
        void **tfile_ptr_addr = (void**)((char*)tun + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }
    
    // Get socket pointer
    u64 sock_ptr = (u64)&tfile->socket;
    
    // Track this queue's sock pointer
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    target_queues.update(&sock_ptr, &qkey);
    
    // No output for tun_net_xmit
    return 0;
}

// Stage 2: vhost_signal
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1;  // vhost_signal
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    
    // Get vhost virtqueue state
    get_vhost_vq_state(vq, &event);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 3: vhost_notify entry
int trace_vhost_notify_entry(struct pt_regs *ctx) {
    struct vhost_dev *dev = (struct vhost_dev *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }
    
    // Store vq pointer for return probe
    u64 tid = bpf_get_current_pid_tgid();
    vhost_notify_params.update(&tid, &vq);
    
    return 0;
}

// Stage 4: vhost_notify return
int trace_vhost_notify_return(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    
    // Get vq from entry probe
    struct vhost_virtqueue **vq_ptr = vhost_notify_params.lookup(&tid);
    if (!vq_ptr || !*vq_ptr) {
        return 0;
    }
    
    struct vhost_virtqueue *vq = *vq_ptr;
    vhost_notify_params.delete(&tid);
    
    // Get sock pointer
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = tid >> 32;
    event.tid = tid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 2;  // vhost_notify
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    
    // Get return value
    event.ret_val = PT_REGS_RC(ctx);
    
    // Get vhost virtqueue state
    get_vhost_vq_state(vq, &event);
    
    // Check if VIRTIO_RING_F_EVENT_IDX is supported
    u64 acked_features = 0;
    READ_FIELD(&acked_features, vq, acked_features);
    event.has_event_idx_feature = (acked_features & (1ULL << VIRTIO_RING_F_EVENT_IDX)) != 0;
    
    // Try to read avail flags from guest memory
    struct vring_avail *avail = NULL;
    READ_FIELD(&avail, vq, avail);
    if (avail) {
        __virtio16 flags = 0;
        if (bpf_probe_read_user(&flags, sizeof(flags), &avail->flags) == 0) {
            event.avail_flags = flags;
            event.guest_flags_valid = true;
        }
    }
    
    // If EVENT_IDX is enabled, try to read used_event_idx
    if (event.has_event_idx_feature) {
        unsigned int num = 0;
        READ_FIELD(&num, vq, num);
        
        if (avail && num > 0) {
            __virtio16 *used_event_ptr = (__virtio16 *)((char *)avail + 
                                          offsetof(struct vring_avail, ring) + 
                                          num * sizeof(__virtio16));
            __virtio16 used_event = 0;
            if (bpf_probe_read_user(&used_event, sizeof(used_event), used_event_ptr) == 0) {
                event.used_event_idx = used_event;
                event.guest_event_valid = true;
            }
        }
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class QueueKey(ct.Structure):
    _fields_ = [
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
    ]

class QueueEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("vq_ptr", ct.c_uint64),
        # VQ state
        ("last_avail_idx", ct.c_uint16),
        ("avail_idx", ct.c_uint16),
        ("last_used_idx", ct.c_uint16),
        ("used_flags", ct.c_uint16),
        ("signalled_used", ct.c_uint16),
        ("signalled_used_valid", ct.c_bool),
        ("log_used", ct.c_bool),
        ("log_addr", ct.c_uint64),
        ("acked_features", ct.c_uint64),
        ("acked_backend_features", ct.c_uint64),
        # vhost_notify specific
        ("ret_val", ct.c_int),
        ("has_event_idx_feature", ct.c_bool),
        ("avail_flags", ct.c_uint16),
        ("used_event_idx", ct.c_uint16),
        ("guest_flags_valid", ct.c_bool),
        ("guest_event_valid", ct.c_bool),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(QueueEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    event_names = {
        1: "vhost_signal",
        2: "vhost_notify"
    }
    
    print("="*80)
    print("Event: {} | Time: {} | Timestamp: {}ns".format(
        event_names.get(event.event_type, "unknown"), timestamp_str, event.timestamp))
    print("Queue: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    print("Sock: 0x{:x}".format(event.sock_ptr))
    
    if event.event_type == 1:  # vhost_signal
        print("VQ: 0x{:x}".format(event.vq_ptr))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Signal: signalled_used={}, valid={}, log_used={}".format(
            event.signalled_used, "YES" if event.signalled_used_valid else "NO", 
            "YES" if event.log_used else "NO"))
        print("Features: acked=0x{:x}, backend=0x{:x}".format(
            event.acked_features, event.acked_backend_features))
        if event.log_used and event.log_addr:
            print("Log: addr=0x{:x}".format(event.log_addr))
    elif event.event_type == 2:  # vhost_notify
        print("VQ: 0x{:x} | Return: {} (notify={})".format(
            event.vq_ptr, event.ret_val, "YES" if event.ret_val else "NO"))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Features: acked=0x{:x}, backend=0x{:x}, EVENT_IDX={}".format(
            event.acked_features, event.acked_backend_features,
            "ENABLED" if event.has_event_idx_feature else "DISABLED"))
        # Guest memory fields
        if event.guest_flags_valid:
            no_interrupt = (event.avail_flags & 0x1) != 0
            print("Guest avail_flags: 0x{:x} (NO_INTERRUPT={})".format(
                event.avail_flags, "YES" if no_interrupt else "NO"))
        else:
            print("Guest avail_flags: <failed to read>")
        
        if event.has_event_idx_feature and event.guest_event_valid:
            print("Guest used_event_idx: {} (host last_used={})".format(
                event.used_event_idx, event.last_used_idx))
        elif event.has_event_idx_feature:
            print("Guest used_event_idx: <failed to read>")
    
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Simple VHOST Queue Monitor (vhost_signal & vhost_notify)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues on all TUN devices
  sudo %(prog)s
  
  # Monitor specific device and queue
  sudo %(prog)s --device vnet33 --queue 0
  
  # Monitor specific device with verbose output  
  sudo %(prog)s --device vnet33 --verbose
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet33)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        b.attach_kprobe(event="vhost_signal", fn_name="trace_vhost_signal")
        
        # Try to attach vhost_notify - it might be inlined with .isra suffix
        vhost_notify_attached = False
        try:
            b.attach_kprobe(event="vhost_notify", fn_name="trace_vhost_notify_entry")
            b.attach_kretprobe(event="vhost_notify", fn_name="trace_vhost_notify_return")
            vhost_notify_attached = True
            if args.verbose:
                print("Attached to vhost_notify")
        except:
            # Try with .isra suffix
            for suffix in [".isra.24", ".isra.23", ".isra.25", ".isra.26", ".isra.27", ".isra.28"]:
                try:
                    event_name = "vhost_notify" + suffix
                    b.attach_kprobe(event=event_name, fn_name="trace_vhost_notify_entry")
                    b.attach_kretprobe(event=event_name, fn_name="trace_vhost_notify_return")
                    vhost_notify_attached = True
                    if args.verbose:
                        print("Attached to {}".format(event_name))
                    break
                except:
                    continue
        
        if not vhost_notify_attached:
            print("Warning: Could not attach to vhost_notify (function may be inlined differently)")
            print("Continuing without vhost_notify monitoring...")
        
        if args.verbose:
            print("All probes attached successfully")
        
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
    
    print("Simple VHOST Queue Monitor Started")
    print("Monitoring: vhost_signal & vhost_notify events")
    print("Clearing maps to avoid stale entries")
    
    # Clear maps
    target_queues_map = b["target_queues"]
    target_queues_map.clear()
    
    if "vhost_notify_params" in b:
        vhost_notify_params_map = b["vhost_notify_params"]
        vhost_notify_params_map.clear()
    
    print("Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()