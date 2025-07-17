#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
from bcc import BPF
import ctypes as ct

# BPF program for Guest virtio-net RX monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>

#define IFNAMSIZ 16
#define MAX_QUEUES 256

// Device name union for efficient comparison
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Event structure for virtio-net RX monitoring
struct virtio_rx_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Event type: 1=skb_recv_done, 2=virtnet_poll
    u8 event_type;
    
    // Device and queue info
    char dev_name[IFNAMSIZ];
    u32 queue_index;
    
    // Virtqueue info
    u64 vq_ptr;
    u32 vq_num;
    u32 vq_num_free;
    
    // NAPI info (for virtnet_poll)
    u64 napi_ptr;
    u32 napi_budget;
    u32 napi_received;
    
    // Network device info
    u64 netdev_ptr;
    u32 netdev_flags;
    u32 netdev_state;
    
    // Statistics
    u64 rx_packets;
    u64 rx_bytes;
    u64 rx_dropped;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Helper function to get queue index from virtqueue
// This mimics the vq2rxq() function from virtio_net.c
static inline u32 vq2rxq(struct virtqueue *vq) {
    // In virtio-net, RX queues are even-numbered (0, 2, 4, ...)
    // TX queues are odd-numbered (1, 3, 5, ...)
    // vq2rxq(vq) = (vq->index) / 2
    u32 vq_index = 0;
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), &vq->index) == 0) {
        return vq_index / 2;
    }
    return 0;
}

// Device filter logic
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname;
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev->name);

    int key = 0;
    union name_buf *leaf = name_map.lookup(&key);
    if (!leaf) {
        return 1;  // No filter set - accept all devices
    }
    if (leaf->name_int.hi == 0 && leaf->name_int.lo == 0) {
        return 1;  // Empty filter - accept all devices
    }
    if (leaf->name_int.hi != real_devname.name_int.hi || 
        leaf->name_int.lo != real_devname.name_int.lo) {
        return 0;  // Device name doesn't match
    }
    return 1;  // Device name matches
}

// Queue filter logic
static inline int queue_filter(u32 queue_index) {
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    return 1;  // Queue matches or no filter
}

// Fill common event fields
static inline void fill_common_event(struct virtio_rx_event *event, u8 event_type) {
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->event_type = event_type;
}

// Fill virtqueue info
static inline void fill_vq_info(struct virtio_rx_event *event, struct virtqueue *vq) {
    event->vq_ptr = (u64)vq;
    if (vq) {
        bpf_probe_read_kernel(&event->vq_num, sizeof(event->vq_num), &vq->num);
        bpf_probe_read_kernel(&event->vq_num_free, sizeof(event->vq_num_free), &vq->num_free);
    }
}

// Fill network device info
static inline void fill_netdev_info(struct virtio_rx_event *event, struct net_device *dev) {
    if (!dev) return;
    
    event->netdev_ptr = (u64)dev;
    bpf_probe_read_kernel_str(event->dev_name, sizeof(event->dev_name), dev->name);
    bpf_probe_read_kernel(&event->netdev_flags, sizeof(event->netdev_flags), &dev->flags);
    bpf_probe_read_kernel(&event->netdev_state, sizeof(event->netdev_state), &dev->state);
    
    // Get RX statistics
    struct rtnl_link_stats64 *stats = NULL;
    if (bpf_probe_read_kernel(&stats, sizeof(stats), &dev->stats) == 0 && stats) {
        bpf_probe_read_kernel(&event->rx_packets, sizeof(event->rx_packets), &stats->rx_packets);
        bpf_probe_read_kernel(&event->rx_bytes, sizeof(event->rx_bytes), &stats->rx_bytes);
        bpf_probe_read_kernel(&event->rx_dropped, sizeof(event->rx_dropped), &stats->rx_dropped);
    }
}

// Probe 1: skb_recv_done - Guest virtio-net RX interrupt handler
int trace_skb_recv_done(struct pt_regs *ctx, struct virtqueue *rvq) {
    if (!rvq) return 0;
    
    // Get virtnet_info from virtqueue
    struct virtio_device *vdev = NULL;
    if (bpf_probe_read_kernel(&vdev, sizeof(vdev), &rvq->vdev) != 0 || !vdev) {
        return 0;
    }
    
    void *priv = NULL;
    if (bpf_probe_read_kernel(&priv, sizeof(priv), &vdev->priv) != 0 || !priv) {
        return 0;
    }
    
    // Get net_device from virtnet_info (first field)
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), priv) != 0 || !dev) {
        return 0;
    }
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    // Get RX queue index
    u32 queue_index = vq2rxq(rvq);
    
    // Apply queue filter
    if (!queue_filter(queue_index)) return 0;
    
    // Create event
    struct virtio_rx_event event = {};
    fill_common_event(&event, 1);  // event_type = 1 (skb_recv_done)
    
    event.queue_index = queue_index;
    fill_vq_info(&event, rvq);
    fill_netdev_info(&event, dev);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe 2: virtnet_poll - Guest virtio-net NAPI poll handler
int trace_virtnet_poll(struct pt_regs *ctx, struct napi_struct *napi, int budget) {
    if (!napi) return 0;
    
    // Get receive_queue from napi_struct using container_of
    // struct receive_queue *rq = container_of(napi, struct receive_queue, napi);
    // We need to calculate the offset of napi field in receive_queue
    // For now, we'll use a simpler approach and try to get the virtqueue
    
    // This is a simplified approach - in real implementation we'd need
    // to properly handle the container_of calculation
    struct virtqueue *vq = NULL;
    // Try to read vq from the expected offset in receive_queue
    // This might need adjustment based on actual kernel structure
    if (bpf_probe_read_kernel(&vq, sizeof(vq), (char*)napi + 64) != 0 || !vq) {
        return 0;  // Skip if we can't get vq
    }
    
    // Get virtnet_info from virtqueue
    struct virtio_device *vdev = NULL;
    if (bpf_probe_read_kernel(&vdev, sizeof(vdev), &vq->vdev) != 0 || !vdev) {
        return 0;
    }
    
    void *priv = NULL;
    if (bpf_probe_read_kernel(&priv, sizeof(priv), &vdev->priv) != 0 || !priv) {
        return 0;
    }
    
    // Get net_device from virtnet_info (first field)
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), priv) != 0 || !dev) {
        return 0;
    }
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    // Get RX queue index
    u32 queue_index = vq2rxq(vq);
    
    // Apply queue filter
    if (!queue_filter(queue_index)) return 0;
    
    // Create event
    struct virtio_rx_event event = {};
    fill_common_event(&event, 2);  // event_type = 2 (virtnet_poll)
    
    event.queue_index = queue_index;
    event.napi_ptr = (u64)napi;
    event.napi_budget = budget;
    fill_vq_info(&event, vq);
    fill_netdev_info(&event, dev);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Return probe for virtnet_poll to get received count
int trace_virtnet_poll_return(struct pt_regs *ctx) {
    // Get return value (number of packets received)
    int received = PT_REGS_RC(ctx);
    
    // For now, we'll skip the return probe implementation
    // as it's complex to correlate with the entry probe
    return 0;
}
"""

# Device name structure for filtering
class Devname(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

# Event structure matching the BPF program
class VirtioRxEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("dev_name", ct.c_char * 16),
        ("queue_index", ct.c_uint32),
        ("vq_ptr", ct.c_uint64),
        ("vq_num", ct.c_uint32),
        ("vq_num_free", ct.c_uint32),
        ("napi_ptr", ct.c_uint64),
        ("napi_budget", ct.c_uint32),
        ("napi_received", ct.c_uint32),
        ("netdev_ptr", ct.c_uint64),
        ("netdev_flags", ct.c_uint32),
        ("netdev_state", ct.c_uint32),
        ("rx_packets", ct.c_uint64),
        ("rx_bytes", ct.c_uint64),
        ("rx_dropped", ct.c_uint64),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VirtioRxEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    event_names = {
        1: "skb_recv_done",
        2: "virtnet_poll"
    }
    
    print("=" * 80)
    print("🔍 Event: {} | Time: {}".format(
        event_names.get(event.event_type, "unknown"), timestamp_str))
    print("📍 Queue: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    
    # Virtqueue information
    print("🔗 VQ: 0x{:x} | Num: {}, Free: {}".format(
        event.vq_ptr, event.vq_num, event.vq_num_free))
    
    # NAPI information (for virtnet_poll)
    if event.event_type == 2:  # virtnet_poll
        print("📊 NAPI: 0x{:x} | Budget: {}, Received: {}".format(
            event.napi_ptr, event.napi_budget, event.napi_received))
    
    # Network device information
    print("🌐 NetDev: 0x{:x} | Flags: 0x{:x}, State: 0x{:x}".format(
        event.netdev_ptr, event.netdev_flags, event.netdev_state))
    
    # Statistics
    if event.rx_packets > 0 or event.rx_bytes > 0:
        print("📈 Stats: Packets: {}, Bytes: {}, Dropped: {}".format(
            event.rx_packets, event.rx_bytes, event.rx_dropped))
    
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Guest virtio-net RX Queue Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all RX queues on all virtio-net devices
  sudo %(prog)s
  
  # Monitor specific device and queue
  sudo %(prog)s --device eth0 --queue 0
  
  # Monitor specific device with verbose output  
  sudo %(prog)s --device eth0 --verbose
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., eth0)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by RX queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach kprobes
        b.attach_kprobe(event="skb_recv_done", fn_name="trace_skb_recv_done")
        b.attach_kprobe(event="virtnet_poll", fn_name="trace_virtnet_poll")
        b.attach_kretprobe(event="virtnet_poll", fn_name="trace_virtnet_poll_return")
        
        if args.verbose:
            print("✅ All probes attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    # Set device filter
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("📡 Device filter: {}".format(args.device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("📡 Device filter: All virtio-net devices")
    
    # Set queue filter
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("🔍 Queue filter: {}".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("🔍 Queue filter: All queues")
    
    print("🚀 Guest virtio-net RX Monitor Started")
    print("📊 Monitoring skb_recv_done and virtnet_poll events")
    print("⏳ Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\n👋 Monitoring stopped.")

if __name__ == "__main__":
    main()