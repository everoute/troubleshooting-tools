#!/usr/bin/env python2

"""
Minimal RX Debug Tool - Simple probe point verification
"""

from bcc import BPF
import time
import argparse
import socket
import struct

# Simple BPF program to verify probe points work
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

struct simple_event {
    u64 timestamp;
    u32 probe_id;          // 1=tcp_v4_rcv, 2=sock_queue_rcv_skb, 3=tcp_recvmsg, 4=udp_recvmsg
    u32 pid;
    char comm[16];
    u64 skb_addr;
    u64 sk_addr;
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct simple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 1;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.skb_addr = (u64)skb;
    event.sk_addr = 0;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct simple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 2;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.skb_addr = (u64)skb;
    event.sk_addr = (u64)sk;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    struct simple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 3;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.skb_addr = 0;
    event.sk_addr = (u64)sk;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    struct simple_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.probe_id = 4;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.skb_addr = 0;
    event.sk_addr = (u64)sk;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

def format_probe_name(probe_id):
    probe_names = {
        1: "tcp_v4_rcv",
        2: "sock_queue_rcv_skb", 
        3: "tcp_recvmsg",
        4: "udp_recvmsg"
    }
    return probe_names.get(probe_id, "unknown_%d" % probe_id)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    print("[%s] PID:%d COMM:%s PROBE:%s SKB:%#x SOCK:%#x" % (
        time.strftime("%H:%M:%S"),
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        format_probe_name(event.probe_id),
        event.skb_addr,
        event.sk_addr
    ))

def main():
    parser = argparse.ArgumentParser(description='Simple RX probe verification tool')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    args = parser.parse_args()
    
    print("=== Simple RX Probe Verification Tool ===")
    print("Duration: %d seconds" % args.duration)
    print("Testing basic probe point functionality...")
    print()
    
    global b
    b = BPF(text=bpf_text)
    
    # Attach probes
    print("Attached probes:")
    print("  1. tcp_v4_rcv")
    print("  2. sock_queue_rcv_skb") 
    print("  3. tcp_recvmsg")
    print("  4. udp_recvmsg")
    print()
    
    b["events"].open_perf_buffer(print_event)
    
    print("Tracing... Hit Ctrl-C to end")
    
    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
    finally:
        print("\n=== Probe verification completed ===")

if __name__ == "__main__":
    main()