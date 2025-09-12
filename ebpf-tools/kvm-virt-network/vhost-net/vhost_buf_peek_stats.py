#!/usr/bin/env python

from bcc import BPF
import time
import argparse

parser = argparse.ArgumentParser(description="Track vhost_net_buf_peek return values by nvq pointer")
parser.add_argument("-i", "--interval", type=int, default=1,
                    help="output interval in seconds (default 1)")
parser.add_argument("-c", "--clear", action="store_true",
                    help="clear counters after each output")
args = parser.parse_args()

bpf_text = """
#include <linux/sched.h>

struct key_t {
    u64 nvq_ptr;
    int ret_val;
};

BPF_HASH(counts, struct key_t, u64);
BPF_HASH(nvq_map, u64, u64);

int trace_vhost_net_buf_peek_entry(struct pt_regs *ctx, void *nvq)
{
    // Store nvq pointer for return probe
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 nvq_val = (u64)nvq;
    nvq_map.update(&pid_tgid, &nvq_val);
    return 0;
}

int trace_vhost_net_buf_peek_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *nvq_ptr = nvq_map.lookup(&pid_tgid);
    if (!nvq_ptr) {
        return 0;
    }
    
    int ret_val = PT_REGS_RC(ctx);
    
    struct key_t key = {};
    key.nvq_ptr = *nvq_ptr;
    key.ret_val = ret_val;
    
    u64 *count = counts.lookup(&key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        counts.update(&key, &init_val);
    }
    
    // Clean up
    nvq_map.delete(&pid_tgid);
    
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="vhost_net_buf_peek", fn_name="trace_vhost_net_buf_peek_entry")
b.attach_kretprobe(event="vhost_net_buf_peek", fn_name="trace_vhost_net_buf_peek_return")

print("Tracking vhost_net_buf_peek return values... Ctrl-C to stop")
print("Output interval: %d seconds" % args.interval)

def print_stats():
    print("\n%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("%-18s %-10s %8s" % ("NVQ_PTR", "RET_VAL", "COUNT"))
    print("-" * 40)
    
    counts = b["counts"]
    if not counts:
        print("No data")
        return
    
    # Group by nvq_ptr
    nvq_data = {}
    for k, v in counts.items():
        nvq_ptr = k.nvq_ptr
        ret_val = k.ret_val
        if nvq_ptr not in nvq_data:
            nvq_data[nvq_ptr] = {}
        nvq_data[nvq_ptr][ret_val] = v.value
    
    for nvq_ptr in sorted(nvq_data.keys()):
        ret_vals = nvq_data[nvq_ptr]
        print("\nNVQ: 0x%016x" % nvq_ptr)
        total_calls = sum(ret_vals.values())
        print("  Total calls: %d" % total_calls)
        
        # Show return value distribution
        for ret_val in sorted(ret_vals.keys()):
            count = ret_vals[ret_val]
            pct = (count * 100.0 / total_calls) if total_calls > 0 else 0
            print("  ret=%d: %d times (%.1f%%)" % (ret_val, count, pct))
    
    if args.clear:
        counts.clear()

try:
    while True:
        time.sleep(args.interval)
        print_stats()
except KeyboardInterrupt:
    print("\nFinal statistics:")
    print_stats()