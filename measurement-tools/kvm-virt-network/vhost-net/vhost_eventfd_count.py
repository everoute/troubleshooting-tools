#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import ctypes as ct
import sys
import time

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


class EventfdKey(ct.Structure):
    _fields_ = [
        ("vq_ptr", ct.c_uint64),
        ("eventfd_ptr", ct.c_uint64),
    ]


BPF_TEXT = r"""
#include <linux/sched.h>

struct eventfd_key {
    u64 vq_ptr;
    u64 eventfd_ptr;
};

BPF_HASH(active_vqs, u64, u64, 4096);
BPF_HASH(counts, struct eventfd_key, u64, 4096);

int trace_vhost_signal(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 vq_ptr = (u64)PT_REGS_PARM2(ctx);

    if (vq_ptr)
        active_vqs.update(&pid_tgid, &vq_ptr);
    return 0;
}

int trace_vhost_signal_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    active_vqs.delete(&pid_tgid);
    return 0;
}

int trace_eventfd_signal(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *active_vq = active_vqs.lookup(&pid_tgid);

    if (!active_vq)
        return 0;

    struct eventfd_key key = {};
    key.vq_ptr = *active_vq;
    key.eventfd_ptr = (u64)PT_REGS_PARM1(ctx);

    // A vhost function may tail-call eventfd_signal without hitting kretprobe.
    active_vqs.delete(&pid_tgid);
    if (!key.eventfd_ptr)
        return 0;

    u64 zero = 0;
    u64 *value = counts.lookup_or_try_init(&key, &zero);
    if (value)
        __sync_fetch_and_add(value, 1);
    return 0;
}
"""


VHOST_SIGNAL_FUNCTIONS = (
    "vhost_add_used_and_signal",
    "vhost_add_used_and_signal_n",
    "vhost_signal",
)


def attach_probes(bpf):
    try:
        bpf.attach_kprobe(event="eventfd_signal", fn_name="trace_eventfd_signal")
    except Exception as error:
        raise RuntimeError("cannot attach eventfd_signal: %s" % error)

    attached = []
    failures = []
    for function in VHOST_SIGNAL_FUNCTIONS:
        try:
            bpf.attach_kretprobe(event=function, fn_name="trace_vhost_signal_return")
            bpf.attach_kprobe(event=function, fn_name="trace_vhost_signal")
            attached.append(function)
        except Exception as error:
            failures.append("%s: %s" % (function, error))

    if not attached:
        details = "; ".join(failures)
        raise RuntimeError("cannot attach any vhost signal function: %s" % details)
    return attached


def print_stats(bpf, clear):
    print("\n%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("%-18s %-18s %8s" % ("VQ_PTR", "EVENTFD_PTR", "COUNT"))
    print("-" * 50)

    counts = bpf["counts"]
    items = sorted(counts.items(), key=lambda item: item[1].value, reverse=True)
    if not items:
        print("No data")
    else:
        for key, value in items:
            print("0x%016x 0x%016x %8d" % (key.vq_ptr, key.eventfd_ptr, value.value))

    if clear:
        counts.clear()


def main():
    parser = argparse.ArgumentParser(
        description="Count vhost_virtqueue + eventfd_ctx combinations"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=1,
        help="output interval in seconds (default 1)",
    )
    parser.add_argument(
        "-c", "--clear", action="store_true", help="clear counters after each output"
    )
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")

    try:
        bpf = BPF(text=BPF_TEXT)
        attached = attach_probes(bpf)
    except Exception as error:
        print("Error: %s" % error, file=sys.stderr)
        return 1

    print("Counting vhost_virtqueue + eventfd_ctx combinations... Ctrl-C to stop")
    print("Output interval: %d seconds" % args.interval)
    print("Vhost probes: %s" % ", ".join(attached))

    try:
        while True:
            time.sleep(args.interval)
            print_stats(bpf, args.clear)
    except KeyboardInterrupt:
        print("\nFinal statistics:")
        print_stats(bpf, args.clear)
    return 0


if __name__ == "__main__":
    sys.exit(main())
