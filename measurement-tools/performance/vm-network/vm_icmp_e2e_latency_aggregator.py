#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VM ICMP End-to-End Latency Aggregator (host-side).

This script runs multiple existing tools together and provides one consolidated
view for VM<->VM ICMP latency on the host:

1) boundary-detection/vm-network/icmp_path_tracer.py
   - End-to-end ICMP flow latency decomposition:
     ReqInternal / External / RepInternal / Total (us)

2) kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py (optional)
   - VM TX host-side latency stages:
     S0(ioeventfd->kick) / S1(kick->sendmsg) / S2(sendmsg->receive) (us)

3) kvm-virt-network/tun/tun_tx_to_kvm_irq.py (optional)
   - Host->VM interrupt/injection chain delays:
     Stage2/3/4/5 delays and chain total (ms)

Run as root.
"""

from __future__ import print_function

import argparse
import datetime
import math
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque


def percentile(sorted_values, p):
    if not sorted_values:
        return None
    if p <= 0:
        return sorted_values[0]
    if p >= 1:
        return sorted_values[-1]
    pos = (len(sorted_values) - 1) * p
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return sorted_values[lo]
    frac = pos - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def fmt_stats(values, unit):
    if not values:
        return "n=0"
    vals = list(values)
    vals_sorted = sorted(vals)
    avg = sum(vals) / float(len(vals))
    p50 = percentile(vals_sorted, 0.50)
    p95 = percentile(vals_sorted, 0.95)
    p99 = percentile(vals_sorted, 0.99)
    vmax = vals_sorted[-1]
    return (
        "n={n} avg={avg:.1f}{u} p50={p50:.1f}{u} "
        "p95={p95:.1f}{u} p99={p99:.1f}{u} max={vmax:.1f}{u}"
    ).format(
        n=len(vals),
        avg=avg,
        p50=p50,
        p95=p95,
        p99=p99,
        vmax=vmax,
        u=unit,
    )


class MetricStore(object):
    def __init__(self, max_samples):
        self._lock = threading.Lock()
        self._series = defaultdict(lambda: deque(maxlen=max_samples))
        self._counters = defaultdict(int)

    def add(self, key, value):
        with self._lock:
            self._series[key].append(float(value))

    def incr(self, key, delta=1):
        with self._lock:
            self._counters[key] += int(delta)

    def snapshot(self):
        with self._lock:
            series_copy = {k: list(v) for k, v in self._series.items()}
            counters_copy = dict(self._counters)
        return series_copy, counters_copy


class SegmentCorrelator(object):
    """
    Best-effort temporal correlation for per-packet extended segments.

    Notes:
    - Different tools do not share a strict packet trace-id.
    - Correlation here is nearest-by-time within a window.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {
            "req": {},
            "rep": {},
        }

    def _update(self, direction, field, value, ts=None):
        if direction not in ("req", "rep"):
            return
        if ts is None:
            ts = time.time()
        with self._lock:
            self._data[direction][field] = (float(ts), float(value))

    def update_vhost(self, direction, s0_us, s1_us, s2_us, total_us, ts=None):
        self._update(direction, "vhost_s0_us", s0_us, ts=ts)
        self._update(direction, "vhost_s1_us", s1_us, ts=ts)
        self._update(direction, "vhost_s2_us", s2_us, ts=ts)
        self._update(direction, "vhost_total_us", total_us, ts=ts)

    def update_irq_stage(self, direction, stage, delay_ms, ts=None):
        self._update(direction, "irq_s{}_ms".format(stage), delay_ms, ts=ts)

    def update_irq_total(self, direction, total_ms, ts=None):
        self._update(direction, "irq_total_ms", total_ms, ts=ts)

    def snapshot_for_row(self, row_ts, window_sec=2.0):
        out = {}
        with self._lock:
            for direction in ("req", "rep"):
                for field, tup in self._data[direction].items():
                    ev_ts, ev_val = tup
                    key = "{}_{}".format(direction, field)
                    if abs(float(row_ts) - ev_ts) <= window_sec:
                        out[key] = ev_val
                    else:
                        out[key] = None
        return out


class PacketTableStore(object):
    def __init__(self, max_rows=10000, realtime_print=False):
        self._lock = threading.Lock()
        self._rows = deque(maxlen=max_rows)
        self._row_idx = 0
        self._realtime_print = realtime_print
        self._printed_header = False

    @staticmethod
    def _columns():
        return [
            "idx", "id", "seq",
            "req_internal_us",
            "req_vhost_s0_us", "req_vhost_s1_us", "req_vhost_s2_us", "req_vhost_total_us",
            "req_irq_s2_ms", "req_irq_s3_ms", "req_irq_s4_ms", "req_irq_s5_ms", "req_irq_total_ms",
            "external_us",
            "rep_irq_s2_ms", "rep_irq_s3_ms", "rep_irq_s4_ms", "rep_irq_s5_ms", "rep_irq_total_ms",
            "rep_vhost_s0_us", "rep_vhost_s1_us", "rep_vhost_s2_us", "rep_vhost_total_us",
            "rep_internal_us",
            "total_us",
        ]

    @staticmethod
    def _fmt(v):
        if v is None:
            return ""
        if isinstance(v, int):
            return str(v)
        return "{:.3f}".format(float(v))

    def _print_csv_header(self):
        print("\nPer-packet ICMP latency table (csv):")
        print(",".join(self._columns()))

    def _print_csv_row(self, row_dict):
        cols = self._columns()
        print(",".join(self._fmt(row_dict.get(c)) for c in cols))

    def add_row(self, icmp_id, seq, req_internal, external, rep_internal, total, extras=None):
        if extras is None:
            extras = {}
        with self._lock:
            self._row_idx += 1
            row = {
                "idx": self._row_idx,
                "id": int(icmp_id) if icmp_id is not None else -1,
                "seq": int(seq) if seq is not None else -1,
                "req_internal_us": float(req_internal),
                "external_us": float(external),
                "rep_internal_us": float(rep_internal),
                "total_us": float(total),
                "req_vhost_s0_us": extras.get("req_vhost_s0_us"),
                "req_vhost_s1_us": extras.get("req_vhost_s1_us"),
                "req_vhost_s2_us": extras.get("req_vhost_s2_us"),
                "req_vhost_total_us": extras.get("req_vhost_total_us"),
                "rep_vhost_s0_us": extras.get("rep_vhost_s0_us"),
                "rep_vhost_s1_us": extras.get("rep_vhost_s1_us"),
                "rep_vhost_s2_us": extras.get("rep_vhost_s2_us"),
                "rep_vhost_total_us": extras.get("rep_vhost_total_us"),
                "req_irq_s2_ms": extras.get("req_irq_s2_ms"),
                "req_irq_s3_ms": extras.get("req_irq_s3_ms"),
                "req_irq_s4_ms": extras.get("req_irq_s4_ms"),
                "req_irq_s5_ms": extras.get("req_irq_s5_ms"),
                "req_irq_total_ms": extras.get("req_irq_total_ms"),
                "rep_irq_s2_ms": extras.get("rep_irq_s2_ms"),
                "rep_irq_s3_ms": extras.get("rep_irq_s3_ms"),
                "rep_irq_s4_ms": extras.get("rep_irq_s4_ms"),
                "rep_irq_s5_ms": extras.get("rep_irq_s5_ms"),
                "rep_irq_total_ms": extras.get("rep_irq_total_ms"),
            }
            self._rows.append(dict(row))
            if self._realtime_print:
                if not self._printed_header:
                    self._print_csv_header()
                    self._printed_header = True
                self._print_csv_row(row)

    def snapshot(self):
        with self._lock:
            return list(self._rows)


class ProcessRunner(object):
    def __init__(self, name, cmd, line_handler):
        self.name = name
        self.cmd = cmd
        self._line_handler = line_handler
        self.proc = None
        self.thread = None
        self.exit_code = None
        self.last_line = ""
        self.started = False

    def start(self):
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )
        self.started = True
        self.thread = threading.Thread(target=self._reader, name=self.name)
        self.thread.daemon = True
        self.thread.start()

    def _reader(self):
        try:
            for raw in self.proc.stdout:
                line = raw.rstrip("\n")
                if not line:
                    continue
                self.last_line = line
                try:
                    self._line_handler(line)
                except Exception:
                    # Keep collector alive even if parsing fails on one line.
                    pass
        finally:
            if self.proc:
                self.exit_code = self.proc.wait()

    def stop(self):
        if not self.started or not self.proc:
            return
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)

    def status(self):
        if not self.started:
            return "not started"
        if self.proc.poll() is None:
            return "running"
        return "exited({})".format(self.exit_code)


def build_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    return {
        "icmp_path_tracer": os.path.join(
            repo_root, "measurement-tools", "boundary-detection",
            "vm-network", "icmp_path_tracer.py"
        ),
        "vhost_tun_latency": os.path.join(
            repo_root, "measurement-tools", "kvm-virt-network",
            "kvm", "kvm_vhost_tun_latency_no_discovery_details.py"
        ),
        "tun_tx_irq": os.path.join(
            repo_root, "measurement-tools", "kvm-virt-network",
            "tun", "tun_tx_to_kvm_irq.py"
        ),
    }


def make_icmp_parser(store, packet_table_store=None, segment_correlator=None):
    complete_re = re.compile(r"\[complete\]\s+ID=(\d+)\s+Seq=(\d+)")
    lat_re = re.compile(
        r"Latency\(us\): ReqInternal=([0-9.]+)\s+External=([0-9.]+)\s+"
        r"RepInternal=([0-9.]+)\s+Total=([0-9.]+)"
    )
    pending_key = {"id": None, "seq": None}

    def parse(line):
        m = complete_re.search(line)
        if m:
            pending_key["id"] = int(m.group(1))
            pending_key["seq"] = int(m.group(2))
            return

        m = lat_re.search(line)
        if m:
            req_internal = float(m.group(1))
            external = float(m.group(2))
            rep_internal = float(m.group(3))
            total = float(m.group(4))
            now_ts = time.time()

            store.add("path.req_internal_us", req_internal)
            store.add("path.external_us", external)
            store.add("path.rep_internal_us", rep_internal)
            store.add("path.total_us", total)

            if packet_table_store is not None:
                extras = {}
                if segment_correlator is not None:
                    extras = segment_correlator.snapshot_for_row(now_ts, window_sec=2.0)
                packet_table_store.add_row(
                    pending_key.get("id"),
                    pending_key.get("seq"),
                    req_internal,
                    external,
                    rep_internal,
                    total,
                    extras=extras,
                )
                pending_key["id"] = None
                pending_key["seq"] = None
            return

        if "Drop Location: Request dropped INTERNALLY" in line:
            store.incr("path.drop.req_internal")
            return
        if "Drop Location: EXTERNAL (network or peer)" in line:
            store.incr("path.drop.external")
            return
        if "Drop Location: Reply dropped INTERNALLY" in line:
            store.incr("path.drop.rep_internal")

    return parse


def make_vhost_parser(store, prefix, segment_correlator=None, direction=None):
    event_re = re.compile(
        r"s0=([0-9.]+)us\s+s1=([0-9.]+)us\s+s2=([0-9.]+)us\s+total=([0-9.]+)us"
    )

    def parse(line):
        m = event_re.search(line)
        if not m:
            return
        store.add(prefix + ".s0_us", float(m.group(1)))
        store.add(prefix + ".s1_us", float(m.group(2)))
        store.add(prefix + ".s2_us", float(m.group(3)))
        store.add(prefix + ".total_us", float(m.group(4)))
        if segment_correlator is not None and direction in ("req", "rep"):
            segment_correlator.update_vhost(
                direction,
                float(m.group(1)),
                float(m.group(2)),
                float(m.group(3)),
                float(m.group(4)),
                ts=time.time(),
            )

    return parse


def make_irq_parser(store, prefix, segment_correlator=None, direction=None):
    stage_re = re.compile(r"Stage\s+([0-9]+)\s+\[[^\]]+\].*Delay=([0-9.]+)ms")
    total_re = re.compile(r"Total\(S1->S5\):\s*([0-9.]+)ms")

    def parse(line):
        m = stage_re.search(line)
        if m:
            stage = int(m.group(1))
            delay_ms = float(m.group(2))
            store.add(prefix + ".stage{}_ms".format(stage), delay_ms)
            if segment_correlator is not None and direction in ("req", "rep") and stage in (2, 3, 4, 5):
                segment_correlator.update_irq_stage(direction, stage, delay_ms, ts=time.time())
            return
        m = total_re.search(line)
        if m:
            total_ms = float(m.group(1))
            store.add(prefix + ".total_ms", total_ms)
            if segment_correlator is not None and direction in ("req", "rep"):
                segment_correlator.update_irq_total(direction, total_ms, ts=time.time())

    return parse


def print_summary(store, runners, packet_rows=None, packet_table_limit=0):
    series, counters = store.snapshot()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 96)
    print("[{}] VM ICMP E2E Latency Aggregated View".format(now))
    print("=" * 96)

    print("Path tracer (host e2e, ICMP):")
    print("  Total:        {}".format(fmt_stats(series.get("path.total_us", []), "us")))
    print("  ReqInternal:  {}".format(fmt_stats(series.get("path.req_internal_us", []), "us")))
    print("  External:     {}".format(fmt_stats(series.get("path.external_us", []), "us")))
    print("  RepInternal:  {}".format(fmt_stats(series.get("path.rep_internal_us", []), "us")))
    print(
        "  Drops: req_internal={} external={} rep_internal={}".format(
            counters.get("path.drop.req_internal", 0),
            counters.get("path.drop.external", 0),
            counters.get("path.drop.rep_internal", 0),
        )
    )

    if any(k.startswith("vhost.") for k in series.keys()):
        print("\nVHOST/TUN TX stage latency:")
        print("  src->dst S0:  {}".format(fmt_stats(series.get("vhost.src_to_dst.s0_us", []), "us")))
        print("  src->dst S1:  {}".format(fmt_stats(series.get("vhost.src_to_dst.s1_us", []), "us")))
        print("  src->dst S2:  {}".format(fmt_stats(series.get("vhost.src_to_dst.s2_us", []), "us")))
        print("  src->dst Tot: {}".format(fmt_stats(series.get("vhost.src_to_dst.total_us", []), "us")))
        print("  dst->src S0:  {}".format(fmt_stats(series.get("vhost.dst_to_src.s0_us", []), "us")))
        print("  dst->src S1:  {}".format(fmt_stats(series.get("vhost.dst_to_src.s1_us", []), "us")))
        print("  dst->src S2:  {}".format(fmt_stats(series.get("vhost.dst_to_src.s2_us", []), "us")))
        print("  dst->src Tot: {}".format(fmt_stats(series.get("vhost.dst_to_src.total_us", []), "us")))

    if any(k.startswith("irq.") for k in series.keys()):
        print("\nInterrupt injection chain (host->VM):")
        print("  req->dst stage2: {}".format(fmt_stats(series.get("irq.req_to_dst.stage2_ms", []), "ms")))
        print("  req->dst stage3: {}".format(fmt_stats(series.get("irq.req_to_dst.stage3_ms", []), "ms")))
        print("  req->dst stage4: {}".format(fmt_stats(series.get("irq.req_to_dst.stage4_ms", []), "ms")))
        print("  req->dst stage5: {}".format(fmt_stats(series.get("irq.req_to_dst.stage5_ms", []), "ms")))
        print("  req->dst total:  {}".format(fmt_stats(series.get("irq.req_to_dst.total_ms", []), "ms")))
        print("  rep->src stage2: {}".format(fmt_stats(series.get("irq.rep_to_src.stage2_ms", []), "ms")))
        print("  rep->src stage3: {}".format(fmt_stats(series.get("irq.rep_to_src.stage3_ms", []), "ms")))
        print("  rep->src stage4: {}".format(fmt_stats(series.get("irq.rep_to_src.stage4_ms", []), "ms")))
        print("  rep->src stage5: {}".format(fmt_stats(series.get("irq.rep_to_src.stage5_ms", []), "ms")))
        print("  rep->src total:  {}".format(fmt_stats(series.get("irq.rep_to_src.total_ms", []), "ms")))

    print("\nTool status:")
    for r in runners:
        status = r.status()
        if status.startswith("exited") and r.last_line:
            print("  {:<20} {} | last: {}".format(r.name + ":", status, r.last_line))
        else:
            print("  {:<20} {}".format(r.name + ":", status))

    if packet_rows is not None:
        print("\nPacket rows captured: {}".format(len(packet_rows)))
        if packet_table_limit > 0:
            rows = packet_rows[-packet_table_limit:]
            print("Last {} packet rows (csv):".format(len(rows)))
            print(",".join(PacketTableStore._columns()))
            for row in rows:
                print(",".join(PacketTableStore._fmt(row.get(c)) for c in PacketTableStore._columns()))


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate host-side VM ICMP end-to-end latency from multiple tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  sudo %(prog)s \\
    --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \\
    --src-iface vnet0 --dst-iface vnet1 \\
    --interval 5
""",
    )
    parser.add_argument("--src-ip", required=True, help="ICMP request source VM IP")
    parser.add_argument("--dst-ip", required=True, help="ICMP request destination VM IP")
    parser.add_argument("--src-iface", required=True, help="Source VM interface on host (e.g. vnet0)")
    parser.add_argument("--dst-iface", required=True, help="Destination VM interface on host (e.g. vnet1)")
    parser.add_argument("--timeout-ms", type=int, default=1000,
                        help="Flow timeout for icmp_path_tracer (default: 1000)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Summary print interval in seconds (default: 5)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Run duration in seconds, 0 means until Ctrl-C (default: 0)")
    parser.add_argument("--max-samples", type=int, default=5000,
                        help="Max samples retained per metric (default: 5000)")
    parser.add_argument("--packet-table", action="store_true",
                        help="Print per-packet ICMP latency rows in realtime")
    parser.add_argument("--packet-table-limit", type=int, default=0,
                        help="Print last N packet rows in each summary (default: 0=off)")

    parser.add_argument("--disable-vhost", action="store_true",
                        help="Disable vhost/tun TX stage tools")
    parser.add_argument("--src-qemu-pid", type=int, default=0,
                        help="Optional QEMU PID for src iface vhost tool")
    parser.add_argument("--dst-qemu-pid", type=int, default=0,
                        help="Optional QEMU PID for dst iface vhost tool")
    parser.add_argument("--vhost-warmup", type=int, default=2,
                        help="Warmup seconds for vhost tool (default: 2)")

    parser.add_argument("--disable-irq", action="store_true",
                        help="Disable interrupt-chain tool")
    parser.add_argument("--src-queue", type=int, default=-1,
                        help="Optional queue filter for src iface irq tool")
    parser.add_argument("--dst-queue", type=int, default=-1,
                        help="Optional queue filter for dst iface irq tool")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This script must be run as root.")
        return 1

    paths = build_paths()
    for key, path in paths.items():
        if not os.path.exists(path):
            print("Required script not found ({}): {}".format(key, path))
            return 1

    py = sys.executable
    store = MetricStore(max_samples=args.max_samples)
    segment_correlator = SegmentCorrelator()
    packet_table_store = PacketTableStore(
        max_rows=max(1000, args.max_samples),
        realtime_print=args.packet_table,
    )
    runners = []

    # 1) ICMP path tracer (always on)
    icmp_cmd = [
        py, "-u", paths["icmp_path_tracer"],
        "--src-ip", args.src_ip,
        "--dst-ip", args.dst_ip,
        "--rx-iface", args.src_iface,
        "--tx-iface", args.dst_iface,
        "--timeout-ms", str(args.timeout_ms),
        "--verbose",
    ]
    runners.append(ProcessRunner(
        "icmp_path_tracer",
        icmp_cmd,
        make_icmp_parser(
            store,
            packet_table_store=packet_table_store,
            segment_correlator=segment_correlator,
        ),
    ))

    # 2) vhost/tun TX latency (optional)
    if not args.disable_vhost:
        src_to_dst_flow = "proto=icmp,src={},dst={}".format(args.src_ip, args.dst_ip)
        dst_to_src_flow = "proto=icmp,src={},dst={}".format(args.dst_ip, args.src_ip)

        vhost_src_cmd = [
            py, "-u", paths["vhost_tun_latency"],
            "--device", args.src_iface,
            "--flow", src_to_dst_flow,
            "--warmup", str(args.vhost_warmup),
        ]
        if args.src_qemu_pid > 0:
            vhost_src_cmd.extend(["--qemu-pid", str(args.src_qemu_pid)])
        runners.append(ProcessRunner(
            "vhost_src_to_dst",
            vhost_src_cmd,
            make_vhost_parser(
                store, "vhost.src_to_dst",
                segment_correlator=segment_correlator,
                direction="req",
            ),
        ))

        vhost_dst_cmd = [
            py, "-u", paths["vhost_tun_latency"],
            "--device", args.dst_iface,
            "--flow", dst_to_src_flow,
            "--warmup", str(args.vhost_warmup),
        ]
        if args.dst_qemu_pid > 0:
            vhost_dst_cmd.extend(["--qemu-pid", str(args.dst_qemu_pid)])
        runners.append(ProcessRunner(
            "vhost_dst_to_src",
            vhost_dst_cmd,
            make_vhost_parser(
                store, "vhost.dst_to_src",
                segment_correlator=segment_correlator,
                direction="rep",
            ),
        ))

    # 3) interrupt chain (optional)
    if not args.disable_irq:
        irq_req_cmd = [
            py, "-u", paths["tun_tx_irq"],
            "--device", args.dst_iface,
            "--protocol", "icmp",
            "--src-ip", args.src_ip,
            "--dst-ip", args.dst_ip,
        ]
        if args.dst_queue >= 0:
            irq_req_cmd.extend(["--queue", str(args.dst_queue)])
        runners.append(ProcessRunner(
            "irq_req_to_dst",
            irq_req_cmd,
            make_irq_parser(
                store, "irq.req_to_dst",
                segment_correlator=segment_correlator,
                direction="req",
            ),
        ))

        irq_rep_cmd = [
            py, "-u", paths["tun_tx_irq"],
            "--device", args.src_iface,
            "--protocol", "icmp",
            "--src-ip", args.dst_ip,
            "--dst-ip", args.src_ip,
        ]
        if args.src_queue >= 0:
            irq_rep_cmd.extend(["--queue", str(args.src_queue)])
        runners.append(ProcessRunner(
            "irq_rep_to_src",
            irq_rep_cmd,
            make_irq_parser(
                store, "irq.rep_to_src",
                segment_correlator=segment_correlator,
                direction="rep",
            ),
        ))

    print("Starting VM ICMP E2E latency aggregator...")
    print("Source VM: {} ({})".format(args.src_ip, args.src_iface))
    print("Destination VM: {} ({})".format(args.dst_ip, args.dst_iface))
    print("Summary interval: {}s".format(args.interval))
    if args.duration > 0:
        print("Duration: {}s".format(args.duration))
    else:
        print("Duration: until Ctrl-C")
    print("")

    for r in runners:
        print("[start] {}: {}".format(r.name, " ".join(r.cmd)))
        r.start()

    stop = False

    def _handle_signal(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    start_ts = time.time()
    next_print = start_ts + args.interval

    try:
        while not stop:
            now = time.time()
            if args.duration > 0 and (now - start_ts) >= args.duration:
                break
            if now >= next_print:
                print_summary(
                    store, runners,
                    packet_rows=packet_table_store.snapshot(),
                    packet_table_limit=args.packet_table_limit,
                )
                next_print = now + args.interval
            time.sleep(0.2)
    finally:
        for r in runners:
            r.stop()
        print_summary(
            store, runners,
            packet_rows=packet_table_store.snapshot(),
            packet_table_limit=args.packet_table_limit,
        )
        print("\nStopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
