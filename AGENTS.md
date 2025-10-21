# Repository Guidelines

## Project Structure & Modules
- `bcc-tools/`: Python + BCC tools grouped by domain (`cpu/`, `linux-network-stack/`, `ovs/`, `packet-drop/`, `performance/{system-network,vm-network}`, `virtio-network/`).
- `bpftrace-tools/`: bpftrace scripts (`*.bt`) for high-level tracing.
- `bcc-program/`: bundled BCC CLI utilities runnable directly (e.g., `tcpconnect`).
- `docs/`: design notes and deep-dive architecture.
- `test/tools/`: helper utilities (e.g., `bpf_remote_executor.py`).

## Build, Test, and Development
- Build: none required; scripts run in place. Root privileges are usually needed.
- Run (examples):
  - `sudo python2 bcc-tools/cpu/offcputime-ts.py --help`
  - `sudo python3 bcc-tools/performance/system-network/system_tcp_udp_latency.py ...`
  - `sudo bpftrace bpftrace-tools/trace-ovs-ct-invalid.bt`
  - `sudo ./bcc-program/tcpconnect -t`
- Quick checks: prefer minimal filters and short durations where supported (e.g., `--timeout 10`) to smoke-test without load.

## Coding Style & Naming
- Python: 4-space indent, `snake_case.py`, keep Python 2/3 compatible where feasible.
  - Import pattern for BCC: `from bcc import BPF` with fallback to `from bpfcc import BPF`.
- bpftrace: `kebab-case.bt`, include brief header comment and usage.
- Place new tools under the closest domain folder; add a focused README or usage notes if complex.
- No enforced formatter; keep diffs small and consistent with nearby files.

## Testing Guidelines
- No unit test framework. Use runtime smoke tests:
  - Start with `--help`; then run with narrow filters and short runs.
  - Ensure graceful Ctrl+C handling and informative final stats.
  - For bpftrace, validate it loads: `sudo bpftrace -d script.bt` (dry-compile) if applicable.
- Capture representative output in the PR description.

## Commit & Pull Requests
- Commits: follow Conventional Commits seen here: `feat:`, `fix:`, `chore:` (e.g., `feat: add drop monitor controller`).
- PRs: include purpose, run instructions, sample output, and any kernel/BPF prerequisites. Link issues if relevant. Screenshots optional; logs preferred.

## Security & Configuration
- Requires kernels with eBPF enabled; install BCC/bpftrace as per README. Use `sudo` responsibly.
- Avoid committing environment-specific IPs/hostnames or secrets; document them as placeholders in examples.

