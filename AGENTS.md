# Repository Guidelines

<<<<<<< HEAD
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

=======
## Project Structure & Module Organization
`ebpf-tools/` hosts runnable collectors grouped by domain: use `performance/system-network/` for host link latency, `performance/vm-network/` for guest paths, `linux-network-stack/packet-drop/` for kernel drop tracing, and `ovs/` for Open vSwitch dataplanes. Share helper modules before adding new directories. Persistent design notes live in `docs/`, with deep datapath write-ups under `docs/virtlization-datapath-analysis/`. Keep test harness code in `test/` and store generated artefacts inside `test/performance-test-results/`. Treat `kernel-source/` as read-only; update it only when rebasing to a new upstream snapshot and document the tag.

## Build, Test, and Development Commands
Activate the repo virtual environment with `source .venv/bin/activate`. Install prerequisites (Python 3, BCC, bpftrace) on the target host before running probes. Collect physical link metrics via `sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py --direction rx`. Summarize guest latency with `sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py --protocol tcp`. Run the full regression using `python3 test/run_all_tests.py`, or replay a single scenario such as `python3 test/test_single_case.py 3` to reproduce command #3 from `test/performance-test-cases.txt`.

## Coding Style & Naming Conventions
Default to PEP 8: four-space indentation, descriptive snake_case, and module-level docstrings only where they add context. Preserve the `#!/usr/bin/env python3` shebang and guard executables with `if __name__ == "__main__":`. Name new bpftrace scripts with lowercase hyphenated filenames and explain attach points inline. Reuse the existing argparse patterns so CLI flags stay aligned across tools.

## Testing Guidelines
Remote runners assume SSH access to `smartx@172.21.152.82`; coordinate before touching credentials or baked host paths. Append new scenarios to `test/performance-test-cases.txt` using sudo-prefixed absolute commands so the harness can infer case names. Record behaviour changes in `test/test-results-self.md`, and capture counter or latency expectations in the relevant design document under `docs/`.

## Commit & Pull Request Guidelines
Use `<type>: <summary>` commit subjects (`feat`, `refactor`, `refine`, etc.) under 72 characters. In commit bodies and PR descriptions, note affected collectors, kernel versions, and executed validation commands. Reference updated documentation, link any follow-up tasks, and highlight items that might impact the remote executor or pinned kernel snapshot.

## Security & Environment Notes
Most collectors require sudo to attach eBPF programs; never run them on production hosts without approval. Scrub host IPs before sharing logs captured from `test/performance-test-cases.txt`. When bumping the kernel snapshot, document the upstream release and revalidate critical latency probes before merging.
>>>>>>> f4bf5d6 (feat: update git ignore)
