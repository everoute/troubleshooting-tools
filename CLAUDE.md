# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Memory File Structure

This is the main Claude configuration file. Additional context-specific memory files:

- `claude_local_project_overview.md` - Project overview
- `claude_local_coding.md` - BPF/BCC coding guidelines and conventions
- `claude_local_test.md` - Testing procedures and environment setup

## Project Overview

This is an **eBPF-based network troubleshooting and performance analysis toolset** for virtualized environments. The repository contains two major components:

1. **eBPF Tools** (`ebpf-tools/`): Production-ready monitoring tools using BCC and bpftrace
2. **Traffic Analyzer** (under development): Python-based PCAP and TCP socket analysis tools

**Target Environment**: openEuler 4.19.90 kernel, virtualized network infrastructure with OVS

## Quick Reference

### Common Commands

```bash
# Execute BCC tools (requires root/sudo)
sudo python ebpf-tools/linux-network-stack/packet-drop/eth_drop.py
sudo python ebpf-tools/performance/system-network/icmp_rtt_latency.py --src-ip IP1 --dst-ip IP2

# Execute bpftrace scripts
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

# Run test suite (for automated testing framework)
python3 test/workflow/tools/test_case_generator.py --spec test/workflow/spec/performance-test-spec.yaml --output test/workflow/case/performance-test-cases.json
python3 test/workflow/tools/test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance

# Traffic Analyzer (under development)
# Design docs: docs/design/traffic-analyzer/claude/
# Requirements: docs/prd/traffic-analyzer/claude/traffic-analysis-requirements-v3.0.md
```

## Architecture

### eBPF Tools Directory Structure

```
ebpf-tools/
├── linux-network-stack/     # Packet drop monitoring, connection tracking
│   └── packet-drop/         # kfree_skb tracing with stack analysis
├── performance/
│   ├── system-network/      # Host-level network performance (ICMP/TCP/UDP latency)
│   └── vm-network/          # VM network latency decomposition and analysis
├── ovs/                     # Open vSwitch monitoring (megaflow, upcall, drops)
├── kvm-virt-network/        # Virtio/TUN/TAP/vhost monitoring
│   ├── kvm/                 # KVM IRQ injection statistics
│   ├── tun/                 # TUN/TAP device ring buffer and GSO monitoring
│   ├── vhost-net/           # vhost eventfd, queue correlation
│   └── virtio-net/          # virtio-net polling, IRQ monitoring
├── cpu/                     # CPU and scheduler analysis (off-CPU time, futex)
└── other/                   # Additional tracers (ARP, qdisc, connection tracking)
```

### Traffic Analyzer Project (Under Development)

**Location**: Development work happens in separate directories:
- **Design**: `docs/design/traffic-analyzer/claude/`
- **Requirements**: `docs/prd/traffic-analyzer/claude/`
- **Original prototypes**: `traffic-analyzer-original/` (reference implementations)
- **Kimi AI research**: `traffic-analyzer-kimi/` (alternative analysis approaches)

**Two Independent Tools**:
1. **PCAP Analyzer**: Packet-level analysis using tshark (Summary/Details/Analysis modes)
2. **TCP Socket Analyzer**: Kernel socket state analysis from eBPF data (Summary/Detailed/Pipeline modes)

**Key Design Documents**:
- `traffic-analysis-tools-design.md` - Complete HLD/LLD following IEEE 1016
- `traffic-analysis-tools-test-plan.md` - Test strategy and acceptance criteria
- `traffic-analysis-requirements-v3.0.md` - Functional requirements with FR-* IDs

**Development Status**: Design phase complete, implementation not started

## Key Design Patterns

### eBPF Tools Patterns

1. **Tool Arguments**: Consistent argparse pattern across tools
   - `--src-ip`, `--dst-ip`: Source and destination IP addresses
   - `--protocol`: Protocol type (tcp, udp, icmp)
   - `--direction`: Traffic direction (rx, tx)
   - `--phy-interface`: Physical interface name
   - `--vm-interface`: Virtual machine interface name
   - `--debug`: Enable debug output

2. **BCC Import Compatibility**: All tools use fallback pattern for `bcc`/`bpfcc` modules
   ```python
   #!/usr/bin/env python
   try:
       from bcc import BPF
   except ImportError:
       from bpfcc import BPF
   ```

3. **Data Flow**: eBPF kernel program → BPF maps → Python userspace processing → stdout

### Test Framework Pattern

- **Specification-driven**: Test specs (YAML) define parameter matrices
- **Remote execution**: Tools run via SSH on `smartx@172.21.152.82`
- **Results collection**: Stored in `test/workflow/result/`

## Virtualized Network Stack

The tools trace data flow through multiple layers:

```
Application Layer
       ↓
Socket Layer (tcp_sendmsg/tcp_recvmsg)
       ↓
TCP/IP Stack (kernel network stack)
       ↓
OVS Datapath (megaflow, upcall)
       ↓
TUN/TAP Device (vnet interfaces)
       ↓
vhost-net (kernel accelerator)
       ↓
virtio-net (guest driver)
       ↓
VM Network Interface
```

**Root Cause Analysis Methodology**: Tools trace execution paths to identify unexpected data structure/metadata changes affecting control logic at each layer.

## Critical Development Guidelines

### Code Style (BPF/BCC Tools)

**IMPORTANT**: See `claude_local_coding.md` for complete guidelines

Key rules:
- Use `#!/usr/bin/env python` for Python 2/3 compatibility
- **Forbidden**: Emojis in print/log statements
- **Forbidden**: Chinese characters in comments/print/log
- Use concise English comments (max 3 per function)
- BPF stack limit: 512 bytes (use maps for large data structures)
- No BTF support on target systems (use direct memory read/write)

### Documentation Standards

**NEVER create documentation files unless explicitly requested**. This includes:
- No proactive creation of README.md files
- No markdown documentation files
- No design documents without explicit user request

**Exception**: When working on Traffic Analyzer, follow IEEE 1016 (design) and IEEE 830 (requirements) standards as defined in `docs/design/README.md` and `docs/prd/README.md`.

### Testing Requirements

See `claude_local_test.md` for environment details:
- **Virtualization Host**: Physical server testing
- **Virtualization Guest**: VM testing
- Python 2 (el7 with `python-bcc`) or Python 3 (oe1 with `python3-bpfcc`)

## Important Instructions

**Do what has been asked; nothing more, nothing less.**

- ALWAYS prefer editing an existing file to creating a new one
- NEVER proactively create documentation files (*.md) or README files
- All eBPF tools require root access and can impact system performance
- Test in dev environment first - never run untested BPF on production
- Output to stdout by default (use redirection for logging)

## Safety Notes

- **All tools require root access** - can impact system performance
- **BPF stack limit**: 512 bytes - use maps for large data structures
- **Test in dev first** - never run untested BPF programs on production systems
- **Symbol resolution**: Stack traces require kernel debug symbols
- **Performance impact**: Consider overhead when running in production

## Documentation Structure

```
docs/
├── design/                  # Software Design Descriptions (SDD)
│   ├── README.md           # IEEE 1016 standard guidelines
│   ├── traffic-analyzer/   # Traffic analyzer HLD/LLD
│   └── *.md                # Individual tool designs
├── prd/                    # Product Requirements Documents
│   ├── README.md           # IEEE 830 standard guidelines
│   └── traffic-analyzer/   # Traffic analyzer requirements (FR-*/NFR-*)
├── analysis/               # Kernel code analysis and research
├── publish/                # User manuals and deployment guides
└── tmp/                    # Temporary analysis (cpu-cache, crash dumps)
```

## Target Users

1. **Development Team**: Configure tracing parameters, analyze complex execution paths
2. **Field Support Team**: Collect logs following documented procedures, forward to dev team

## Reference Materials

- Kernel source: `kernel-source/` directory (openEuler 4.19.90)
- User manual: `docs/publish/user-manual.md`
- Design standards: `docs/design/README.md` (IEEE 1016)
- Requirements standards: `docs/prd/README.md` (IEEE 830)
