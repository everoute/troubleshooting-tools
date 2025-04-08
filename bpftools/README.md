# BPF Tools (using bcc/Python)

This directory contains tools built using the **bcc** framework (BPF Compiler Collection) with Python bindings. These tools leverage eBPF for kernel tracing and monitoring.

## `multi-protocol-drop-monitor.py`

**Functionality:**

*   Monitors packet drops in the kernel by tracing the `kfree_skb` function.
*   Uses eBPF to capture information about dropped packets.
*   Allows filtering based on:
    *   Source IP address (`--src`)
    *   Destination IP address (`--dst`)
    *   Protocol (`--protocol`: all, icmp, tcp, udp)
    *   Source port (`--src-port`, for TCP/UDP)
    *   Destination port (`--dst-port`, for TCP/UDP)
*   Outputs detailed information for each matching dropped packet, including:
    *   Timestamp
    *   Process ID (PID) and Command Name
    *   Source and Destination IP Addresses
    *   IP ID
    *   VLAN ID (if present)
    *   Protocol (TCP, UDP, ICMP, etc.)
    *   Source and Destination Ports (for TCP/UDP)
    *   ICMP Type and Code (for ICMP)
    *   Network Interface Name
    *   Kernel and User stack traces (if successfully captured by BPF)
*   Provides an option to log output to a specified file (`--log-file`).
*   Separates the BPF C code into `multi-protocol-drop-monitor.c` for better organization.

**Usage:**

Requires `bcc` tools and Python 2 to be installed. Run with root privileges (or `sudo`).

```bash
# Basic usage (monitor all drops)
sudo python bpftools/multi-protocol-drop-monitor.py

# Monitor TCP drops to destination IP 192.168.1.100, port 80
sudo python bpftools/multi-protocol-drop-monitor.py --dst 192.168.1.100 --protocol tcp --dst-port 80

# Monitor ICMP drops from source IP 10.0.0.5 and log to a file
sudo python bpftools/multi-protocol-drop-monitor.py --src 10.0.0.5 --protocol icmp --log-file /var/log/dropped_icmp.log

# Monitor UDP drops between specific IPs and ports
sudo python bpftools/multi-protocol-drop-monitor.py --src 192.168.10.5 --dst 192.168.10.10 --protocol udp --src-port 5000 --dst-port 5001
```

Press Ctrl+C to stop monitoring.

## `storage-network-monitor.py`

**Functionality:**

*   Monitors network I/O activity, likely focusing on traffic patterns associated with storage protocols (e.g., iSCSI, NFS) or specific ports.
*   May provide metrics like latency, throughput, or error counts for monitored storage-related connections.

**Usage:**

```bash
# Monitor storage network activity (check script --help for specific filters)
sudo python bpftools/storage-network-monitor.py [options]
```

## `trace_ip_defrag.py`

**Functionality:**

*   Traces IP packet defragmentation events within the kernel (`ip_defrag` function and related points).
*   Helps diagnose issues with fragmented packets, such as reassembly failures or performance problems.
*   Outputs information about packets undergoing defragmentation.

**Usage:**

```bash
# Trace IP defragmentation events (check script --help for filters)
sudo python bpftools/trace_ip_defrag.py [options]
```

## `ovs-clone-execute-summary.py`

**Functionality:**

*   Monitors Open vSwitch (OVS) datapath actions, specifically focusing on `clone` and `execute` operations.
*   Provides summarized statistics about these actions, helping to understand OVS flow processing and performance.

**Usage:**

```bash
# Summarize OVS clone/execute actions (check script --help for options)
sudo python bpftools/ovs-clone-execute-summary.py [options]
```

## `ovs-kernel-module-drop-monitor.py`

**Functionality:**

*   Monitors packet drops occurring specifically within the Open vSwitch (OVS) kernel module.
*   Traces potential drop locations within OVS code to pinpoint reasons for packet loss.
*   Likely allows filtering based on OVS-specific details (e.g., ports).

**Usage:**

```bash
# Monitor packet drops within the OVS kernel module (check script --help for filters)
sudo python bpftools/ovs-kernel-module-drop-monitor.py [options]
```

## `packet_datapath_tracing.py`

**Functionality:**

*   Provides a general mechanism to trace the journey of packets through the kernel's network datapath.
*   Attaches probes to various network stack functions (receive, forward, transmit) to visualize the path and potential bottlenecks or drop points.
*   Allows filtering by packet characteristics (IP, port, protocol).

**Usage:**

```bash
# Trace packet datapath (use --help for detailed filter options)
sudo python bpftools/packet_datapath_tracing.py --host <IP_address> [--dport <port>] [--proto <tcp|udp|icmp>]
``` 