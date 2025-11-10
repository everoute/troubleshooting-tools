# Kernel ICMP RTT Tracer Guide

## Overview

`kernel_icmp_rtt.py` is a simplified eBPF-based tool for tracing ICMP packet round-trip latency through the Linux kernel network stack **without OVS layer**. This tool is designed for environments where ICMP packets go directly through the kernel protocol stack to/from physical interfaces.

## Use Cases

- Measure ICMP RTT in non-virtualized environments
- Trace ICMP packets in bare-metal or container setups without OVS
- Debug kernel network stack latency issues
- Analyze ping performance at kernel level

## Architecture

### Trace Stages

The tool traces ICMP packets through 6 kernel stages (3 for each path):

#### TX Mode (Local pings Remote)

**Path 1 - Request (Outgoing):**
- Stage 0: `ip_send_skb` - ICMP request enters IP layer
- Stage 1: `ip_local_out` - IP packet output processing
- Stage 2: `dev_queue_xmit` - Packet queued to network device

**Path 2 - Reply (Incoming):**
- Stage 3: `__netif_receive_skb` - Packet received from network device
- Stage 4: `ip_rcv` - IP layer receives packet
- Stage 5: `icmp_rcv` - ICMP layer processes reply

#### RX Mode (Remote pings Local)

**Path 1 - Request (Incoming):**
- Stage 0: `__netif_receive_skb` - Packet received from network device
- Stage 1: `ip_rcv` - IP layer receives packet
- Stage 2: `icmp_rcv` - ICMP layer processes request

**Path 2 - Reply (Outgoing):**
- Stage 3: `ip_send_skb` - ICMP reply enters IP layer
- Stage 4: `ip_local_out` - IP packet output processing
- Stage 5: `dev_queue_xmit` - Packet queued to network device

### Comparison with system_network_icmp_rtt.py

| Feature | kernel_icmp_rtt.py | system_network_icmp_rtt.py |
|---------|-------------------|---------------------------|
| **Stages** | 6 (3 per path) | 14 (7 per path) |
| **OVS Support** | No | Yes |
| **Use Case** | Direct kernel stack | OVS-based virtualization |
| **Complexity** | Simple | Complex |
| **Probe Points** | 6 kernel functions | 9 kernel functions |
| **Parameters** | Simpler (single interface) | More complex (dual interfaces) |

## Usage

### Basic Syntax

```bash
sudo ./kernel_icmp_rtt.py --src-ip <local_ip> --dst-ip <remote_ip> \
                          [--interface <iface>] [--direction {tx,rx}] \
                          [--latency-ms <threshold>] [--disable-kernel-stacks]
```

### Parameters

- `--src-ip`: Local IP address (required)
  - TX mode: Source IP of ICMP request
  - RX mode: Destination IP of ICMP request (local host)

- `--dst-ip`: Remote IP address (required)
  - TX mode: Destination IP of ICMP request
  - RX mode: Source IP of ICMP request (remote host)

- `--interface`: Network interface to monitor (optional)
  - If not specified, monitors all interfaces
  - Example: `eth0`, `ens3`, `ens11`

- `--direction`: Trace direction (default: tx)
  - `tx`: Local host pings remote (outgoing request)
  - `rx`: Remote host pings local (incoming request)

- `--latency-ms`: Minimum RTT threshold in milliseconds (default: 0)
  - Only report round trips exceeding this threshold
  - Useful for filtering high-latency events

- `--disable-kernel-stacks`: Disable kernel stack trace output
  - Reduces output verbosity
  - Stack traces helpful for debugging kernel path

### Examples

#### Example 1: TX Mode - Local pings Remote

Monitor ICMP requests from local host (192.168.1.10) to remote (192.168.1.20):

```bash
sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                          --interface eth0 --direction tx
```

Then from another terminal:
```bash
ping 192.168.1.20
```

#### Example 2: RX Mode - Remote pings Local

Monitor ICMP requests from remote host (192.168.1.20) to local (192.168.1.10):

```bash
sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                          --interface eth0 --direction rx
```

Then from the remote host (192.168.1.20):
```bash
ping 192.168.1.10
```

#### Example 3: High Latency Filtering

Only report ICMP round trips with RTT >= 10ms:

```bash
sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                          --interface eth0 --latency-ms 10
```

#### Example 4: Monitor All Interfaces

Omit `--interface` to monitor all network interfaces:

```bash
sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                          --direction tx
```

#### Example 5: Minimal Output (No Stack Traces)

```bash
sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                          --interface eth0 --disable-kernel-stacks
```

## Output Format

### Sample Output

```
=== Kernel ICMP RTT Tracer ===
Trace Direction: TX
SRC_IP_FILTER (Local IP): 192.168.1.10 (0xc0a8010a)
DST_IP_FILTER (Remote IP): 192.168.1.20 (0xc0a80114)
Monitoring interface: eth0 (ifindex 2)

Tracing ICMP RTT (src=192.168.1.10, dst=192.168.1.20, dir=tx) ... Hit Ctrl-C to end.

================================================================================
=== ICMP RTT Trace: 2025-01-07 10:30:45.123 (TX (Local -> Remote)) ===
Session: 192.168.1.10 -> 192.168.1.20 (ID: 1234, Seq: 1)
Path 1 (Request: TX to 192.168.1.20)     : PID=5678   COMM=ping         IF=eth0       ICMP_Type=8
Path 2 (Reply:   RX from 192.168.1.20)   : PID=0      COMM=swapper/0    IF=eth0       ICMP_Type=0

SKB Pointers:
  Stage 0 (P1:S0 (ip_send_skb)                    ): 0xffff88800abc1234
  Stage 1 (P1:S1 (ip_local_out)                   ): 0xffff88800abc1234
  Stage 2 (P1:S2 (dev_queue_xmit)                 ): 0xffff88800abc1234
  Stage 3 (P2:S0 (__netif_receive_skb)            ): 0xffff88800def5678
  Stage 4 (P2:S1 (ip_rcv)                         ): 0xffff88800def5678
  Stage 5 (P2:S2 (icmp_rcv)                       ): 0xffff88800def5678

Path 1 Latencies (us):
  [0->1] P1:S0 (ip_send_skb)                       -> P1:S1 (ip_local_out)                      :  12.345 us
  [1->2] P1:S1 (ip_local_out)                      -> P1:S2 (dev_queue_xmit)                    :  23.456 us
  Total Path 1:  35.801 us

Path 2 Latencies (us):
  [3->4] P2:S0 (__netif_receive_skb)               -> P2:S1 (ip_rcv)                            :   8.123 us
  [4->5] P2:S1 (ip_rcv)                            -> P2:S2 (icmp_rcv)                          :   4.567 us
  Total Path 2:  12.690 us

Total RTT (Path1 Start to Path2 End): 1048.491 us
Inter-Path Latency (P1 end -> P2 start): 1000.000 us

Kernel Stack Traces:
  Stage 0 (P1:S0 (ip_send_skb)):
    ip_send_skb+0x1
    ip_push_pending_frames+0xab
    raw_sendmsg+0x123
    ...
  ...
================================================================================
```

### Output Fields Explained

- **Session Info**: Source/destination IPs, ICMP ID and sequence number
- **Path Info**: Process info (PID, COMM) and interface for each path
- **SKB Pointers**: Kernel socket buffer addresses at each stage (useful for cross-referencing)
- **Latencies**: Time spent between consecutive stages
  - Path 1 latencies: Request path processing time
  - Path 2 latencies: Reply path processing time
  - Total RTT: Complete round-trip time
  - Inter-Path Latency: Network transmission time between paths
- **Kernel Stack Traces**: Call stack at each probe point (if enabled)

## Performance Considerations

- **Overhead**: Minimal overhead for typical ping workloads
- **High-frequency ICMP**: May introduce noticeable overhead with very high ping rates (>1000 pps)
- **Stack traces**: Disable with `--disable-kernel-stacks` to reduce overhead
- **Filtering**: Use `--latency-ms` to reduce event processing

## Troubleshooting

### Tool doesn't capture events

1. **Check IP addresses**: Ensure `--src-ip` and `--dst-ip` match the actual ping IPs
2. **Check direction**: Use `tx` if pinging from local host, `rx` if pinged from remote
3. **Check interface**: Verify interface name with `ip link` or omit `--interface`
4. **Check ping is running**: Ensure ping command is actively sending packets

### BPF loading errors

1. **Kernel version**: Requires kernel 4.1+ with BPF support
2. **Missing functions**: Some kernel functions may not exist in older kernels
3. **BCC installation**: Ensure `python-bcc` or `python3-bcc` is installed

### Incomplete traces

If you see partial traces (only Path 1 or Path 2):
- **Network issues**: Reply may not be received
- **Filtering**: Check if `--latency-ms` threshold is too high
- **Interface mismatch**: Request and reply may use different interfaces

## Integration with Test Framework

The tool can be integrated into the test framework:

```yaml
# test/workflow/spec/kernel-icmp-test-spec.yaml
test_topic: kernel-icmp
tool:
  name: kernel_icmp_rtt.py
  path: ebpf-tools/performance/system-network/kernel_icmp_rtt.py
parameters:
  - name: src_ip
    type: string
    values: ["10.132.114.11"]
  - name: dst_ip
    type: string
    values: ["10.132.114.12"]
  - name: interface
    type: string
    values: ["ens11"]
  - name: direction
    type: string
    values: ["tx", "rx"]
```

## Related Tools

- **system_network_icmp_rtt.py**: Full-featured ICMP RTT tracer with OVS support
- **system_network_performance_metrics.py**: TCP/UDP performance metrics
- **kernel_drop_stack_stats_summary.py**: Packet drop analysis

## References

- Kernel probe points: `ip_send_skb`, `ip_local_out`, `dev_queue_xmit`, `__netif_receive_skb`, `ip_rcv`, `icmp_rcv`
- BCC documentation: https://github.com/iovisor/bcc
- Linux ICMP implementation: `net/ipv4/icmp.c`
