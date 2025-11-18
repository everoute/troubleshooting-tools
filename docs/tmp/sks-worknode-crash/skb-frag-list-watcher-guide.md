# SKB frag_list Watcher - Usage Guide

## Overview

`skb_frag_list_watcher.py` is a BCC-based eBPF tool that traces all modifications to `sk_buff->frag_list` in the Linux kernel network stack. This tool is specifically designed to debug GSO (Generic Segmentation Offload) crashes caused by inconsistent `frag_list` state, such as the `skb_segment` crash where `frag_list` is NULL but GSO parameters indicate otherwise.

**Target Issue**: `skb_segment` crash at line 4263 due to NULL `frag_list` with non-zero `gso_size`

## What It Does

The tool monitors these critical operations:

### 1. frag_list Creation
- **`skb_gro_receive_list`**: Creates frag_list during GRO (Generic Receive Offload) aggregation

### 2. frag_list Clearing
- **`skb_segment_list`**: Clears frag_list during fragment list segmentation
- **`__skb_linearize`**: Clears frag_list during linearization
- **`pskb_expand_head`**: May affect frag_list during header expansion

### 3. frag_list Access
- **`skb_segment`**: Accesses frag_list during GSO segmentation (the crash point)

### 4. Inconsistent State Detection
Automatically detects dangerous conditions:
- frag_list is NULL
- gso_size > 0 or gso_type != 0
- nr_frags = 0 and data_len = 0
- **This is the exact condition that triggers the crash**

## Installation

### Prerequisites
```bash
# CentOS/RHEL
sudo yum install bcc-tools python3-bcc kernel-devel

# Or if using python2-bcc
sudo yum install python2-bcc

# Ubuntu/Debian
sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

### Verify Installation
```bash
# Check if BCC is installed
python3 -c "from bcc import BPF; print('BCC OK')"

# Check if kernel functions exist
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep -E "skb_gro_receive_list|skb_segment|pskb_expand_head"
```

## Usage

### Basic Usage

#### 1. Monitor All frag_list Changes
```bash
sudo python skb_frag_list_watcher.py
```

Output:
```
TIME               CPU EVENT        FUNCTION             | SKB                | CHANGE
----------------------------------------------------------------------------------------------------
14:23:45.123       2   CREATE       skb_gro_receive_list | 0xffff888abc123000 | NULL -> 0xffff888def456000
14:23:45.125       2   CLEAR        skb_segment_list     | 0xffff888abc123000 | 0xffff888def456000 -> NULL [!!]
14:23:45.126       2   INCONSISTENT skb_segment          | 0xffff888abc123000 | 0x0 (no change) [CRITICAL]
```

#### 2. Filter by GSO Packets Only
```bash
sudo python skb_frag_list_watcher.py --gso-only
```

This filters out non-GSO traffic, focusing only on packets with `gso_size > 0`.

#### 3. Filter by Source IP
```bash
sudo python skb_frag_list_watcher.py --src-ip 10.132.114.11
```

Useful for isolating traffic from a specific sender.

#### 4. Filter by Destination IP
```bash
sudo python skb_frag_list_watcher.py --dst-ip 10.132.114.12
```

#### 5. Filter by Network Interface
```bash
sudo python skb_frag_list_watcher.py --interface ens11
```

Monitor only packets on a specific interface.

#### 6. Verbose Output with Full Details
```bash
sudo python skb_frag_list_watcher.py --verbose
```

Output includes:
- Full GSO type flags (DODGY, UDP_TUNNEL, PARTIAL, etc.)
- Packet flow (src_ip:port -> dst_ip:port)
- Length information (len, data_len, nr_frags)
- SKB flags (cloned, slow_gro)

Example verbose output:
```
TIME               CPU COMM             PID     FUNCTION                 | SKB                | FRAG_LIST            | GSO_INFO
--------------------------------------------------------------------------------------------------------------------------------
14:23:45.123       2   ksoftirqd/2      25      skb_gro_receive_list    | 0xffff888abc123000 | NULL -> 0xdef456000  | type=DODGY|UDP_TUNNEL|PARTIAL size=1348 segs=0
  -> Flow: 10.132.114.11:5201 -> 10.132.114.12:35678 | len=10 data_len=0 nr_frags=0 cloned=0 gro=1
```

#### 7. With Kernel Stack Traces
```bash
sudo python skb_frag_list_watcher.py --stack-trace
```

**Warning**: This adds significant overhead. Use only when you need to see the call path.

Example with stack:
```
14:23:45.125       2   CLEAR        pskb_expand_head     | 0xffff888abc123000 | 0xdef456000 -> NULL [!!]
        pskb_expand_head+0x123
        ip_forward+0x456
        ip_rcv+0x789
        __netif_receive_skb_core+0xabc
```

### Combined Filters

#### Track Specific Traffic Flow
```bash
sudo python skb_frag_list_watcher.py \
    --src-ip 10.132.114.11 \
    --dst-ip 10.132.114.12 \
    --interface ens11 \
    --gso-only \
    --verbose
```

#### Debug in Production (Minimal Overhead)
```bash
sudo python skb_frag_list_watcher.py \
    --src-ip 10.132.114.11 \
    --gso-only
```

## Output Interpretation

### Event Types

| Event Type     | Meaning | Severity |
|----------------|---------|----------|
| CREATE         | frag_list was created (NULL -> addr) | Normal |
| CLEAR          | frag_list was cleared (addr -> NULL) | **Check if expected** |
| MODIFY         | frag_list pointer changed (addr1 -> addr2) | Unusual |
| ACCESS         | Accessed frag_list when NULL | **Warning** |
| INCONSISTENT   | NULL frag_list with GSO params set | **CRITICAL** |

### Markers

| Marker      | Meaning |
|-------------|---------|
| `[!!]`      | frag_list cleared - monitor for GSO inconsistency |
| `[WARNING]` | frag_list is NULL but gso_size > 0 |
| `[CRITICAL]`| Dangerous state - likely to crash in skb_segment |

### GSO Type Flags

Common combinations:

| Flag Combination | Meaning |
|------------------|---------|
| DODGY \| UDP_TUNNEL \| PARTIAL | VXLAN/GRO packet with partial GSO |
| TCPV4 | TCP over IPv4 GSO |
| TCPV6 | TCP over IPv6 GSO |
| UDP_L4 \| FRAGLIST | UDP with fragment list GSO |
| GRE \| GRE_CSUM | GRE tunnel with checksum |

## Troubleshooting Crash Scenario

### Scenario: skb_segment Crash

**Symptoms**:
- Kernel panic in `skb_segment+558`
- `list_skb` (frag_list) is NULL
- `gso_size = 1348`, `gso_type = 1027` (non-zero)

**Investigation Steps**:

#### Step 1: Capture the Problem
```bash
# Run with filters matching your crash scenario
sudo python skb_frag_list_watcher.py \
    --src-ip <source_ip_from_vmcore> \
    --gso-only \
    --verbose \
    > /tmp/frag_list_trace.log 2>&1 &
```

#### Step 2: Reproduce the Issue
Trigger the workload that causes the crash.

#### Step 3: Analyze the Output
Look for this pattern:
```
14:23:45.123  2  CREATE       skb_gro_receive_list  | 0xffff888abc123000 | NULL -> 0xdef456000
14:23:45.124  2  CLEAR        pskb_expand_head      | 0xffff888abc123000 | 0xdef456000 -> NULL [!!]
14:23:45.125  2  INCONSISTENT skb_segment           | 0xffff888abc123000 | 0x0 (no change) [CRITICAL]
```

**This tells you**:
1. frag_list was created by GRO at 14:23:45.123
2. frag_list was **unexpectedly cleared** by `pskb_expand_head` at 14:23:45.124
3. `skb_segment` tried to access it at 14:23:45.125 → CRASH

#### Step 4: Identify Root Cause

Common causes:

**1. pskb_expand_head Clearing frag_list**
```
CLEAR event in pskb_expand_head
```
→ Header expansion during IP forwarding corrupts frag_list
→ **Fix**: Ensure pskb_expand_head preserves frag_list properly

**2. Unexpected Linearization**
```
CLEAR event in __skb_linearize
```
→ Forced linearization clears frag_list but doesn't reset GSO params
→ **Fix**: Call `skb_gso_reset()` after linearization

**3. Tunnel Decapsulation Issue**
```
Multiple MODIFY events between tunnel functions
```
→ VXLAN/GRE decapsulation doesn't properly handle inner/outer skb state
→ **Fix**: Fix tunnel segmentation code

#### Step 5: Use Stack Traces for Exact Call Path
```bash
sudo python skb_frag_list_watcher.py \
    --src-ip <source_ip> \
    --stack-trace \
    --gso-only
```

Find the exact calling sequence that leads to frag_list corruption.

## Performance Considerations

### Overhead Levels

| Configuration | Overhead | Use Case |
|---------------|----------|----------|
| Basic | Low | Production monitoring |
| `--gso-only` | Very Low | Production debugging |
| `--verbose` | Low-Medium | Detailed analysis |
| `--stack-trace` | High | Root cause analysis |
| All filters | Very Low | Targeted investigation |

### Best Practices

1. **Always use filters in production**:
   - Use `--gso-only` to reduce noise
   - Use `--src-ip` or `--dst-ip` to isolate specific flows
   - Use `--interface` to monitor specific NICs

2. **Start broad, then narrow**:
   ```bash
   # Step 1: See if problem exists
   sudo python skb_frag_list_watcher.py --gso-only | grep INCONSISTENT

   # Step 2: Focus on problematic SKB
   sudo python skb_frag_list_watcher.py --src-ip <ip> --verbose

   # Step 3: Get stack trace
   sudo python skb_frag_list_watcher.py --src-ip <ip> --stack-trace
   ```

3. **Save output for analysis**:
   ```bash
   sudo python skb_frag_list_watcher.py --verbose > /tmp/trace_$(date +%s).log 2>&1
   ```

## Statistics

When you exit (Ctrl-C), the tool prints statistics:

```
--- Statistics ---
Total events:       145
  CREATE events:    25
  CLEAR events:     24
  ACCESS events:    1
  INCONSISTENT:     1    ← This is the problem!
  Filtered out:     1234
```

**Key metrics**:
- **INCONSISTENT > 0**: You have the exact bug condition
- **CLEAR events >> CREATE events**: Unexpected frag_list clearing
- **ACCESS events**: Dangerous NULL accesses

## Common Workflows

### Workflow 1: Confirm the Bug Exists
```bash
sudo python skb_frag_list_watcher.py --gso-only | grep INCONSISTENT
```

If you see output → bug confirmed

### Workflow 2: Find Which Function Clears frag_list
```bash
sudo python skb_frag_list_watcher.py --gso-only --verbose | grep "-> NULL"
```

Look at the FUNCTION column to identify the culprit.

### Workflow 3: Reproduce and Capture Full Context
```bash
# Terminal 1: Start tracing
sudo python skb_frag_list_watcher.py \
    --src-ip 10.132.114.11 \
    --verbose \
    > /tmp/frag_list_full_trace.log 2>&1

# Terminal 2: Reproduce the issue
# (run your workload)

# Terminal 1: Stop tracing (Ctrl-C)
# Analyze /tmp/frag_list_full_trace.log
```

### Workflow 4: Identify the Calling Context
```bash
sudo python skb_frag_list_watcher.py \
    --src-ip 10.132.114.11 \
    --stack-trace | tee /tmp/trace_with_stack.log
```

## Integration with Analysis Report

This tool directly addresses the monitoring requirements from the analysis report:

| Report Section | Tool Feature |
|----------------|--------------|
| **3.1.2 清除 frag_list** | Traces all CLEAR events with function name |
| **3.2.1 设置 GSO 参数** | Shows gso_size, gso_segs, gso_type changes |
| **5.2 可能的异常路径** | Detects all 3 hypothesized paths |
| **6.2 必须 Hook 的关键函数** | Hooks all 5 critical functions |
| **6.3 需要记录的信息** | Records all required metadata |

## Limitations

1. **Kernel Version**: Requires Linux kernel with eBPF support (4.1+)
2. **Probe Points**: Requires the monitored functions to exist in the kernel
3. **BTF**: Works without BTF (uses direct memory access)
4. **Overhead**: Stack traces add ~20-30% overhead

## Troubleshooting the Tool

### Error: "Neither bcc nor bpfcc module found"
```bash
# Install BCC
sudo yum install python3-bcc
# or
sudo apt-get install python3-bpfcc
```

### Error: "Cannot attach kprobe"
Check if the function exists:
```bash
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep skb_segment
```

If missing, your kernel may have a different function name or the function is inlined.

### No Output
Check filters:
- Remove `--gso-only` to see if any packets match
- Remove IP filters to see all traffic
- Check if the interface name is correct

### Tool Crashes
Increase memory limits:
```bash
ulimit -l unlimited
sudo python skb_frag_list_watcher.py
```

## Example Output Analysis

### Example 1: Normal GRO/GSO Flow
```
14:23:45.123  2  CREATE   skb_gro_receive_list   | 0xffff888abc123000 | NULL -> 0xdef456000
14:23:45.456  2  CLEAR    skb_segment_list       | 0xffff888abc123000 | 0xdef456000 -> NULL [!!]
```
→ Normal: GRO created frag_list, then properly segmented it

### Example 2: The Bug
```
14:23:45.123  2  CREATE   skb_gro_receive_list   | 0xffff888abc123000 | NULL -> 0xdef456000
14:23:45.124  2  CLEAR    pskb_expand_head       | 0xffff888abc123000 | 0xdef456000 -> NULL [!!]
14:23:45.125  2  INCONSISTENT skb_segment        | 0xffff888abc123000 | 0x0 [CRITICAL]
```
→ **BUG**: pskb_expand_head unexpectedly cleared frag_list, causing skb_segment to access NULL

### Example 3: Linearization
```
14:23:45.123  2  CREATE   skb_gro_receive_list   | 0xffff888abc123000 | NULL -> 0xdef456000
14:23:45.200  2  CLEAR    __skb_linearize        | 0xffff888abc123000 | 0xdef456000 -> NULL [!!]
```
→ Check if linearization was expected; if not, investigate why it was triggered

## Next Steps After Identifying Root Cause

1. **Develop Kernel Patch**:
   - Based on the function identified (pskb_expand_head, etc.)
   - Ensure frag_list is preserved or GSO params are reset

2. **Test Patch**:
   - Run this tool again with the patch applied
   - Verify INCONSISTENT events disappear

3. **Submit Upstream**:
   - Include this tool's output as proof of the bug
   - Show before/after statistics

---

**Author**: Automated kernel crash analysis tooling
**Version**: 1.0
**Last Updated**: 2025-11-07
**Target Kernel**: Linux 4.18.0-553.47.1.el8_10
