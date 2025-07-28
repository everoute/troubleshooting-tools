# VM Network Latency Measurement Tool

A comprehensive eBPF-based tool for measuring end-to-end and segment latencies in KVM virtualization environments. This tool tracks network packet transmission latency across the complete VM network data path.

## Features

- **Multi-Protocol Support**: TCP, UDP, and ICMP with protocol-specific flow identification
- **Complete Path Coverage**: Tracks packets from VM through TUN devices, OVS, to physical NICs
- **Flexible Filtering**: Filter by IP addresses, ports, protocol, direction, and latency thresholds  
- **Dual Output Modes**: Real-time detailed events or statistical histogram distributions
- **Segment Analysis**: Measures latency between different stages of the network path
- **High Performance**: Uses in-kernel aggregation and efficient BPF maps

## Architecture

### Data Path Coverage

**TX Path (VM → Network):**
1. `tun_net_xmit` - VM packet transmission start
2. `ovs_dp_process_packet` - OVS datapath processing
3. `__dev_queue_xmit` - Physical device transmission

**RX Path (Network → VM):**
1. `__netif_receive_skb` - Physical device reception
2. `ovs_dp_process_packet` - OVS datapath processing  
3. `tun_net_xmit` - TUN device transmission to VM
4. Protocol handlers (`tcp_v4_rcv`, `udp_rcv`, `icmp_rcv`) - Final delivery

### Flow Identification

- **TCP/UDP**: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
- **ICMP**: 3-tuple (src_ip, dst_ip, icmp_id) with sequence tracking

## Requirements

- Linux kernel with eBPF support (4.9+)
- BCC (BPF Compiler Collection) 
- Python 2.7+
- Root privileges for eBPF program loading
- KVM virtualization environment with TUN/TAP devices

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd troubleshooting-tools/bcc-tools/performance/vm-network/

# Make executable
chmod +x vm_network_latency.py test_vm_latency.sh

# Run test script (optional)
sudo ./test_vm_latency.sh
```

## Usage

### Basic Examples

```bash
# Monitor TCP traffic between specific VMs
sudo ./vm_network_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                             --protocol tcp --dst-port 80

# Monitor all UDP traffic with histogram output
sudo ./vm_network_latency.py --protocol udp --mode histogram --interval 5

# Monitor ICMP ping latency
sudo ./vm_network_latency.py --protocol icmp --src-ip 192.168.1.10

# Filter high-latency packets only (>100μs)
sudo ./vm_network_latency.py --latency-threshold 100 --timeout 30

# Monitor specific direction only
sudo ./vm_network_latency.py --direction tx --protocol tcp --dst-port 80
```

### Command Line Options

```
--src-ip IP            Source IP filter
--dst-ip IP            Destination IP filter  
--src-port PORT        Source port filter (TCP/UDP)
--dst-port PORT        Destination port filter (TCP/UDP)
--protocol PROTO       Protocol filter (tcp/udp/icmp)
--direction DIR        Traffic direction (tx/rx/both)
--vm-dev DEVICE        VM network device name
--phy-dev DEVICE       Physical network device name
--mode MODE            Output mode (detailed/histogram)
--interval SECONDS     Histogram update interval (default: 5)
--latency-threshold N  Minimum latency threshold in microseconds
--verbose              Enable verbose debug output
--timeout SECONDS      Run for specified duration (0 = forever)
```

## Output Formats

### Detailed Mode (Default)

Shows individual packet latency events with full path breakdown:

```
[12:34:56.789] TCP 192.168.1.10:8080 -> 192.168.1.20:80 TX
  TUN_XMIT: 123.45μs | OVS_DP: 234.56μs | DEV_QUEUE: 345.67μs
  Total Latency: 703.68μs | PID: 1234 (qemu-kvm)
```

### Histogram Mode

Provides statistical distribution of latencies across different path segments:

```
Latency Distribution (μs) - TCP TX Path:
Stage: TUN_XMIT -> OVS_DP
  [10-20)    : ████████████████████ 1,024
  [20-50)    : ████████████ 512  
  [50-100)   : ████ 128
  [100-200)  : ██ 64

Percentiles: P50=15.2μs P90=45.8μs P99=89.1μs
```

## Performance Considerations

- **Production Impact**: Monitor BPF program overhead in high-traffic environments
- **Memory Usage**: Large numbers of concurrent flows consume kernel memory
- **Filtering**: Use specific filters to reduce event volume and overhead
- **Sampling**: Consider using latency thresholds for high-volume scenarios

## Troubleshooting

### Common Issues

1. **BPF Load Failures**:
   ```bash
   # Check kernel BPF support
   zgrep CONFIG_BPF /proc/config.gz
   
   # Verify BCC installation
   python2 -c "from bcc import BPF"
   ```

2. **No Events Captured**:
   - Verify traffic is flowing through monitored interfaces
   - Check filter parameters (IPs, ports, protocols)
   - Ensure VM uses TUN/TAP devices (not SR-IOV)

3. **High Overhead**:
   - Add more specific filtering (IP ranges, port ranges)
   - Use histogram mode instead of detailed mode
   - Increase latency threshold to reduce event volume

### Debugging

Enable verbose mode for additional diagnostic information:

```bash
sudo ./vm_network_latency.py --verbose --protocol tcp --timeout 10
```

## Integration with Testing

The tool integrates with the existing test framework:

```bash
# Deploy to test environment
scp vm_network_latency.py smartx@192.168.70.33:/home/smartx/lcc/vm-latency-test/

# Run remote testing
ssh smartx@192.168.70.33
sudo ./vm_network_latency.py --protocol tcp --mode histogram --interval 10
```

## Limitations

- **tun_get_user Support**: Complex iov_iter parsing not yet implemented
- **OVS Upcall Path**: Optional probe points may not be available in all kernels
- **SR-IOV Devices**: Tool focuses on virtualized TUN/TAP path, not hardware passthrough
- **Container Networks**: Designed for KVM VMs, not container networking

## Development

### Adding New Probe Points

1. Add probe function to `probe_functions` list
2. Implement `kprobe__function_name` handler
3. Update stage definitions and flow tracking logic
4. Test with actual traffic scenarios

### Extending Protocol Support

1. Add protocol parsing in `parse_packet_key()`
2. Define appropriate flow key structure
3. Update filtering logic for new protocol
4. Add protocol-specific handlers if needed

## See Also

- [icmp_rtt_latency.py](../system-network/icmp_rtt_latency.py) - ICMP-specific latency measurement
- [BCC Documentation](https://github.com/iovisor/bcc) - BPF Compiler Collection
- [Linux Network Stack](https://wiki.linuxfoundation.org/networking/kernel_flow) - Kernel networking overview