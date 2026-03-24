# VM ICMP E2E Tools Bundle

This bundle is for host-side troubleshooting of VM ICMP latency.

## Included scripts

- `measurement-tools/performance/vm-network/vm_icmp_e2e_latency_aggregator.py`
- `measurement-tools/boundary-detection/vm-network/icmp_path_tracer.py`
- `measurement-tools/kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py`
- `measurement-tools/kvm-virt-network/tun/tun_tx_to_kvm_irq.py`
- `run_vm_icmp_e2e.sh` (entrypoint wrapper)

## Requirements

- Linux host with root/sudo
- Python 3
- BCC (`python3-bcc` or `python3-bpfcc`)
- Target scripts must be supported by the host kernel symbols

## Quick start

```bash
chmod +x run_vm_icmp_e2e.sh
./run_vm_icmp_e2e.sh --help
```

Basic run:

```bash
./run_vm_icmp_e2e.sh \
  --src-ip 192.168.70.33 --dst-ip 192.168.75.80 \
  --src-iface enp24s0f0np0 --dst-iface vnet238 \
  --interval 5
```

If you only need end-to-end ICMP path stats:

```bash
./run_vm_icmp_e2e.sh \
  --src-ip 192.168.70.33 --dst-ip 192.168.75.80 \
  --src-iface enp24s0f0np0 --dst-iface vnet238 \
  --disable-vhost --disable-irq
```

## Notes

- `src-iface` / `dst-iface` are host interfaces seen by the packet path.
- For same-host VM-to-VM traffic, usually use corresponding `vnet*` interfaces.
- For cross-host traffic, `src-iface` may be physical NIC and `dst-iface` may be `vnet*` on this host.
