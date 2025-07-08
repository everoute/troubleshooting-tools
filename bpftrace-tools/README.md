# bpftrace Scripts

This directory contains scripts written for the **bpftrace** high-level tracing language. bpftrace provides a simpler syntax for creating eBPF-based tracing tools, often suitable for one-liners or focused scripts.

## `trace-abnormal-arp.bt`

**Functionality:**

*   Traces ARP (Address Resolution Protocol) related kernel functions (`arp_send`, `arp_create`, `arp_process`, `arp_error_handler`).
*   Monitors for potentially abnormal ARP activities or errors.
*   Captures and prints information when these functions are hit, including:
    *   Timestamp
    *   Function name
    *   Process ID (PID) and Command Name
    *   Relevant arguments or context from the traced function (e.g., ARP packet details if available in context).
    *   Kernel stack trace.

**Usage:**

Requires `bpftrace` to be installed. Run with root privileges (or `sudo`).

```bash
# Start tracing abnormal ARP events
sudo bpftrace bpftrace/trace-abnormal-arp.bt
```

Press Ctrl+C to stop tracing.

## `tun-abnormal-gso-type`

**Functionality:**

*   Focuses on monitoring Generic Segmentation Offload (GSO) operations, specifically within the context of TUN/TAP virtual interfaces (often used by VPNs, virtualization, etc.).
*   Likely traces kernel functions involved in TUN/TAP packet processing and GSO handling (e.g., `tun_sendmsg`, `tun_get_user`, functions related to `netif_receive_skb` or segmentation).
*   Aims to detect and report packets passing through TUN interfaces that have unexpected or potentially problematic GSO types or sizes set in their `sk_buff` structure.
*   Prints details about these abnormal packets/events, including:
    *   Timestamp
    *   PID and Command Name
    *   Network interface name (likely the TUN/TAP device)
    *   Packet details (IP addresses, ports if applicable)
    *   The specific GSO type and size detected.
    *   Kernel stack trace leading to the event.

**Usage:**

Requires `bpftrace` to be installed. Run with root privileges (or `sudo`).

```bash
# Start monitoring for abnormal GSO types on TUN interfaces
sudo bpftrace bpftrace/tun-abnormal-gso-type
```

Press Ctrl+C to stop tracing. 