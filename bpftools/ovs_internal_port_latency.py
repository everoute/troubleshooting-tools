#!/usr/bin/python2
# -*- coding: utf-8 -*-

import argparse
from bcc import BPF # KProbe not needed for import
import time
from socket import inet_ntop, AF_INET, inet_aton, htonl
import socket # For protocol constants
import struct # For IP packing/unpacking

# Helper function to convert IP address string to hex int
def ip_to_hex(ip):
    """Converts an IP string (dotted decimal) to its hex integer representation (network byte order)."""
    try:
        packed_ip = inet_aton(ip)
        int_ip = struct.unpack("!I", packed_ip)[0]
        return int_ip
    except socket.error:
        # Use print() function with .format()
        print("Error: Invalid IP address format '{}'".format(ip))
        exit(1)

# Map protocol names to numbers
protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP}

# --- BPF Stage Constants ---
STAGE_PHY_RECV = 1
STAGE_OVS_VPORT_RECV = 2
STAGE_INT_XMIT = 3
STAGE_STACK_DELIVER = 4

def main():
    parser = argparse.ArgumentParser(description="Measure RX path latency segments: Phy Recv -> OVS -> Intf Xmit -> Intf Stack")
    parser.add_argument("--phy", default="eth0", help="Physical interface name (e.g., eth0)")
    parser.add_argument("--internal", default="ovs-system", help="OVS internal interface name (e.g., ovs-system)")
    parser.add_argument('--src-ip', type=str, help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, help='Destination port filter (TCP/UDP)')
    # Use list(protocol_map.keys()) for Python 3 compatibility with choices
    parser.add_argument('--protocol', type=str, choices=list(protocol_map.keys()), default='all', help='Protocol filter (icmp, tcp, udp, all)')

    args = parser.parse_args()

    # --- Validate Args ---
    if not args.phy or not args.internal:
        # Use print() function
        print("Error: Physical and internal interface names cannot be empty.")
        exit(1)
    if len(args.phy) >= 16 or len(args.internal) >= 16:
         # Use print() function
         print("Error: Interface names must be less than 16 characters (IFNAMSIZ).")
         exit(1)

    # --- Prepare Filters for BPF ---
    filter_src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    filter_dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    filter_src_port = args.src_port if args.src_port else 0
    filter_dst_port = args.dst_port if args.dst_port else 0
    filter_protocol = protocol_map[args.protocol]

    # Construct BPF program text using positional % formatting
    bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/icmp.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/openvswitch.h> // REMOVED: Rely on BTF or kernel headers if possible
#include <net/openvswitch/vport.h>

// Forward declare vport if header is removed

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// --- Placeholders for Python Formatting ---
#define PHY_IFNAME "%s"     // 1st arg (string)
#define INT_IFNAME "%s"     // 2nd arg (string)
#define FILTER_SRC_IP 0x%x  // 3rd arg (hex)
#define FILTER_DST_IP 0x%x  // 4th arg (hex)
#define FILTER_SRC_PORT %d  // 5th arg (decimal)
#define FILTER_DST_PORT %d  // 6th arg (decimal)
#define FILTER_PROTOCOL %d  // 7th arg (decimal)

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
};

struct timestamp_data {
    u64 ts;
    u8 stage;
};

BPF_HASH(rx_flow_timestamps, struct flow_key_t, struct timestamp_data);

#define STAGE_PHY_RECV 1
#define STAGE_OVS_VPORT_RECV 2
#define STAGE_INT_XMIT 3
#define STAGE_STACK_DELIVER 4

static __always_inline int get_flow_key(struct sk_buff *skb, struct flow_key_t *key) {
    struct iphdr iph;
    int ip_offset = skb->network_header;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + ip_offset) < 0) { return -1; }
    if (iph.version != 4) return -2;

    key->saddr = iph.saddr;
    key->daddr = iph.daddr;
    key->protocol = iph.protocol;
    key->sport = 0;
    key->dport = 0;

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        int tcp_offset = skb->transport_header;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + tcp_offset) < 0) { return -3; }
        key->sport = ntohs(tcph.source);
        key->dport = ntohs(tcph.dest);
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        int udp_offset = skb->transport_header;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + udp_offset) < 0) { return -4; }
        key->sport = ntohs(udph.source);
        key->dport = ntohs(udph.dest);
    }
    return 0;
}

static __always_inline bool packet_matches_filters(struct flow_key_t *key) {
    if (FILTER_PROTOCOL != 0 && key->protocol != FILTER_PROTOCOL) { return false; }
    if (FILTER_SRC_IP != 0 && key->saddr != FILTER_SRC_IP) { return false; }
    if (FILTER_DST_IP != 0 && key->daddr != FILTER_DST_IP) { return false; }
    if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
        if (FILTER_SRC_PORT != 0 && key->sport != FILTER_SRC_PORT) { return false; }
        if (FILTER_DST_PORT != 0 && key->dport != FILTER_DST_PORT) { return false; }
    }
    return true;
}

int trace_phy_receive(struct tracepoint__net__netif_receive_skb *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb) return 0;
    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0) return 0;
    if (!dev) return 0;
    if (bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name) < 0) return 0;
    if (__builtin_memcmp(ifname, PHY_IFNAME, IFNAMSIZ) != 0) return 0;

    struct flow_key_t key = {};
    if (get_flow_key(skb, &key) != 0) return 0;
    if (!packet_matches_filters(&key)) return 0;

    u64 ts = bpf_ktime_get_ns();
    struct timestamp_data data = { .ts = ts, .stage = STAGE_PHY_RECV };
    rx_flow_timestamps.update(&key, &data);
    return 0;
}

int kprobe__ovs_vport_receive(struct pt_regs *ctx, struct vport *vport, struct sk_buff *skb) {
    if (!vport || !skb) return 0;
    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &vport->dev) < 0) {
        // If this fails, BTF/headers didn't work. Could add a printk warning here.
        // bpf_trace_printk("WARN: Failed to read vport->dev\\n");
        return 0;
    }
    if (!dev) return 0;
    if (bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name) < 0) return 0;
    if (__builtin_memcmp(ifname, PHY_IFNAME, IFNAMSIZ) != 0) return 0;

    struct flow_key_t key = {};
    if (get_flow_key(skb, &key) != 0) return 0;

    struct timestamp_data *prev_data = rx_flow_timestamps.lookup(&key);
    if (!prev_data || prev_data->stage != STAGE_PHY_RECV) return 0;

    u64 ts_now = bpf_ktime_get_ns();
    u64 delta_us = (ts_now > prev_data->ts) ? (ts_now - prev_data->ts) / 1000 : 0;

    struct timestamp_data current_data = { .ts = ts_now, .stage = STAGE_OVS_VPORT_RECV };
    rx_flow_timestamps.update(&key, &current_data);
    return 0;
}

int trace_internal_transmit(struct tracepoint__net__net_dev_xmit *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb) return 0;
    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0) return 0;
    if (!dev) return 0;
    if (bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name) < 0) return 0;
    if (__builtin_memcmp(ifname, INT_IFNAME, IFNAMSIZ) != 0) return 0;

    struct flow_key_t key = {};
    if (get_flow_key(skb, &key) != 0) return 0;

    struct timestamp_data *prev_data = rx_flow_timestamps.lookup(&key);
    if (!prev_data || prev_data->stage != STAGE_OVS_VPORT_RECV) return 0;

    u64 ts_now = bpf_ktime_get_ns();
    u64 delta_us = (ts_now > prev_data->ts) ? (ts_now - prev_data->ts) / 1000 : 0;

    struct timestamp_data current_data = { .ts = ts_now, .stage = STAGE_INT_XMIT };
    rx_flow_timestamps.update(&key, &current_data);
    return 0;
}

int kprobe__ip_local_deliver_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    if (!skb) return 0;
    struct flow_key_t key = {};
    if (get_flow_key(skb, &key) != 0) return 0;

    struct timestamp_data *prev_data = rx_flow_timestamps.lookup(&key);
    if (!prev_data || prev_data->stage != STAGE_INT_XMIT) return 0;

    u64 ts_now = bpf_ktime_get_ns();
    u64 delta_us = (ts_now > prev_data->ts) ? (ts_now - prev_data->ts) / 1000 : 0;

    rx_flow_timestamps.delete(&key);
    return 0;
}
"""

    # Define the tuple of arguments in the correct order for positional formatting
    bpf_args = (
        args.phy,
        args.internal,
        filter_src_ip_hex,
        filter_dst_ip_hex,
        filter_src_port,
        filter_dst_port,
        filter_protocol
    )

    # Format the BPF text using the tuple
    formatted_bpf_text = bpf_text % bpf_args

    # Load BPF program
    # Use print() function with .format() for Python 3 compatibility
    print("Loading BPF program... Monitoring RX path for {} -> OVS -> {} -> Stack".format(args.phy, args.internal))
    # Format hex values correctly within .format() using :x
    print("Filters: Proto={} SrcIP={}(0x{:x}) DstIP={}(0x{:x}) SrcPort={} DstPort={}".format(
        filter_protocol,
        args.src_ip if args.src_ip else "any", filter_src_ip_hex,
        args.dst_ip if args.dst_ip else "any", filter_dst_ip_hex,
        filter_src_port, filter_dst_port
    ))
    print("INFO: Requires kernel headers for struct net_device access.")
    print("INFO: Attempting to use BTF or included kernel headers for struct vport layout.")
    print("INFO: Ensure 'ovs_vport_receive' and 'ip_local_deliver_finish' are valid kernel symbols.")

    ovs_func_name = "ovs_vport_receive"
    stack_func_name = "ip_local_deliver_finish"
    cflags=[
        "-I/usr/src/linux-4.19.90-2307.3.0.el7.v97.x86_64",
        -D__KERNEL__,
        -D__BPF_TRACING__,           
        -DKBUILD_MODNAME=\"bpf\"    
    ]

    try:
        # Pass the formatted text to BPF
        b = BPF(text=formatted_bpf_text, cflags=cflags)

        # Attach Probes for RX Path
        b.attach_tracepoint(tp="net:netif_receive_skb", fn_name="trace_phy_receive")
        b.attach_tracepoint(tp="net:net_dev_xmit", fn_name="trace_internal_transmit")

        print("Attempting to attach kprobes...")
        b.attach_kprobe(event=ovs_func_name, fn_name="kprobe__ovs_vport_receive")
        print(" - Attached kprobe to {}".format(ovs_func_name))
        b.attach_kprobe(event=stack_func_name, fn_name="kprobe__ip_local_deliver_finish")
        print(" - Attached kprobe to {}".format(stack_func_name))
        print("Successfully attached all probes.")

    except Exception as e:
        # Use print() function
        print("\nERROR loading/attaching BPF probes:")
        print(e) # Print exception using print()
        if ovs_func_name in str(e) or stack_func_name in str(e):
             print("  (Check kernel symbols: '{}', '{}')".format(ovs_func_name, stack_func_name))
        # Check specifically for the vport->dev access error
        if "incomplete definition of type 'struct vport'" in str(e) or "member reference base type 'struct vport *' is not a structure or union" in str(e):
             print("  (BPF compile error accessing vport->dev. Check OVS headers installation or BTF status.)")
        elif "vport" in str(e) or "net_device" in str(e): # General struct error
             print("  (BPF compile error related to vport/net_device structs. Check kernel/OVS headers or BTF.)")
        exit(1)

    # Use print() function
    print("\nTracing RX latency segments... Hit Ctrl-C to end.")
    # Use format specifiers compatible with .format() for alignment
    print("\n{:<18} {:<15} {}".format("TIME(s)", "INTERFACE", "LATENCY_EVENT"))

    try:
        while True:
            try:
                (task, pid, cpu, flags, ts, msg_bytes) = b.trace_fields(nonblocking=False)
                msg = msg_bytes.decode('utf-8', 'replace')

                if "LATENCY" in msg:
                     parts = msg.split(':')
                     event_desc = parts[0].strip()
                     details_str = parts[1].strip()
                     details = details_str.split()

                     iface = "N/A"
                     latency_val = "?"
                     latency_unit = "us"

                     if len(details) >= 2:
                         try:
                             float(details[-2])
                             latency_val = details[-2]
                             latency_unit = details[-1]
                             if len(details) >= 3 and not details[0].replace('.','',1).isdigit():
                                 iface = details[0]
                         except (ValueError, IndexError):
                             pass

                     # Use print() function with .format()
                     print("{:<18.9f} {:<15} {} ({} {})".format(ts, iface, event_desc, latency_val, latency_unit))

                elif "WARN" in msg or "KPROBE" in msg or "INFO" in msg:
                     # Use print() function with .format()
                     print("{:<18.9f} {:<15} {}".format(ts, "BPF", msg))

            except ValueError:
                time.sleep(0.01)
                continue
            except KeyboardInterrupt:
                # Use print() function
                print("\nDetaching...")
                break

    except Exception as e:
        # Use print() function with .format()
        print("\nAn error occurred during tracing: {}".format(e))
    finally:
        b.cleanup()

if __name__ == "__main__":
    main()
# Ensure final newline

