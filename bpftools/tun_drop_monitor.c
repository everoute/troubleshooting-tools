#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h> // For VLAN_HLEN
#include <linux/ptr_ring.h> // For struct ptr_ring definition if available via bcc

// Define NETDEV_ALIGN if not available through headers, common value is 32
#ifndef NETDEV_ALIGN
#define NETDEV_ALIGN 32
#endif

// Placeholders for filtering criteria - to be replaced by Python script
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d
#define TRACE_TX %d
#define TRACE_RX %d

// Kernel structures (adapted from tun-vhost.bt and kernel sources)
// These might need adjustments based on the specific kernel version
// and what bcc can access.

struct tun_struct {
	struct tun_file __rcu	*tfiles[256]; // Simplified, assuming direct access works
	unsigned int            numqueues;
	unsigned int 		    flags;
	kuid_t			        owner;
	kgid_t			        group;
	struct net_device	    *dev;
	// ... other fields as needed, trying to keep it minimal for BPF
    int			            vnet_hdr_sz;
    // Add more fields if they are directly used and accessible
};

struct tun_file {
	struct sock             sk;
    // Skip many anonymous fields for simplicity in BPF context if not used
    // long: 64; long: 64; ...
	struct socket           socket;
	struct tun_struct       *tun;
	unsigned int            flags;
	union {
		u16                 queue_index;
		unsigned int        ifindex;
	};
	struct ptr_ring         tx_ring; // Key structure for TX monitoring
    // ... other fields
};


// Event data structure
enum trace_path {
    PATH_TX,
    PATH_RX,
};

struct tun_event_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    enum trace_path path; // TX or RX

    // Packet L3/L4 info
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u16 ip_id;
    u16 vlan_id;
    u8 icmp_type;
    u8 icmp_code;

    // tun_net_xmit specific (TX)
    u32 tx_ring_size;
    u32 tx_ring_producer;
    u32 tx_ring_consumer_tail; // Most relevant for checking if ring is full
    u16 tx_queue_mapping;

    // RX specific (to be defined based on RX probe point)
    // e.g., rx_ring_size, rx_ring_producer, rx_ring_consumer
    // u32 rx_some_buffer_param;

    int kernel_stack_id;
    int user_stack_id;
};

BPF_PERF_OUTPUT(tun_events);
BPF_STACK_TRACE(stack_traces, 16384); // Increased size a bit

// Helper to get tun_struct from net_device
// This is a common pattern but might need adjustment based on kernel version / layout
static inline struct tun_struct *netdev_priv_tun(struct net_device *dev) {
    // Calculate offset similar to netdev_priv
    // unsigned long aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    // return (struct tun_struct *)((char *)dev + aligned_size);
    // Simpler approach: direct cast if bcc/kernel allows direct access to dev->priv for tun
    // For many drivers, dev->priv points directly to the main device structure.
    // However, tun uses `netdev_priv` which is `(char *)dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN)`
    // Let's try the calculation, ensuring types are correct for BPF.
    // The direct usage of dev->ax25_ptr, dev->ip_ptr etc. in some examples suggests bcc
    // might have its own way of handling these. For tun, it's netdev_priv().
    // Let's stick to offset calculation as in tun-vhost.bt
    return (struct tun_struct *)((void *)dev + ((sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1)));
}


int kprobe__tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (TRACE_TX == 0) return 0;

    // Filter early if dev is not tun (though function name implies it is)
    // Can add more checks on dev->name if needed, but filtering done in Python usually.

    struct tun_event_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.path = PATH_TX;

    if (dev && dev->name[0]) { // Check if dev and dev->name are valid
        bpf_probe_read_kernel_str(&data.ifname, IFNAMSIZ, dev->name);
    }

    // Extract tun_struct and ptr_ring details
    struct tun_struct *tun = netdev_priv_tun(dev);
    if (!tun) return 0;

    // Assuming single queue or queue 0/1 for simplicity as in tun-vhost.bt example.
    // Real multi-queue devices would need skb->queue_mapping to select the tun_file.
    // skb->queue_mapping provides the queue index.
    u16 queue_idx = 0;
    bpf_probe_read_kernel(&queue_idx, sizeof(queue_idx), &skb->queue_mapping);
    data.tx_queue_mapping = queue_idx;

    if (queue_idx < 256) { // Check bounds
        struct tun_file *tfile = NULL;
        bpf_probe_read_kernel(&tfile, sizeof(tfile), &tun->tfiles[queue_idx]);

        if (tfile) {
            // Reading from tfile->tx_ring
            // Need to be careful with direct struct member access vs bpf_probe_read_kernel
            struct ptr_ring tx_ring_snapshot; // Create a local copy
            bpf_probe_read_kernel(&tx_ring_snapshot, sizeof(tx_ring_snapshot), &tfile->tx_ring);

            data.tx_ring_size = tx_ring_snapshot.size;
            data.tx_ring_producer = tx_ring_snapshot.producer;
            // For ptr_ring, consumer_tail is often what's checked against producer + 1
            // to see if the ring is full. consumer_head is for the reader.
            data.tx_ring_consumer_tail = tx_ring_snapshot.consumer_tail;
        }
    }


    // --- SKB Parsing Logic (adapted from multi-protocol-drop-monitor) ---
    if (!skb) return 0;

    unsigned char *head;
    u16 network_header_offset;
    u16 vlan_tci = 0;

    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header);
    bpf_probe_read_kernel(&vlan_tci, sizeof(vlan_tci), &skb->vlan_tci); // Read vlan_tci

    data.vlan_id = 0;
    if (vlan_tci != 0) { // Check if VLAN tag is present
        data.vlan_id = vlan_tci & 0x0FFF; // VLAN ID is lower 12 bits
        // If skb->protocol was ETH_P_8021Q, network_header would already be adjusted by kernel
        // If not, and we are before mac_header processing, we might need to adjust offset.
        // Given we read skb->network_header, it should be correct post-VLAN.
    }

    struct iphdr iph;
    int ret = bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header_offset);
    if (ret != 0 || iph.version != 4) {
        return 0; // Not IPv4 or failed to read
    }

    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.ip_id = bpf_ntohs(iph.id);


    // Apply filters
    if (!((SRC_IP == 0 || data.saddr == SRC_IP) &&
          (DST_IP == 0 || data.daddr == DST_IP) &&
          (PROTOCOL == 0 || data.protocol == PROTOCOL))) {
        return 0;
    }

    unsigned int transport_header_offset = network_header_offset + iph.ihl * 4;

    if (data.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header_offset) == 0) {
            data.sport = bpf_ntohs(tcph.source);
            data.dport = bpf_ntohs(tcph.dest);
        }
    } else if (data.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset) == 0) {
            data.sport = bpf_ntohs(udph.source);
            data.dport = bpf_ntohs(udph.dest);
        }
    } else if (data.protocol == IPPROTO_ICMP) {
        struct icmphdr icmph;
         if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) == 0) {
            data.icmp_type = icmph.type;
            data.icmp_code = icmph.code;
        }
    }

    // Port filtering (after extracting ports)
    if (data.protocol == IPPROTO_TCP || data.protocol == IPPROTO_UDP) {
        if (!((SRC_PORT == 0 || data.sport == SRC_PORT) &&
              (DST_PORT == 0 || data.dport == DST_PORT))) {
            return 0;
        }
    }
    
    data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

    tun_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Placeholder for RX probe, e.g., on tun_rx or similar
// The exact function and parameters will depend on what details are needed for RX.
// A common function to look into for tun RX is tun_get_user or functions it calls.
// For simplicity, let's assume a function `tun_handle_rx_frame(struct sk_buff *skb, struct net_device *dev)`
// This is hypothetical and would need to be replaced with an actual kernel function.
// Or, kprobe `tun_rx` or `tun_recvmsg` and parse args.
// Let's try to find a suitable rx probe, maybe `tun_rx` or `tun_rx_batched`.
// `tun_rx` is static inline. `tun_do_read` calls `tun_get_user`.
// `tun_get_user` is a good candidate.
// Args: struct tun_file *tfile, struct msghdr *m, struct iov_iter *to, int noblock
// This doesn't directly give an skb.
//
// Alternative: `netif_rx` or `netif_receive_skb` kretprobe, filtering for tun device.
// Or kprobe on `tun_queue_xmit` for packets *received by tun* from network stack to be given to userspace.
// However, `tun_queue_xmit` is for TX path of the *other side* of the TAP device.
//
// Let's consider a kprobe on `tun_rx_batched` or `tun_rxq_receive_skb` (if it exists and is suitable)
// For now, let's add a placeholder for a generic RX kprobe.
// The user might specify the exact RX function they are interested in later.
// For now, a simple placeholder.

/*
// Example RX probe (Hypothetical, needs a real target function)
// int kprobe__some_tun_rx_function(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
//     if (TRACE_RX == 0) return 0;

//     struct tun_event_data_t data = {};
//     data.ts = bpf_ktime_get_ns();
//     data.pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_get_current_comm(&data.comm, sizeof(data.comm));
//     data.path = PATH_RX;

//     if (dev && dev->name[0]) {
//         bpf_probe_read_kernel_str(&data.ifname, IFNAMSIZ, dev->name);
//     }

//     // ... SKB parsing similar to TX ...
//     // ... Extract RX specific buffer/queue states if possible ...
//     // e.g., from tun_file->napi or other RX related structures

//     // Apply filters
//     // ...

//     data.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
//     data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

//     tun_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }
*/ 