#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>

BPF_HASH(ipv4_count, u32, u64);
BPF_STACK_TRACE(stack_traces, 8192);  
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d

struct dropped_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u16 ip_id; // Add IP ID field
    int kernel_stack_id;
    int user_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    u32 drop_reason;
    u16 vlan_id; // Add VLAN ID field
};
BPF_PERF_OUTPUT(kfree_drops);

int trace_kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u32 drop_reason = (u32)PT_REGS_PARM2(ctx);
    
    if (skb == NULL)
        return 0;

    u16 initial_protocol;
    bpf_probe_read_kernel(&initial_protocol, sizeof(initial_protocol), &skb->protocol);

    // Check for VLAN tag by reading vlan_tci (compatible with older kernels)
    u16 vlan_tci = 0;
    u16 vlan_id = 0;
    bpf_probe_read_kernel(&vlan_tci, sizeof(vlan_tci), &skb->vlan_tci);

    unsigned int network_header_offset;
    bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header);

    if (vlan_tci != 0) { // vlan_tci non-zero indicates VLAN tag present
        vlan_id = vlan_tci & 0x0FFF; // VLAN ID is the lower 12 bits
        network_header_offset += VLAN_HLEN; // Adjust offset for VLAN header
        // Note: skb->protocol might be ETH_P_8021Q here. We care about the inner protocol.
        // The IP header check later handles non-IP packets after potential VLAN.
    }
    
    // Check if the protocol *after* potential VLAN is IP
    // Read head pointer
    unsigned char *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);

    // Check the EtherType field at the L2 header end (before potential IP header)
    u16 post_vlan_protocol = 0;
    // Assuming ETH_HLEN includes MAC addresses + EtherType (14 bytes)
    // If VLAN was present, the network_header_offset points *after* VLAN tag.
    // The EtherType *before* the network header (IP) tells us the L3 protocol.
    // Need to carefully read the EtherType *after* MAC addresses but *before* IP.
    // Let's read the protocol field directly from the IP header later, it's safer.

    // Extract IP header using the potentially adjusted offset
    struct iphdr iph;
    // Ensure we don't read past the end of the skb data
    // This read assumes the IP header starts exactly at network_header_offset
    int ret = bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header_offset);
    if (ret != 0) {
        // Failed to read IP header, maybe packet too short or offset wrong
        return 0; 
    }

    // Check if it's actually an IPv4 packet by verifying the version field
    if (iph.version != 4) {
        return 0;
    }

    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);
    }

    struct dropped_skb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.ip_id = ntohs(iph.id); // Assign IP ID (convert from network to host byte order)
    data.vlan_id = vlan_id; // Assign VLAN ID

    data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    if (data.kernel_stack_id < 0) {
        data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
    if (data.user_stack_id < 0) {
        data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    }

    data.drop_reason = drop_reason;
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Calculate transport header offset
    unsigned int transport_header_offset = network_header_offset + iph.ihl * 4;

    // Check IP addresses
    if ((SRC_IP == 0 || saddr == SRC_IP) && (DST_IP == 0 || daddr == DST_IP)) {
        // Check protocol
        if (PROTOCOL == 0 || iph.protocol == PROTOCOL) {
            if (iph.protocol == IPPROTO_ICMP) {
                struct icmphdr icmph;
                bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset);
                data.icmp_type = icmph.type;
                data.icmp_code = icmph.code;
                kfree_drops.perf_submit(ctx, &data, sizeof(data));
            } else if (iph.protocol == IPPROTO_TCP) {
                struct tcphdr tcph;
                bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header_offset);
                data.sport = ntohs(tcph.source);
                data.dport = ntohs(tcph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                struct udphdr udph;
                bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset);
                data.sport = ntohs(udph.source);
                data.dport = ntohs(udph.dest);
                if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                }
            } else {
                // For other protocols, submit without port information
                kfree_drops.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }

    return 0;
} 