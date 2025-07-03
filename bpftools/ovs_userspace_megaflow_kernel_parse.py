#!/usr/bin/python2
# -*- coding: utf-8 -*-
"""
OVS Userspace Megaflow Tracker V6
增强版本：补充 IP 地址、端口信息、Netlink portid 和精确内核时间戳
"""

from bcc import BPF
import ctypes as ct
from socket import inet_ntop, AF_INET
from struct import pack, unpack
from time import strftime
import sys
import datetime

TARGET_ETH_SRC = "52:54:00:39:89:ff"
TARGET_ETH_TYPE = 0x0800

def mac_str_to_bytes(mac_str):
    return [int(x, 16) for x in mac_str.split(':')]

TARGET_MAC_BYTES = mac_str_to_bytes(TARGET_ETH_SRC)

bpf_text = """
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/sock.h>
#include <net/genetlink.h>

// Define ETH_ALEN if not defined
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// sw_flow_key 结构体定义 (简化版本，只包含我们需要的字段)
struct sw_flow_key {
    u32 phy_data;           // +0
    u32 tun_opts_len;       // +4
    u32 recirc_id;          // +8
    u32 skb_mark;           // +12
    u16 in_port;            // +16
    // ... 其他字段我们不需要
};

// OVS Netlink 属性定义
enum ovs_flow_attr {
    OVS_FLOW_ATTR_UNSPEC,
    OVS_FLOW_ATTR_KEY,        /* Sequence of OVS_KEY_ATTR_* attributes. */
    OVS_FLOW_ATTR_ACTIONS,    /* Nested OVS_ACTION_ATTR_* attributes. */
    OVS_FLOW_ATTR_STATS,      /* struct ovs_flow_stats */
    OVS_FLOW_ATTR_TCP_FLAGS,  /* 8-bit OR'd TCP flags. */
    OVS_FLOW_ATTR_USED,       /* u64 msecs last used in monotonic time. */
    OVS_FLOW_ATTR_CLEAR,      /* Flag to clear stats, tcp_flags, used. */
    OVS_FLOW_ATTR_MASK,       /* Sequence of OVS_KEY_ATTR_* attributes. */
    OVS_FLOW_ATTR_PROBE,      /* Nested OVS_ACTION_ATTR_* attributes. */
    OVS_FLOW_ATTR_UFID,       /* Variable length unique flow identifier. */
    OVS_FLOW_ATTR_UFID_FLAGS, /* u32 of OVS_UFID_F_* */
    OVS_FLOW_ATTR_PAD,
    __OVS_FLOW_ATTR_MAX
};

// OVS key 属性定义
enum ovs_key_attr {
    OVS_KEY_ATTR_UNSPEC,
    OVS_KEY_ATTR_ENCAP,       /* Nested set of encapsulated attributes. */
    OVS_KEY_ATTR_PRIORITY,    /* u32 skb->priority */
    OVS_KEY_ATTR_IN_PORT,     /* u32 OVS dp port number */
    OVS_KEY_ATTR_ETHERNET,    /* struct ovs_key_ethernet */
    OVS_KEY_ATTR_VLAN,        /* be16 VLAN TCI */
    OVS_KEY_ATTR_ETHERTYPE,   /* be16 Ethernet type */
    OVS_KEY_ATTR_IPV4,        /* struct ovs_key_ipv4 */
    OVS_KEY_ATTR_IPV6,        /* struct ovs_key_ipv6 */
    OVS_KEY_ATTR_TCP,         /* struct ovs_key_tcp */
    OVS_KEY_ATTR_UDP,         /* struct ovs_key_udp */
    OVS_KEY_ATTR_ICMP,        /* struct ovs_key_icmp */
    OVS_KEY_ATTR_ICMPV6,      /* struct ovs_key_icmpv6 */
    OVS_KEY_ATTR_ARP,         /* struct ovs_key_arp */
    OVS_KEY_ATTR_ND,          /* struct ovs_key_nd */
    OVS_KEY_ATTR_SKB_MARK,    /* u32 skb mark */
    OVS_KEY_ATTR_TUNNEL,      /* Nested set of ovs_tunnel_key_attr */
    OVS_KEY_ATTR_SCTP,        /* struct ovs_key_sctp */
    OVS_KEY_ATTR_TCP_FLAGS,   /* be16 TCP flags. */
    OVS_KEY_ATTR_DP_HASH,     /* u32 hash value. */
    OVS_KEY_ATTR_RECIRC_ID,   /* u32 recirc id */
    OVS_KEY_ATTR_MPLS,        /* array of struct ovs_key_mpls */
    OVS_KEY_ATTR_CT_STATE,    /* u32 bitmask of OVS_CS_F_* */
    OVS_KEY_ATTR_CT_ZONE,     /* u16 connection tracking zone. */
    OVS_KEY_ATTR_CT_MARK,     /* u32 connection tracking mark */
    OVS_KEY_ATTR_CT_LABELS,   /* 16-octet connection tracking labels */
    OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,   /* struct ovs_key_ct_tuple_ipv4 */
    OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,   /* struct ovs_key_ct_tuple_ipv6 */
    OVS_KEY_ATTR_NSH,         /* Nested set of ovs_nsh_key_* */
    OVS_KEY_ATTR_PACKET_TYPE, /* be32 packet type */
    OVS_KEY_ATTR_ND_EXTENSIONS, /* Nested set of OVS_KEY_ATTR_ND_* */
    OVS_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
    OVS_KEY_ATTR_IPV6_EXTHDRS, /* struct ovs_key_ipv6_exthdrs */
    __OVS_KEY_ATTR_MAX
};

// OVS key 结构体定义 (注意字段顺序)
struct ovs_key_ethernet {
    __u8 eth_src[ETH_ALEN];
    __u8 eth_dst[ETH_ALEN];
};

struct ovs_key_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __u8 ipv4_proto;
    __u8 ipv4_tos;
    __u8 ipv4_ttl;
    __u8 ipv4_frag;
};

struct ovs_key_tcp {
    __be16 tcp_src;
    __be16 tcp_dst;
};

struct ovs_key_udp {
    __be16 udp_src;
    __be16 udp_dst;
};

struct upcall_event_t {
    u64 kernel_timestamp;  // 内核时间戳
    u32 pid;
    u32 portid;
    char comm[16];
    
    // 从 SKB 直接解析的字段 (用于过滤和显示)
    u8 skb_eth_dst[6];
    u8 skb_eth_src[6];
    u16 skb_eth_type;
    u32 skb_src_ip;
    u32 skb_dst_ip;
    u16 skb_src_port;
    u16 skb_dst_port;
    u8 skb_ip_proto;
    u32 skb_mark;          // 从 SKB 直接读取的 mark
    
    char dev_name[16];
    u32 parse_status; // 0=成功, 1=SKB解析失败, 2=非IPv4, 3=其他错误
};

struct flow_cmd_new_event_t {
    u64 kernel_timestamp;  // 内核时间戳
    u32 pid;
    char comm[16];
    u32 netlink_portid;    // Netlink 端口 ID
    
    // 从 Netlink 消息解析的字段
    u32 dp_ifindex;
    u32 recirc_id;
    u32 skb_mark;
    u16 in_port;
    u8 eth_dst[6];
    u8 eth_src[6];
    u16 eth_type;
    u32 src_ip;            // IPv4 源地址
    u32 dst_ip;            // IPv4 目标地址
    u16 src_port;          // 源端口
    u16 dst_port;          // 目标端口
    u8 ip_proto;           // IP 协议
    
    // 解析状态
    u32 has_key;
    u32 has_mask;
    u32 parse_status; // 0=成功, 非0=失败
    
    // Mask 中的以太网地址
    u8 mask_eth_dst[6];
    u8 mask_eth_src[6];
    
    // 调试信息
    u64 key_attr_ptr;
    u32 key_attr_len;
};

BPF_PERF_OUTPUT(upcall_events);
BPF_PERF_OUTPUT(flow_cmd_new_events);

// 直接解析 SKB 以太网头部 (参考 icmp_rtt_latency.py)
static __always_inline int parse_skb_headers(struct sk_buff *skb, 
                                            u8 eth_dst[6], u8 eth_src[6], u16 *eth_type,
                                            u32 *src_ip, u32 *dst_ip, 
                                            u16 *src_port, u16 *dst_port, u8 *ip_proto) {
    if (!skb) return 1;
    
    unsigned char *skb_head;
    if (bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 1;
    }
    if (!skb_head) return 1;
    
    unsigned long skb_data_ptr_val; 
    if (bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 1;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset; 
    
    // 读取以太网头部
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 1;
    }
    
    // 复制 MAC 地址
    bpf_probe_read_kernel(eth_dst, 6, eth.h_dest);
    bpf_probe_read_kernel(eth_src, 6, eth.h_source);
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;
    
    // 处理 VLAN 标签
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        net_offset += VLAN_HLEN; 
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 1;
        }
        // 处理双层 VLAN
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
             net_offset += VLAN_HLEN;
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + (2 * VLAN_HLEN) + 2) < 0) {
                 return 1;
             }
        }
    }
    
    *eth_type = ntohs(h_proto);  // 转换为主机字节序
    
    // 如果不是 IPv4，返回 2
    if (h_proto != htons(ETH_P_IP)) {
        return 2;
    }
    
    // 解析 IP 头部
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0) {
        return 1;
    }
    
    *src_ip = ip.saddr;  // 保持网络字节序
    *dst_ip = ip.daddr;
    *ip_proto = ip.protocol;
    
    // 解析传输层端口 (TCP/UDP)
    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
        u8 ip_ihl = ip.ihl & 0x0F;  
        if (ip_ihl >= 5) {
            unsigned int trans_offset = net_offset + (ip_ihl * 4);
            struct tcphdr th;
            if (bpf_probe_read_kernel(&th, sizeof(th), skb_head + trans_offset) == 0) {
                *src_port = ntohs(th.source);
                *dst_port = ntohs(th.dest);
            }
        }
    }
    
    return 0; // 成功
}

// 简化的 nlattr 解析 - 只解析关键字段
static __always_inline void parse_nlattr_simple(void *attr_ptr, struct flow_cmd_new_event_t *event) {
    struct nlattr nla;
    if (bpf_probe_read_kernel(&nla, sizeof(nla), attr_ptr) < 0) {
        return;
    }
    
    u16 type = nla.nla_type & ~(1 << 15);  // 去掉 nested 标志
    void *data_ptr = attr_ptr + sizeof(struct nlattr);
    
    // 只解析最关键的字段
    if (type == OVS_KEY_ATTR_RECIRC_ID) {
        bpf_probe_read_kernel(&event->recirc_id, sizeof(u32), data_ptr);
    } else if (type == OVS_KEY_ATTR_SKB_MARK) {
        bpf_probe_read_kernel(&event->skb_mark, sizeof(u32), data_ptr);
    } else if (type == OVS_KEY_ATTR_IN_PORT) {
        bpf_probe_read_kernel(&event->in_port, sizeof(u32), data_ptr);
        event->in_port = (u16)event->in_port;
    } else if (type == OVS_KEY_ATTR_ETHERNET) {
        struct ovs_key_ethernet eth_key;
        if (bpf_probe_read_kernel(&eth_key, sizeof(eth_key), data_ptr) == 0) {
            bpf_probe_read_kernel(event->eth_src, ETH_ALEN, eth_key.eth_src);
            bpf_probe_read_kernel(event->eth_dst, ETH_ALEN, eth_key.eth_dst);
        }
    } else if (type == OVS_KEY_ATTR_ETHERTYPE) {
        __be16 eth_type;
        if (bpf_probe_read_kernel(&eth_type, sizeof(eth_type), data_ptr) == 0) {
            event->eth_type = ntohs(eth_type);
        }
    }
    // 简化版本暂时不解析 IP 和端口，减少指令数量
}

// 简化的 flow key 解析
static __always_inline void parse_flow_key_simple(void *key_attr, u32 key_len, struct flow_cmd_new_event_t *event) {
    if (!key_attr || key_len < sizeof(struct nlattr)) {
        return;
    }
    
    // 简化遍历 - 只解析前15个属性
    void *pos = key_attr;
    void *end = key_attr + key_len;
    
    #pragma unroll
    for (int i = 0; i < 15; i++) {  // 减少到15个属性
        if (pos + sizeof(struct nlattr) > end) {
            break;
        }
        
        struct nlattr nla;
        if (bpf_probe_read_kernel(&nla, sizeof(nla), pos) < 0) {
            break;
        }
        
        if (nla.nla_len < sizeof(struct nlattr) || pos + nla.nla_len > end) {
            break;
        }
        
        parse_nlattr_simple(pos, event);
        
        // 移动到下一个属性 (4字节对齐)
        pos += ((nla.nla_len + 3) & ~3);
    }
}

// 解析 mask 属性中的以太网地址
static __always_inline void parse_mask_key_simple(void *mask_attr, u32 mask_len, struct flow_cmd_new_event_t *event) {
    if (!mask_attr || mask_len < sizeof(struct nlattr)) {
        return;
    }
    
    void *pos = mask_attr;
    void *end = mask_attr + mask_len;
    
    #pragma unroll
    for (int i = 0; i < 15; i++) {  // 增加到15个属性
        if (pos + sizeof(struct nlattr) > end) {
            break;
        }
        
        struct nlattr nla;
        if (bpf_probe_read_kernel(&nla, sizeof(nla), pos) < 0) {
            break;
        }
        
        if (nla.nla_len < sizeof(struct nlattr) || pos + nla.nla_len > end) {
            break;
        }
        
        u16 type = nla.nla_type & ~(1 << 15);
        void *data_ptr = pos + sizeof(struct nlattr);
        
        // 解析 ETHERNET 类型
        if (type == OVS_KEY_ATTR_ETHERNET) {
            // 直接读取 12 字节：前 6 字节是 src，后 6 字节是 dst
            if (bpf_probe_read_kernel(event->mask_eth_src, ETH_ALEN, data_ptr) == 0) {
                bpf_probe_read_kernel(event->mask_eth_dst, ETH_ALEN, data_ptr + ETH_ALEN);
            }
            break;  // 找到就退出
        }
        
        // 移动到下一个属性
        pos += ((nla.nla_len + 3) & ~3);
    }
}

int trace_ovs_dp_upcall(struct pt_regs *ctx)
{
    struct datapath *dp = (struct datapath *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    void *key_ptr = (void *)PT_REGS_PARM3(ctx);  // 第三个参数才是 sw_flow_key
    void *upcall_info = (void *)PT_REGS_PARM4(ctx);
    
    if (!key_ptr || !skb) {
        return 0;
    }
    
    struct upcall_event_t event = {};
    event.kernel_timestamp = bpf_ktime_get_ns();  // 内核时间戳
    event.pid = bpf_get_current_pid_tgid() >> 32;
    
    // 修复: upcall_info 是一个结构体，portid 通常在第一个字段
    if (upcall_info) {
        bpf_probe_read_kernel(&event.portid, sizeof(u32), upcall_info);
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 直接从 SKB 解析包头信息
    int parse_result = parse_skb_headers(skb,
        event.skb_eth_dst, event.skb_eth_src, &event.skb_eth_type,
        &event.skb_src_ip, &event.skb_dst_ip,
        &event.skb_src_port, &event.skb_dst_port, &event.skb_ip_proto);
    
    event.parse_status = parse_result;
    
    // 从 SKB 直接读取 mark
    bpf_probe_read_kernel(&event.skb_mark, sizeof(u32), &skb->mark);
    
    // 获取设备名称
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        bpf_probe_read_kernel_str(&event.dev_name, sizeof(event.dev_name), &dev->name);
    }
    
    upcall_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_ovs_flow_cmd_new(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct genl_info *info = (struct genl_info *)PT_REGS_PARM2(ctx);
    
    if (!skb || !info) {
        return 0;
    }
    
    struct flow_cmd_new_event_t event = {};
    event.kernel_timestamp = bpf_ktime_get_ns();  // 内核时间戳
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 初始化 mask 字段为 0xFF 来测试是否被正确写入
    __builtin_memset(event.mask_eth_src, 0xFF, ETH_ALEN);
    __builtin_memset(event.mask_eth_dst, 0xFF, ETH_ALEN);
    
    // 读取 netlink portid
    if (bpf_probe_read_kernel(&event.netlink_portid, sizeof(event.netlink_portid), &info->snd_portid) < 0) {
        event.netlink_portid = 0;
    }
    
    // 读取 dp_ifindex
    struct ovs_header {
        int dp_ifindex;
    } ovs_hdr;
    
    void *userhdr;
    if (bpf_probe_read_kernel(&userhdr, sizeof(userhdr), &info->userhdr) == 0 && userhdr) {
        if (bpf_probe_read_kernel(&ovs_hdr, sizeof(ovs_hdr), userhdr) == 0) {
            event.dp_ifindex = ovs_hdr.dp_ifindex;
        }
    }
    
    // 读取 attrs 数组
    void *attrs;
    if (bpf_probe_read_kernel(&attrs, sizeof(attrs), &info->attrs) < 0) {
        event.parse_status = 1;
        flow_cmd_new_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    
    // 读取 OVS_FLOW_ATTR_KEY
    void *key_attr = NULL;
    if (bpf_probe_read_kernel(&key_attr, sizeof(key_attr), attrs + (OVS_FLOW_ATTR_KEY * sizeof(void*))) == 0 && key_attr) {
        event.has_key = 1;
        event.key_attr_ptr = (u64)key_attr;
        
        // 读取属性长度
        struct nlattr key_nla;
        if (bpf_probe_read_kernel(&key_nla, sizeof(key_nla), key_attr) == 0) {
            event.key_attr_len = key_nla.nla_len;
            
            // 解析 key 内容 (简化版)
            void *key_data = key_attr + sizeof(struct nlattr);
            u32 key_data_len = key_nla.nla_len - sizeof(struct nlattr);
            parse_flow_key_simple(key_data, key_data_len, &event);
        }
    }
    
    // 检查是否有 mask 并解析
    void *mask_attr = NULL;
    if (bpf_probe_read_kernel(&mask_attr, sizeof(mask_attr), attrs + (OVS_FLOW_ATTR_MASK * sizeof(void*))) == 0 && mask_attr) {
        event.has_mask = 1;
        
        // 解析 mask 内容
        struct nlattr mask_nla;
        if (bpf_probe_read_kernel(&mask_nla, sizeof(mask_nla), mask_attr) == 0) {
            void *mask_data = mask_attr + sizeof(struct nlattr);
            u32 mask_data_len = mask_nla.nla_len - sizeof(struct nlattr);
            parse_mask_key_simple(mask_data, mask_data_len, &event);
        }
    }
    
    flow_cmd_new_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class UpcallEvent(ct.Structure):
    _fields_ = [
        ("kernel_timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("portid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("skb_eth_dst", ct.c_ubyte * 6),
        ("skb_eth_src", ct.c_ubyte * 6),
        ("skb_eth_type", ct.c_uint16),
        ("skb_src_ip", ct.c_uint32),
        ("skb_dst_ip", ct.c_uint32),
        ("skb_src_port", ct.c_uint16),
        ("skb_dst_port", ct.c_uint16),
        ("skb_ip_proto", ct.c_uint8),
        ("skb_mark", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("parse_status", ct.c_uint32),
    ]

class FlowCmdNewEvent(ct.Structure):
    _fields_ = [
        ("kernel_timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("netlink_portid", ct.c_uint32),
        ("dp_ifindex", ct.c_uint32),
        ("recirc_id", ct.c_uint32),
        ("skb_mark", ct.c_uint32),
        ("in_port", ct.c_uint16),
        ("eth_dst", ct.c_ubyte * 6),
        ("eth_src", ct.c_ubyte * 6),
        ("eth_type", ct.c_uint16),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("ip_proto", ct.c_uint8),
        ("has_key", ct.c_uint32),
        ("has_mask", ct.c_uint32),
        ("parse_status", ct.c_uint32),
        ("mask_eth_dst", ct.c_ubyte * 6),
        ("mask_eth_src", ct.c_ubyte * 6),
        ("key_attr_ptr", ct.c_ulonglong),
        ("key_attr_len", ct.c_uint32),
    ]

stats = {'upcalls': 0, 'flows': 0, 'filtered_upcalls': 0, 'filtered_flows': 0}

def mac_bytes_to_str(mac_bytes):
    return ':'.join(['%02x' % b for b in mac_bytes])

def ip_to_str(ip):
    return inet_ntop(AF_INET, pack('I', ip))

def format_kernel_timestamp(ns_timestamp):
    """直接显示原始内核时间戳（纳秒）"""
    return str(ns_timestamp)

def matches_target_filter_upcall(event):
    """检查 upcall 事件是否匹配目标过滤条件"""
    if event.parse_status != 0:  # SKB 解析失败
        return False
        
    target_mac = mac_bytes_to_str(TARGET_MAC_BYTES)
    current_mac = mac_bytes_to_str(event.skb_eth_src)
    
    mac_match = current_mac == target_mac
    type_match = event.skb_eth_type == TARGET_ETH_TYPE
    
    return mac_match and type_match

def matches_target_filter_flow(event):
    """检查 flow 事件是否匹配目标过滤条件"""
    if event.parse_status != 0 or not event.has_key:
        return False
        
    target_mac = mac_bytes_to_str(TARGET_MAC_BYTES)
    current_mac = mac_bytes_to_str(event.eth_src)
    
    mac_match = current_mac == target_mac
    type_match = event.eth_type == TARGET_ETH_TYPE
    
    return mac_match and type_match

def handle_upcall_event(cpu, data, size):
    global stats
    event = ct.cast(data, ct.POINTER(UpcallEvent)).contents
    stats['upcalls'] += 1
    
    if not matches_target_filter_upcall(event):
        return
    
    stats['filtered_upcalls'] += 1
    
    print("\n=== UPCALL EVENT (过滤后) ===")
    print("Time: %s (kernel: %s)" % (strftime('%H:%M:%S'), format_kernel_timestamp(event.kernel_timestamp)))
    print("Process: %s (PID: %d)" % (event.comm.decode('utf-8', 'replace'), event.pid))
    print("PortID: %u, Device: %s" % (event.portid, event.dev_name.decode('utf-8', 'replace')))
    print("SKB Mark: 0x%x" % event.skb_mark)
    print("SKB Eth: %s -> %s, type=0x%04x" % (
        mac_bytes_to_str(event.skb_eth_src), mac_bytes_to_str(event.skb_eth_dst), event.skb_eth_type))
    
    if event.skb_src_ip:
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(event.skb_ip_proto, str(event.skb_ip_proto))
        print("SKB IP: %s:%d -> %s:%d (%s)" % (
            ip_to_str(event.skb_src_ip), event.skb_src_port,
            ip_to_str(event.skb_dst_ip), event.skb_dst_port, proto_name))
    
    print("="*50)

def handle_flow_cmd_new_event(cpu, data, size):
    global stats
    event = ct.cast(data, ct.POINTER(FlowCmdNewEvent)).contents
    stats['flows'] += 1
    
    if not matches_target_filter_flow(event):
        return
    
    stats['filtered_flows'] += 1
    
    print("\n=== FLOW CMD NEW EVENT (过滤后) ===")
    print("Time: %s (kernel: %s)" % (strftime('%H:%M:%S'), format_kernel_timestamp(event.kernel_timestamp)))
    print("Process: %s (PID: %d)" % (event.comm.decode('utf-8', 'replace'), event.pid))
    print("DP: ifindex=%d, Netlink PortID: %u" % (event.dp_ifindex, event.netlink_portid))
    print("Key: recirc_id=%u, in_port=%u, mark=0x%x" % (event.recirc_id, event.in_port, event.skb_mark))
    print("Eth: %s -> %s, type=0x%04x" % (
        mac_bytes_to_str(event.eth_src), mac_bytes_to_str(event.eth_dst), event.eth_type))
    
    # 注意: 简化版本暂未解析 IP 和端口信息以减少 BPF 程序大小
    # if event.src_ip:
    #     proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(event.ip_proto, str(event.ip_proto))
    #     print("Flow IP: %s:%d -> %s:%d (%s)" % (
    #         ip_to_str(event.src_ip), event.src_port,
    #         ip_to_str(event.dst_ip), event.dst_port, proto_name))
    
    print("Netlink: has_key=%s, has_mask=%s" % (
        "是" if event.has_key else "否",
        "是" if event.has_mask else "否"))
    
    # 显示 mask 中的以太网地址
    if event.has_mask:
        mask_src_str = mac_bytes_to_str(event.mask_eth_src)
        mask_dst_str = mac_bytes_to_str(event.mask_eth_dst)
        print("Mask Eth: %s -> %s" % (mask_src_str, mask_dst_str))
        
        # 调试：检查是否都是零
        if mask_src_str == "00:00:00:00:00:00" and mask_dst_str == "00:00:00:00:00:00":
            print("⚠️  Mask 解析可能有问题 - 所有字段都是 0")
    
    print("="*50)

def print_debug_summary():
    """打印调试汇总信息"""
    print("\n" + "="*60)
    print("=== 统计汇总 ===")
    
    print("\n统计信息:")
    print("   总 upcall: %d" % stats['upcalls'])
    print("   过滤后 upcall: %d" % stats['filtered_upcalls'])
    print("   总 flow: %d" % stats['flows'])
    print("   过滤后 flow: %d" % stats['filtered_flows'])
    
    if stats['upcalls'] > 0:
        upcall_filter_rate = (stats['filtered_upcalls'] * 100.0) / stats['upcalls']
        print("   Upcall 过滤率: %.2f%%" % upcall_filter_rate)
    
    if stats['flows'] > 0:
        flow_filter_rate = (stats['filtered_flows'] * 100.0) / stats['flows']
        print("   Flow 过滤率: %.2f%%" % flow_filter_rate)
    
    print("="*60)

def main():
    print("OVS Megaflow Tracker V6 - 简化版")
    print("目标: eth.src=%s, eth.type=0x%04x" % (TARGET_ETH_SRC, TARGET_ETH_TYPE))
    print("功能: 独立输出 Upcall 和 Flow 事件 (不进行事件关联)\n")
    
    b = BPF(text=bpf_text)
    
    try:
        b.attach_kprobe(event="ovs_dp_upcall", fn_name="trace_ovs_dp_upcall")
        print("✅ 附加到 ovs_dp_upcall")
        
        try:
            b.attach_kprobe(event="ovs_flow_cmd_new", fn_name="trace_ovs_flow_cmd_new")
            print("✅ 附加到 ovs_flow_cmd_new")
        except Exception as e:
            print("⚠️  无法附加到 ovs_flow_cmd_new: %s" % str(e))
            
    except Exception as e:
        print("错误: %s" % str(e))
        sys.exit(1)
    
    b["upcall_events"].open_perf_buffer(handle_upcall_event)
    b["flow_cmd_new_events"].open_perf_buffer(handle_flow_cmd_new_event)
    
    print("\n🔍 开始监控...\n")
    
    try:
        while True:
            b.perf_buffer_poll()
                
    except KeyboardInterrupt:
        print("\n用户中断...")
    finally:
        print_debug_summary()

if __name__ == "__main__":
    main()