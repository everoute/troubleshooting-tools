#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
VM 中断统计工具 - 按 VM 聚合的 irqfd_wakeup 统计

基于 kvm_kernel_irqfd 中的 kvm 指针，将每个 VM 的多个 RX 队列中断进行聚合显示
支持多队列网络设备，一个 KVM 实例对应多个 irqfd 中断数据结构

功能：
1. 以 VM (KVM 指针) 为单位聚合中断统计
2. 显示每个 VM 的所有队列的中断信息  
3. 不做任何过滤，全输出所有 irqfd_wakeup 事件
4. 实时显示中断频率和分布

测试环境：虚拟化主机
"""

from __future__ import print_function
import argparse
from bcc import BPF
import ctypes as ct
import time
import signal
import sys
from collections import defaultdict, OrderedDict

# BPF程序
bpf_text = """
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/poll.h>

// 完整的 kvm_kernel_irqfd 结构定义
struct kvm_kernel_irqfd {
    /* Used for MSI fast-path */
    struct kvm *kvm;
    wait_queue_entry_t wait;
    /* Update side is protected by irq_lock */
    struct kvm_kernel_irq_routing_entry irq_entry;
    seqcount_t irq_entry_sc;
    /* Used for level-triggered shutdown */
    int gsi;
    struct work_struct inject;
    struct kvm_kernel_irq_routing_entry *irq_entry_cache;
    /* Used for resampling */
    void *resampler;  // struct kvm_kernel_irqfd_resampler *
    struct eventfd_ctx *resamplefd;
    struct list_head resampler_link;
    /* Used for shutdown */
    struct eventfd_ctx *eventfd;
    struct list_head list;
    poll_table pt;
    struct work_struct shutdown;
    void *irq_bypass_consumer;   // struct irq_bypass_consumer *
    void *irq_bypass_producer;   // struct irq_bypass_producer *
};

// 使用 member_read 和 READ_FIELD 宏
#define member_address(source_struct, source_member)            \\
        ({                                                      \\
                void* __ret;                                    \\
                __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \\
                __ret;                                          \\
})

#define member_read(destination, source_struct, source_member)  \\
        do{                                                      \\
                bpf_probe_read_kernel(                           \\
                destination,                                     \\
                sizeof(source_struct->source_member),            \\
                member_address(source_struct, source_member)     \\
                );                                               \\
        } while(0)

#define READ_FIELD(dst, ptr, field)                                   \\
    do {                                                              \\
        typeof(ptr->field) __tmp;                                     \\
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \\
        *(dst) = __tmp;                                               \\
    } while (0)

struct vm_irqfd_event {
    u64 timestamp;
    u32 cpu_id;
    u32 pid;
    char comm[16];
    
    // VM 和队列信息
    u64 kvm_ptr;           // KVM 实例指针 (VM 标识)
    u64 irqfd_ptr;         // irqfd 结构指针 (队列标识)
    u64 eventfd_ctx;       // EventFD 上下文
    u32 gsi;               // 全局系统中断号
    
    // 扩展信息
    u64 wait_ptr;          // wait queue entry 指针
    u64 resampler_ptr;     // resampler 指针
    u64 resamplefd_ptr;    // resample EventFD 指针
    
    // 调用栈信息
    u8 stack_enabled;      // 是否启用调用栈
    int stack_id;          // 调用栈 ID
};

BPF_PERF_OUTPUT(vm_irqfd_events);
BPF_STACK_TRACE(stack_traces, 4096);

// 跟踪所有 irqfd_wakeup 事件
int trace_vm_irqfd_stats(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    unsigned mode = (unsigned)PT_REGS_PARM2(ctx);
    int sync = (int)PT_REGS_PARM3(ctx);
    void *key = (void *)PT_REGS_PARM4(ctx);
    
    if (!wait) return 0;
    
    // 检查 EPOLLIN 标志 (网络中断通常是输入事件)
    u64 flags = (u64)key;
    if (!(flags & 0x1)) return 0;
    
    // 使用 container_of 获取 kvm_kernel_irqfd 结构
    struct kvm_kernel_irqfd *irqfd = (struct kvm_kernel_irqfd *)
        ((char *)wait - offsetof(struct kvm_kernel_irqfd, wait));
        
    if (!irqfd) return 0;
    
    // 使用 READ_FIELD 宏读取所有关键字段
    struct kvm *kvm = NULL;
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;
    void *resampler = NULL;
    struct eventfd_ctx *resamplefd = NULL;
    
    READ_FIELD(&kvm, irqfd, kvm);
    READ_FIELD(&eventfd, irqfd, eventfd);
    READ_FIELD(&gsi, irqfd, gsi);
    READ_FIELD(&resampler, irqfd, resampler);
    READ_FIELD(&resamplefd, irqfd, resamplefd);
    
    // 验证关键字段有效性
    if (!kvm || !eventfd || (u64)kvm < 0xffff000000000000ULL || (u64)eventfd < 0xffff000000000000ULL) {
        return 0;
    }
    
    // 构造事件
    struct vm_irqfd_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.cpu_id = bpf_get_smp_processor_id();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.kvm_ptr = (u64)kvm;
    event.irqfd_ptr = (u64)irqfd;
    event.eventfd_ctx = (u64)eventfd;
    event.gsi = (u32)gsi;
    event.wait_ptr = (u64)wait;
    event.resampler_ptr = (u64)resampler;
    event.resamplefd_ptr = (u64)resamplefd;
    
    // 获取调用栈 (如果启用)
    event.stack_enabled = STACK_ENABLED;
    if (STACK_ENABLED) {
        event.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    } else {
        event.stack_id = -1;
    }
    
    vm_irqfd_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class VMIrqfdEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("cpu_id", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        
        ("kvm_ptr", ct.c_uint64),
        ("irqfd_ptr", ct.c_uint64),
        ("eventfd_ctx", ct.c_uint64),
        ("gsi", ct.c_uint32),
        
        ("wait_ptr", ct.c_uint64),
        ("resampler_ptr", ct.c_uint64),
        ("resamplefd_ptr", ct.c_uint64),
        
        ("stack_enabled", ct.c_uint8),
        ("stack_id", ct.c_int32),
    ]

# 全局统计数据
vm_stats = defaultdict(lambda: {
    'total_interrupts': 0,
    'queues': defaultdict(lambda: {
        'count': 0,
        'gsi': None,
        'eventfd': None,
        'first_time': None,
        'last_time': None,
        'cpus': set(),
        'pids': set(),
        'comms': set()
    }),
    'first_seen': None,
    'last_seen': None
})

total_events = 0
start_time = None

# 全局过滤参数
filter_vhost_pid = None
filter_vhost_comm = None
filter_rx_only = False
filter_tx_only = False
enable_stack_trace = False
filter_category = None  # 'data', 'control', or None for all
filter_subcategory = None  # 'vhost-rx', 'vhost-tx', 'qemu', or None for all

# 全局 BPF 实例和调用栈缓存
bpf_instance = None
stack_cache = {}

def get_stack_trace(stack_id):
    """获取并格式化调用栈"""
    global bpf_instance, stack_cache
    
    if stack_id < 0 or not bpf_instance:
        return []
    
    # 检查缓存
    if stack_id in stack_cache:
        return stack_cache[stack_id]
    
    try:
        stack = list(bpf_instance["stack_traces"].walk(stack_id))
        formatted_stack = []
        
        for addr in stack:
            sym = bpf_instance.ksym(addr, show_module=True, show_offset=True)
            if sym:
                formatted_stack.append(sym)
            else:
                formatted_stack.append("0x{:x}".format(addr))
        
        # 缓存结果
        stack_cache[stack_id] = formatted_stack
        return formatted_stack
        
    except Exception as e:
        return ["Failed to get stack: {}".format(str(e))]

def classify_interrupt(comm_str, stack_trace):
    """基于进程名和调用栈分类中断
    返回: (category, subcategory) 元组
    category: 'data' 或 'control'
    subcategory: 'vhost-rx', 'vhost-tx', 或 'qemu'
    """
    # 控制面：QEMU进程触发
    if comm_str.startswith('qemu'):
        return ('control', 'qemu')
    
    # 数据面：vhost进程触发
    if comm_str.startswith('vhost-'):
        # 检查调用栈以区分 RX 和 TX
        if stack_trace:
            stack_str = ' '.join(stack_trace)
            
            # 检查是否包含 handle_rx 函数（RX路径）
            if 'handle_rx' in stack_str:
                return ('data', 'vhost-rx')
            
            # 检查是否包含 handle_tx 或 handle_tx_copy 函数（TX路径）
            if 'handle_tx' in stack_str or 'handle_tx_copy' in stack_str:
                return ('data', 'vhost-tx')
            
            # 如果没有明确的函数标识，尝试通过其他线索判断
            # TX路径通常包含 vhost_net_tx 相关函数
            if 'vhost_net_tx' in stack_str or 'vhost_tx' in stack_str:
                return ('data', 'vhost-tx')
            
            # RX路径通常包含 vhost_net_rx 相关函数
            if 'vhost_net_rx' in stack_str or 'vhost_rx' in stack_str:
                return ('data', 'vhost-rx')
        
        # 默认情况下，如果无法从调用栈判断，返回未知的数据面中断
        return ('data', 'vhost-unknown')
    
    # 其他情况
    return ('unknown', 'unknown')

def process_event(cpu, data, size):
    global total_events, start_time, filter_vhost_pid, filter_vhost_comm, filter_rx_only, filter_tx_only, enable_stack_trace, filter_category, filter_subcategory
    
    event = ct.cast(data, ct.POINTER(VMIrqfdEvent)).contents
    
    if start_time is None:
        start_time = time.time()
    
    import datetime
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    comm_str = event.comm.decode('utf-8', 'replace')
    
    # 获取调用栈（用于分类）
    stack_trace = []
    if event.stack_enabled and event.stack_id >= 0:
        stack_trace = get_stack_trace(event.stack_id)
    
    # 对中断进行分类
    category, subcategory = classify_interrupt(comm_str, stack_trace)
    
    # 应用过滤条件
    should_show = True
    
    # VHOST PID 过滤
    if filter_vhost_pid and event.pid != filter_vhost_pid:
        should_show = False
    
    # VHOST COMM 过滤
    if filter_vhost_comm and filter_vhost_comm not in comm_str:
        should_show = False
    
    # 类别过滤
    if filter_category and category != filter_category:
        should_show = False
    
    # 子类别过滤
    if filter_subcategory and subcategory != filter_subcategory:
        should_show = False
    
    # 旧的 RX/TX 过滤（保持向后兼容）
    if filter_rx_only and subcategory != 'vhost-rx':
        should_show = False
    
    if filter_tx_only and subcategory != 'vhost-tx':
        should_show = False
    
    if not should_show:
        return
    
    total_events += 1
    kvm_ptr = event.kvm_ptr
    irqfd_ptr = event.irqfd_ptr
    
    # 更新 VM 统计
    vm_stat = vm_stats[kvm_ptr]
    vm_stat['total_interrupts'] += 1
    
    if vm_stat['first_seen'] is None:
        vm_stat['first_seen'] = timestamp_str
    vm_stat['last_seen'] = timestamp_str
    
    # 更新队列统计 (以 irqfd_ptr 为队列标识)
    queue_stat = vm_stat['queues'][irqfd_ptr]
    queue_stat['count'] += 1
    queue_stat['gsi'] = event.gsi
    queue_stat['eventfd'] = event.eventfd_ctx
    
    if queue_stat['first_time'] is None:
        queue_stat['first_time'] = timestamp_str
    queue_stat['last_time'] = timestamp_str
    
    queue_stat['cpus'].add(event.cpu_id)
    queue_stat['pids'].add(event.pid)
    queue_stat['comms'].add(comm_str)
    
    # 创建中断类型标签
    if subcategory == 'vhost-rx':
        type_label = "[数据面-RX]"
    elif subcategory == 'vhost-tx':
        type_label = "[数据面-TX]"
    elif subcategory == 'qemu':
        type_label = "[控制面]"
    else:
        type_label = "[{}]".format(subcategory)
    
    # 实时输出事件
    print("{} VM=0x{:x} Queue=0x{:x} GSI={} EventFD=0x{:x} Time={} CPU={} PID={} COMM={}".format(
        type_label, kvm_ptr, irqfd_ptr, event.gsi, event.eventfd_ctx,
        timestamp_str, event.cpu_id, event.pid, comm_str))
    
    # 输出调用栈 (如果启用)
    if enable_stack_trace and stack_trace:
        print("  📋 调用栈:")
        for i, frame in enumerate(stack_trace[:10]):  # 限制显示前10层
            # 高亮显示关键函数
            if 'handle_rx' in frame:
                print("    #{}: {} ⬅️ RX处理函数".format(i, frame))
            elif 'handle_tx' in frame or 'handle_tx_copy' in frame:
                print("    #{}: {} ⬅️ TX处理函数".format(i, frame))
            else:
                print("    #{}: {}".format(i, frame))
        print()

def print_summary():
    current_time = time.time()
    duration = current_time - start_time if start_time else 0
    
    print("\n" + "="*100)
    print("VM 中断统计汇总 (按 KVM 实例聚合)")
    print("="*100)
    print("监控时长: {:.2f} 秒".format(duration))
    print("总中断数: {}".format(total_events))
    print("发现 VM 数量: {}".format(len(vm_stats)))
    
    if duration > 0:
        print("总中断频率: {:.2f} 中断/秒".format(total_events / duration))
    print()
    
    # 按 VM 显示详细统计
    for vm_idx, (kvm_ptr, vm_stat) in enumerate(sorted(vm_stats.items()), 1):
        print("🖥️  VM #{} (KVM=0x{:x})".format(vm_idx, kvm_ptr))
        print("   总中断数: {}".format(vm_stat['total_interrupts']))
        print("   队列数量: {}".format(len(vm_stat['queues'])))
        print("   活动时间: {} -> {}".format(vm_stat['first_seen'], vm_stat['last_seen']))
        
        if duration > 0:
            vm_rate = vm_stat['total_interrupts'] / duration
            print("   中断频率: {:.2f} 中断/秒".format(vm_rate))
        
        # 显示每个队列的详细信息
        print("   队列详情:")
        for queue_idx, (irqfd_ptr, queue_stat) in enumerate(sorted(vm_stat['queues'].items()), 1):
            queue_rate = ""
            if duration > 0:
                rate = queue_stat['count'] / duration
                queue_rate = " ({:.2f}/秒)".format(rate)
            
            print("     📡 队列 #{}: IRQFD=0x{:x}".format(queue_idx, irqfd_ptr))
            print("        GSI: {}".format(queue_stat['gsi']))
            print("        EventFD: 0x{:x}".format(queue_stat['eventfd']))
            print("        中断数: {}{}".format(queue_stat['count'], queue_rate))
            print("        活动时间: {} -> {}".format(queue_stat['first_time'], queue_stat['last_time']))
            print("        CPU分布: {}".format(sorted(list(queue_stat['cpus']))))
            print("        进程: {} (PID: {})".format(
                ', '.join(list(queue_stat['comms'])[:3]),
                ', '.join(str(pid) for pid in sorted(list(queue_stat['pids']))[:3])
            ))
        print()
    
    print("📊 队列分布分析:")
    single_queue_vms = sum(1 for vm_stat in vm_stats.values() if len(vm_stat['queues']) == 1)
    multi_queue_vms = len(vm_stats) - single_queue_vms
    
    print("   单队列 VM: {} 个".format(single_queue_vms))
    print("   多队列 VM: {} 个".format(multi_queue_vms))
    
    if multi_queue_vms > 0:
        max_queues = max(len(vm_stat['queues']) for vm_stat in vm_stats.values())
        print("   最大队列数: {}".format(max_queues))

def signal_handler(sig, frame):
    print("\n\n收到中断信号，正在生成汇总...")
    print_summary()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="VM 中断统计工具 - 按 VM 聚合的 irqfd_wakeup 统计")
    parser.add_argument("--timeout", type=int, default=60, help="监控时间 (秒)")
    parser.add_argument("--summary-interval", type=int, default=10, help="汇总显示间隔 (秒)")
    parser.add_argument("--vhost-pid", type=int, help="过滤特定 VHOST 进程 PID")
    parser.add_argument("--vhost-comm", type=str, help="过滤特定 VHOST 进程名 (如 vhost-12345)")
    parser.add_argument("--rx-only", action="store_true", help="仅显示数据面 RX 中断 (vhost-rx)")
    parser.add_argument("--tx-only", action="store_true", help="仅显示数据面 TX 中断 (vhost-tx)")
    parser.add_argument("--category", choices=['data', 'control'], help="过滤中断类别: data(数据面) 或 control(控制面)")
    parser.add_argument("--subcategory", choices=['vhost-rx', 'vhost-tx', 'qemu'], help="过滤中断子类别")
    parser.add_argument("--stack-trace", action="store_true", help="启用调用栈跟踪 (分析模块交互和数据路径)")
    args = parser.parse_args()
    
    # 设置全局过滤参数
    global filter_vhost_pid, filter_vhost_comm, filter_rx_only, filter_tx_only, enable_stack_trace, bpf_instance, filter_category, filter_subcategory
    filter_vhost_pid = args.vhost_pid
    filter_vhost_comm = args.vhost_comm
    filter_rx_only = args.rx_only
    filter_tx_only = args.tx_only
    enable_stack_trace = args.stack_trace
    filter_category = args.category
    filter_subcategory = args.subcategory
    
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("加载 VM 中断统计程序...")
    try:
        # 处理 STACK_ENABLED 宏
        bpf_text_with_macro = "#define STACK_ENABLED %d\n\n%s" % (
            1 if enable_stack_trace else 0,
            bpf_text
        )
        
        b = BPF(text=bpf_text_with_macro)
        bpf_instance = b  # 保存全局引用
        b.attach_kprobe(event="irqfd_wakeup", fn_name="trace_vm_irqfd_stats")
        print("✅ 成功附加到 irqfd_wakeup")
        if enable_stack_trace:
            print("✅ 调用栈跟踪已启用")
    except Exception as e:
        print("❌ 加载失败: {}".format(e))
        return
    
    print("\n" + "="*80)
    print("VM 中断统计监控 (按 KVM 实例聚合)")
    print("="*80)
    print("🎯 功能:")
    print("  • 以 VM (KVM 指针) 为单位聚合中断统计")
    print("  • 显示每个 VM 的多个 RX/TX 队列中断信息")
    print("  • 支持多队列网络设备分析")
    print("  • 实时显示中断频率和分布")
    
    # 显示过滤条件
    filters = []
    if filter_vhost_pid:
        filters.append("VHOST PID: {}".format(filter_vhost_pid))
    if filter_vhost_comm:
        filters.append("VHOST COMM: {}".format(filter_vhost_comm))
    if filter_category:
        filters.append("类别: {} ({})".format(filter_category, '数据面' if filter_category == 'data' else '控制面'))
    if filter_subcategory:
        subcategory_desc = {
            'vhost-rx': '数据面RX (Host->Guest)',
            'vhost-tx': '数据面TX完成',
            'qemu': '控制面中断'
        }
        filters.append("子类别: {} ({})".format(filter_subcategory, subcategory_desc.get(filter_subcategory, filter_subcategory)))
    if filter_rx_only:
        filters.append("仅数据面 RX 中断")
    if filter_tx_only:
        filters.append("仅数据面 TX 中断")
    
    if filters:
        print("\n🔍 过滤条件:")
        for f in filters:
            print("  • {}".format(f))
    
    if enable_stack_trace:
        print("\n📋 调用栈分析:")
        print("  • 将显示中断触发的完整调用链")
        print("  • 基于调用栈中的函数自动分类中断类型：")
        print("    - 数据面RX: 包含 handle_rx 函数 (Host->Guest 数据接收)")
        print("    - 数据面TX: 包含 handle_tx/handle_tx_copy 函数 (TX完成通知)")
        print("    - 控制面: QEMU进程触发 (配置和控制操作)")
    
    print("\n🚀 开始监控... (按 Ctrl+C 生成汇总报告)")
    print("\n中断分类说明:")
    print("  [数据面-RX] = Host->Guest 数据接收中断 (vhost进程, handle_rx)")
    print("  [数据面-TX] = TX完成通知中断 (vhost进程, handle_tx)")
    print("  [控制面]   = 配置和控制中断 (qemu-kvm进程)")
    print("="*80)
    print()
    
    # 打开性能缓冲区
    b["vm_irqfd_events"].open_perf_buffer(process_event)
    
    # 主循环
    try:
        last_summary = time.time()
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)
                
                # 定期显示汇总 (但不退出)
                current_time = time.time()
                if current_time - last_summary >= args.summary_interval and total_events > 0:
                    print("\n" + "-"*50 + " 中间汇总 " + "-"*50)
                    print_summary()
                    print("-"*100 + "\n")
                    last_summary = current_time
                    
            except KeyboardInterrupt:
                break
                
    except KeyboardInterrupt:
        pass
    
    # 最终汇总
    print_summary()

if __name__ == "__main__":
    main()