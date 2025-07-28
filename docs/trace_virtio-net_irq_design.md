# virtio-net 网卡中断处理时序信息采集

## 背景
我们遇到的问题是，vm 内部在某时刻出发了 irq 中断保护机制（99900/100000 的中断返回被 判定为 unhandled， 即返回 IRQ_NONE）,导致对应队列 （rx queue 0 ） 的中断被 disable。

## 功能
主要针对 virtio 网卡接收到的中断：
// Guest 内核中断处理
do_IRQ(unsigned int irq, struct pt_regs *regs)
├── handle_irq(irq, regs)
└── handle_edge_irq(irq, desc)
    └── handle_irq_event(desc)
        └── handle_irq_event_percpu(desc)
            └── action->handler(irq, action->dev_id)   // virtio 中断处理函数

// drivers/virtio/virtio_ring.c:939  
vring_interrupt(int irq, void *_vq)
├── more_used(vq)                                     // 检查是否有 used buffer
└── vq->vq.callback(&vq->vq)                         // 调用注册的回调
```

#### 队列特定回调

```c
// drivers/net/virtio_net.c:1269 (RX 队列回调)
skb_recv_done(struct virtqueue *rvq)
└── virtqueue_napi_schedule(&rq->napi, rvq)

这里获取指定中断号调用到 kprobe:handle_irq_event_percpu 时的中断信息， 因为中断号与 rx queue 一一对应，我们可以提前获取，我们输入的参数为 irq 号， 然后追踪该 irq 的详细信息以及处理返回值。
支持输入 1 个或者多个中断号吗。

还有一个参数为统计周期。默认值为 5s 。 

输出应当包含周期内 irq 调用handle_irq_event_percpu 的统计信息，以及返回值的统计信息。 用以确定是否包含返回 NONE 比较多的周期，以及 irq 本身信息是否正常。 