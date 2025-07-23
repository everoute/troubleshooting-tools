# 虚拟机对应 vnet 端口 tx 丢包问题定位

| 修订时间    | 修订者                                          | 描述 |
| :---------- | :---------------------------------------------- | :--- |
| Apr 1, 2024 | [Chengcheng Luo](mailto:chengcheng.luo@smartx.com) |      |
|             |                                                 |      |

# **问题**

客户环境 vm ，虚拟机内使用 netstat \-route 查看无网卡丢包（windows 虚拟机）， host 上虚拟机网卡对应的 vnet 端口 tx 丢包计数持续增加，用户部署了流量可视化，触发了持续的丢包告警。实际业务正常。

|  |
| :- |

# **分析定位**

关键数据路径分两段：

1）虚拟机内部 virtio-net 网卡 && driver 以及虚拟机内部内核网络栈；

2）host 上 ovs output 经 tun driver 最后到 vhost 后端；

其中 vnet tx drop 属于以上 2）中的部分。

其中 1）对应 vm 内部 netstat 统计显示无 rx 丢包 （对应 vnet tx，且 tx 同样无丢包），该统计包含网络栈中的 dev 丢包以及 driver 中的丢包统计，因此可以推断 virtio-net driver 层面未发生丢包（基本的假设 windows 系统 netstat 获取的接口计数类似 linux ：包含驱动 && 网络栈本身的丢包。 需要确认这点： windows 机器中使用类似 ethtool 的工具查看虚拟机对应虚拟网卡驱动层面的统计信息）

Vnet tx drop 具体来源如下具体展开：

## **用户态执行路径**

Ip \-s link 相关调用信息：

| access("/etc/selinux/config", F\_OK)     \= 0getuid()                                \= 0socket(AF\_NETLINK, SOCK\_RAW|SOCK\_CLOEXEC, NETLINK\_ROUTE) \= 3setsockopt(3, SOL\_SOCKET, SO\_SNDBUF, \[32768\], 4) \= 0setsockopt(3, SOL\_SOCKET, SO\_RCVBUF, \[1048576\], 4) \= 0setsockopt(3, SOL\_NETLINK, NETLINK\_EXT\_ACK, \[1\], 4) \= 0bind(3, {sa\_family=AF\_NETLINK, nl\_pid=0, nl\_groups=00000000}, 12) \= 0getsockname(3, {sa\_family=AF\_NETLINK, nl\_pid=93975, nl\_groups=00000000}, \[12\]) \= 0setsockopt(3, SOL\_NETLINK, NETLINK\_GET\_STRICT\_CHK, \[1\], 4) \= 0sendto(3, \[{nlmsg\_len=40, nlmsg\_type=RTM\_GETLINK, nlmsg\_flags=NLM\_F\_REQUEST|NLM\_F\_DUMP, nlmsg\_seq=1704800972, nlmsg\_pid=0}, {ifi\_family=AF\_PACKET, ifi\_type=ARPHRD\_NETROM, ifi\_index=0, ifi\_flags=0, ifi\_change=0}, \[{nla\_len=8, nla\_type=IFLA\_EXT\_MASK}, 1\]\], 40, 0, NULL, 0) \= 40 |
| :---- |

创建一个 Netlink 套接字来进行路由相关的通信。`AF_NETLINK` 表示使用 Netlink 地址族，`SOCK_RAW` 指定原始套接字，`NETLINK_ROUTE` 是 Netlink 服务类型，用于路由管理。返回值 `3` 是这个新创建套接字的文件描述符。

实际通信过程使用的 netlink msg type为 RTM\_GETLINK， flags 为 NLM\_F\_REQUEST|NLM\_F\_DUMP 。 以下查看分析相关代码。

## **Kernel && ethtool 代码分析：**

在 kernel core initialization 阶段进行各种用于 kernel 与 userspace 交互的 netlink proto 的初始化，其中就包括用于 rtnetlink 相关的初始化。

[https://elixir.bootlin.com/linux/v4.18/source/net/netlink/af\_netlink.c\#L2775](https://elixir.bootlin.com/linux/v4.18/source/net/netlink/af_netlink.c#L2775)

| static int\_\_init netlink\_proto\_init(void){int i;int err \= proto\_register(\&netlink\_proto, 0);......sock\_register(\&netlink\_family\_ops);register\_pernet\_subsys(\&netlink\_net\_ops);register\_pernet\_subsys(\&netlink\_tap\_net\_ops);/\* The netlink device handler may be needed early. \*/rtnetlink\_init();out:return err;panic:panic("netlink\_init: Cannot allocate nl\_table\\n");}core\_initcall(netlink\_proto\_init); |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

Route netlink 初始话中首先为各个 ns 初始化 netlink socket。

[https://elixir.bootlin.com/linux/v4.18/source/net/core/rtnetlink.c\#L4741](https://elixir.bootlin.com/linux/v4.18/source/net/core/rtnetlink.c#L4741)

在任意 net namespce 初始化时，创建 netlink socket 其分类为 NETLINK\_ROUTE。

| static int\_\_net\_init rtnetlink\_net\_init(struct net \*net){struct sock \*sk;struct netlink\_kernel\_cfg cfg \= {.groups \= RTNLGRP\_MAX,.input \= rtnetlink\_rcv,.cb\_mutex \= \&rtnl\_mutex,.flags \= NL\_CFG\_F\_NONROOT\_RECV,.bind \= rtnetlink\_bind,};sk \= netlink\_kernel\_create(net, NETLINK\_ROUTE, \&cfg);if (\!sk)return \-ENOMEM;net-\>rtnl \= sk;return 0;} |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

之后注册 netlink socket 的各类 msg type 对应的函数指针, 其中 ip \-s link 所使用的 RTM\_GETLINK 注册的函数为 rtnl\_getlink && rtnl\_dump\_ifinfo。

| void\_\_init rtnetlink\_init(void){if (register\_pernet\_subsys(\&rtnetlink\_net\_ops))panic("rtnetlink\_init: cannot initialize rtnetlink\\n");register\_netdevice\_notifier(\&rtnetlink\_dev\_notifier);rtnl\_register(PF\_UNSPEC, RTM\_GETLINK, rtnl\_getlink,     rtnl\_dump\_ifinfo, 0);......rtnl\_register(PF\_BRIDGE, RTM\_GETLINK, NULL, rtnl\_bridge\_getlink, 0);} |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

[https://elixir.bootlin.com/linux/v4.18/source/net/core/rtnetlink.c\#L1169](https://elixir.bootlin.com/linux/v4.18/source/net/core/rtnetlink.c#L1169)

接下来的执行路径如下，具体中间调用细节不表：

rtnl\_getlink---\> rtnl\_fill\_ifinfo \---\> rtnl\_fill\_stats \---\> dev\_get\_stats \---\>

rtnl\_dump\_ifinfo---\> rtnl\_fill\_ifinfo \---\> rtnl\_fill\_stats \---\> dev\_get\_stats \---\>

| /\*\*\* dev\_get\_stats \- get network device statistics\* @dev: device to get statistics from\* @storage: place to store stats\*\* Get network statistics from device. Return @storage.\* The device driver may provide its own method by setting\* dev-\>netdev\_ops-\>get\_stats64 or dev-\>netdev\_ops-\>get\_stats;\* otherwise the internal statistics structure is used.\*/struct rtnl\_link\_stats64 \*dev\_get\_stats(struct net\_device \*dev,struct rtnl\_link\_stats64 \*storage){const struct net\_device\_ops \*ops \= dev\-\>netdev\_ops;if (ops-\>ndo\_get\_stats64) {memset(storage, 0, sizeof(\*storage));ops-\>ndo\_get\_stats64(dev, storage);} else if (ops-\>ndo\_get\_stats) {netdev\_stats\_to\_stats64(storage, ops-\>ndo\_get\_stats(dev));} else {netdev\_stats\_to\_stats64(storage, \&dev-\>stats);}storage-\>rx\_dropped \+= (unsigned long)atomic\_long\_read(\&dev-\>rx\_dropped);storage-\>tx\_dropped \+= (unsigned long)atomic\_long\_read(\&dev-\>tx\_dropped);storage-\>rx\_nohandler \+= (unsigned long)atomic\_long\_read(\&dev-\>rx\_nohandler);return storage;}EXPORT\_SYMBOL(dev\_get\_stats); |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

优先使用 dev 驱动注册的 ndo\_get\_stats/ndo\_get\_stats64 回调函数从 dev 获取设备以及驱动层次的 packet drop 计数，并将这部分数据 copy 到与用户态交互接口使用的数据结构 rtnl\_link\_stats64 前半部分（前部分字段以及顺序完全相同），并将后一部分 rtnl\_link\_stats64 特有的字段置 0。

如果驱动没有注册 ndo\_get\_stats/ndo\_get\_stats64，则直接 copy dev-\>stats 到 rtnl\_link\_stats64 ，实际上 dev-stats rx 计数不会通过其他途径更新。 如果 driver 没有定义 ndo\_get\_stats/ndo\_get\_stats64 的话必须实现异步的将 driver 中的设备统计同步至 dev stats 的机制（[https://elixir.bootlin.com/linux/v4.18/source/include/linux/netdevice.h\#L986](https://elixir.bootlin.com/linux/v4.18/source/include/linux/netdevice.h#L986)）。

最后，分别将 skb-\>dev 中保存的 rx\_dropped/tx\_dropped/rx\_nohandler 加到 rtnl\_link\_stats64 的对应项目上。

至此可以确定 vnet tx\_dropped 主要来自两个部分：
1）skb-\>dev 中的 tx\_dropped;

2\)  tun driver 中统计的 tx\_dropped;

其中 skb-\>dev 中的 drop 来源是数据包在 host 上经 ovs 处理发送至 vnet 驱动前被统计为 drop 的部分（），这部分事实上不涉及协议栈处理，因此不会是常规的 unkonw protocol 等处理逻辑导致的丢包，具体后续展开。

下面分别分这两部分数据来源。

## **Tun driver**

分析代码寻找 dev-\>rx\_dropped 计数可能增加的场景：

### **Tap filter**

1. `count`：表示过滤器中的地址数量。如果 `count` 为零，则表示过滤器被禁用。
2. `mask`：一个包含两个元素的 `u32` 类型的数组，用于存储哈希地址的掩码。通过对地址进行哈希运算并与掩码进行比较，可以快速判断地址是否与过滤器匹配。
3. `addr`：一个二维数组，用于存储精确匹配的地址。数组的第一维大小为 `FLT_EXACT_COUNT`，即精确匹配地址的最大数量，默认为8。第二维大小为 `ETH_ALEN`，表示以太网地址的长度（通常为6个字节）

| struct[tap\_filter](https://elixir.bootlin.com/linux/v4.19.90/C/ident/tap_filter) { 	unsigned int    count;    */\* Number of addrs. Zero means disabled \*/* 	[u32](https://elixir.bootlin.com/linux/v4.19.90/C/ident/u32)             mask\[2\];  */\* Mask of the hashed addrs \*/* 	unsigned char	addr\[[FLT\_EXACT\_COUNT](https://elixir.bootlin.com/linux/v4.19.90/C/ident/FLT_EXACT_COUNT)\]\[[ETH\_ALEN](https://elixir.bootlin.com/linux/v4.19.90/C/ident/ETH_ALEN)\]; }; |
| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

用于让 tun/tap 设备过滤特定类型的数据包，不满足 tap fileter 设定的数据包将被 drop （tx 方向）。

### **Sk filter**

|  |
| :- |

其中两处可能 变更 dev-\>rx\_dropped 计数的代码如上。

|  |
| :- |

运行 ebpf 程序

### **Ebpf filter**

### **Orphan frag rx**

#### **Tx zero copy**

Copy 内存出错

#### **Non tx zero copy**

一定成功

### **Ring produce**

Tun\_net\_xmit → sk\_data\_ready \-\> sock\_def\_readable()

| static void sock\_def\_readable(struct sock \*sk){	struct socket\_wq \*wq;	rcu\_read\_lock();	wq \= rcu\_dereference(sk-\>sk\_wq);	if (skwq\_has\_sleeper(wq))		wake\_up\_interruptible\_sync\_poll(\&wq-\>wait, EPOLLIN | EPOLLPRI |						EPOLLRDNORM | EPOLLRDBAND);	sk\_wake\_async(sk, SOCK\_WAKE\_WAITD, POLL\_IN);	rcu\_read\_unlock();} |
| :---- |

| static inline void sk\_wake\_async(const struct sock \*sk, int how, int band){	if (sock\_flag(sk, SOCK\_FASYNC)) {		rcu\_read\_lock();		sock\_wake\_async(rcu\_dereference(sk-\>sk\_wq), how, band);		rcu\_read\_unlock();	}} |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

向sk 对应 file 发送 POLL\_IN singnal。

| static void kill\_fasync\_rcu(struct fasync\_struct \*fa, int sig, int band){	while (fa) {		struct fown\_struct \*fown;		if (fa-\>magic \!= FASYNC\_MAGIC) {			printk(KERN\_ERR "kill\_fasync: bad magic number in "			       "fasync\_struct\!\\n");			return;		}		read\_lock(\&fa-\>fa\_lock);		if (fa-\>fa\_file) {			fown \= \&fa-\>fa\_file-\>f\_owner;			/\* Don't send SIGURG to processes which have not set a			   queued signum: SIGURG has its own default signalling			   mechanism. \*/			if (\!(sig \== SIGURG && fown-\>signum \== 0))				send\_sigio(fown, fa-\>fa\_fd, band);		}		read\_unlock(\&fa-\>fa\_lock);		fa \= rcu\_dereference(fa-\>fa\_next);	}} |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

Vhost 捕获 POLL\_IN singal

| const struct file\_operations fuse\_dev\_operations \= {	.owner		\= THIS\_MODULE,	.open		\= fuse\_dev\_open,	.llseek		\= no\_llseek,	.read\_iter	\= fuse\_dev\_read,	.splice\_read	\= fuse\_dev\_splice\_read,	.write\_iter	\= fuse\_dev\_write,	.splice\_write	\= fuse\_dev\_splice\_write,	.poll		\= fuse\_dev\_poll,	.release	\= fuse\_dev\_release,	.fasync		\= fuse\_dev\_fasync,	.unlocked\_ioctl \= fuse\_dev\_ioctl,	.compat\_ioctl   \= fuse\_dev\_ioctl,};EXPORT\_SYMBOL\_GPL(fuse\_dev\_operations);static struct miscdevice fuse\_miscdevice \= {	.minor \= FUSE\_MINOR,	.name  \= "fuse",	.fops \= \&fuse\_dev\_operations,}; |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

Miscdevice-\>fops-\>write\_iter 在 misc device dirver 初始化是被定义为 [**fuse\_dev\_write**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/fuse_dev_write) ， 因此 misc device write 操作时调用 fuse\_dev\_write ， 对 misc 设备进行写。
[**Write\_iter**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/write_iter) \-\> [**fuse\_dev\_write**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/fuse_dev_write) \-\> [**fuse\_dev\_do\_write**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/fuse_dev_do_write) \-\>
[**Fuse\_notify**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/fuse_notify) \-\> [**Fuse\_notify\_poll**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/fuse_notify_poll) **\-\>** fuse\_notify\_poll\_wakeup

| /\* \* This is called from fuse\_handle\_notify() on FUSE\_NOTIFY\_POLL and \* wakes up the poll waiters. \*/int fuse\_notify\_poll\_wakeup(struct fuse\_conn \*fc,			    struct fuse\_notify\_poll\_wakeup\_out \*outarg){	u64 kh \= outarg-\>kh;	struct rb\_node \*\*link;	spin\_lock(\&fc-\>lock);	link \= fuse\_find\_polled\_node(fc, kh, NULL);	if (\*link) {		struct fuse\_file \*ff;		ff \= rb\_entry(\*link, struct fuse\_file, polled\_node);		wake\_up\_interruptible\_sync(\&ff-\>poll\_wait);	}	spin\_unlock(\&fc-\>lock);	return 0;} |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

Wake\_up\_interruptible\_sync → [**\_\_wake\_up\_sync**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/__wake_up_sync)  \-\> [**\_\_wake\_up\_sync\_key**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/__wake_up_sync_key)
[**\_\_wake\_up\_common\_lock**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/__wake_up_common_lock) \-\> [**\_\_wake\_up\_common**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/__wake_up_common_lock)

最终调用 wait\_up\_entry\_t 中注册的 wait fun，

### **Ring consumer**

qemu创建tap设备时会调用到net\_init\_tap()函数。net\_init\_tap()其中会检查选项是否指定vhost=on，如果指定，则会调用到vhost\_net\_init()进行初始化 .

[**vhost\_net\_set\_backend**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_set_backend)  [https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L1271](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L1271)
初始化 vhost-net backend 线程，包括设置 tx ring [**get\_tap\_ptr\_ring**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/get_tap_ptr_ring)
（[https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L1323](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L1323) ），每当 vhost fd 对应 sock 发生变更时重新初始化 rx\_ring && userspace buf 等数据结构。

| sock\= get\_socket(fd);	if (IS\_ERR(sock)) {		r \= PTR\_ERR(sock);		goto err\_vq;	}	/\* start polling new socket \*/	oldsock \= vq-\>private\_data;	if (sock \!= oldsock) {		ubufs \= vhost\_net\_ubuf\_alloc(vq,					     sock && vhost\_sock\_zcopy(sock));		if (IS\_ERR(ubufs)) {			r \= PTR\_ERR(ubufs);			goto err\_ubufs;		}		vhost\_net\_disable\_vq(n, vq);		vq-\>private\_data \= sock;		vhost\_net\_buf\_unproduce(nvq);		r \= vhost\_vq\_init\_access(vq);		if (r)			goto err\_used;		r \= vhost\_net\_enable\_vq(n, vq);		if (r)			goto err\_used;		if (index \== VHOST\_NET\_VQ\_RX)			nvq-\>rx\_ring \= get\_tap\_ptr\_ring(fd);		oldubufs \= nvq-\>ubufs;		nvq-\>ubufs \= ubufs; |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

Get\_tap\_ptr\_ring 将 fd 对应的 tun 设备队列对应的 ptr\_ring 赋给 nvq-\>rx\_ring 。

[https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L1322](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L1322)   vhost rx\_ring init ( tun tx-\>fd-\>ptr-ring)

Handle\_rx\_kick

Handle\_rx ( [https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L884](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L884))
[**Vhost\_net\_rx\_peek\_head\_len**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_rx_peek_head_len) ( [https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L756](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L756))
[**Peek\_head\_len**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/peek_head_len)  ([https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L725](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L725) )
[**Vhost\_net\_buf\_peek**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_buf_peek) [https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L202](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L202)
使用 vhost-\>rvq-\>rx\_ring, 读取，生成/恢复（？）中断注入。 `vhost_net_buf_peek` 函数用于查看 vhost\_net 虚拟队列的接收缓冲区中的数据长度。它首先检查接收缓冲区是否为空，如果为空，则尝试生成新的缓冲区。如果接收缓冲区不为空或成功生成了新的缓冲区，函数将返回缓冲区中数据的长度。如果无法生成新的缓冲区，函数返回 0。
[**Ptr\_ring\_consume\_batched**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/ptr_ring_consume_batched)  ([https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c\#L174](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/vhost/net.c#L174) )
从 producer 写的 ptr\_ring 中读取。

不使用 Rx\_ring 的话直接使用 sk 的接收队列（什么情况下这么使用？）

Vhost\_net\_buf 的 producer 的数据来源是 ptr\_ring ， 其作为 ptr\_ring 的 consumer 读取 ptr\_ring 可用 items，

其中 vhost\_net\_buf  produce 写 , handle\_rx 处理从 host 发往 guest ：
[**Vhost\_net\_rx\_peek\_head\_len**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_rx_peek_head_len) \-\> [**Peek\_head\_len**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/peek_head_len) \-\> [**vhost\_net\_buf\_peek**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_buf_peek) , vhost-rxq-\>rx\_ring 存在，则走 rx\_ring consume 逻辑， vhost  buf producer 的上游是 vhost\_net\_virtqueue-\>rx\_ring，否则，上游是 skb\_receive\_queue。

| static int peek\_head\_len(struct vhost\_net\_virtqueue \*rvq, struct sock \*sk){	struct sk\_buff \*head;	int len \= 0;	unsigned long flags;	if (rvq-\>rx\_ring)		return vhost\_net\_buf\_peek(rvq);	spin\_lock\_irqsave(\&sk-\>sk\_receive\_queue.lock, flags);	head \= skb\_peek(\&sk-\>sk\_receive\_queue);	if (likely(head)) {		len \= head-\>len;		if (skb\_vlan\_tag\_present(head))			len \+= VLAN\_HLEN;	}	spin\_unlock\_irqrestore(\&sk-\>sk\_receive\_queue.lock, flags);	return len;} |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |

[**vhost\_net\_virtqueue**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_virtqueue)\-\>rxq-\>queue-\>tail 为 i（总共从 ptr\_ring 中成功 consume 的 item 数），

Ptr\_ring consume 读： 依次从 ptr\_ring 中通过 consume 读取可用 item 的 pointer，并将指针分配给 [**vhost\_net\_virtqueue**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/vhost_net_virtqueue)\-\>rxq-\>queue\[i\], 其中 i 为读取 batch 中的序列号，直到 consume 读取到 NULL 指针，意味着没有可以 consume 的 item，结束，返回 i ，即共读取的 item 数。

* [ ] 何时更新 ptr\_ring-\>consumer\_tail ? 应当在 consumer 对应的 vhost producer 读取相应 ptr，然后将 ptr 相应数据 交给 virtio-device， virtio-device 处理完该数据段，最后通知 vhost 更新。

## **Kvm /qemu**

## **Virtio driver（frontend）**

注入 guest 的中断处理结束，调用 virtqueue 注册的 callback [**skb\_recv\_done**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/skb_recv_done) **[https://elixir.bootlin.com/linux/v4.19.90/source/drivers/net/virtio\_net.c\#L2726）](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/net/virtio_net.c#L2726）)**

[**Virtnet\_restore**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtnet_restore) **\-\> [virtnet\_restore\_up](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtnet_restore_up) \-\> [init\_vqs](https://elixir.bootlin.com/linux/v4.19.90/C/ident/init_vqs) \-\>  [virtnet\_find\_vqs](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtnet_find_vqs) \-\>**

Restore 过程开启 napi，进行 polling， 注册 rx/tx queue 的 callback 用于中断处理结束后操作。 其调用  [virtqueue\_napi\_schedule](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtqueue_napi_schedule) 即就是开始 napi polling， 关闭 queue 的 中断 （[**virtqueue\_disable\_cb**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtqueue_disable_cb)

），避免连续中断带来的性能开销。 开始 napi poll （[**\_\_napi\_schedule**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/__napi_schedule)）。最终调用 [**virtnet\_poll**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/virtnet_poll)

,

这里主要是 vq 对应的 used/avail ring 以及 desc ring 的获取/归还操作：

virtio网卡队列中的几个重要参数，即avail-\>idx、used-\>idx和last\_used\_idx。使用这些参数，我们可以清晰地了解网卡队列当前包含的报文数量，并进一步得到以下可观测指标：

a.发送队列报文数：表示尚未被virtio网卡后端发送的报文数量。计算方法是avail-\>idx \- used-\>idx；

b.接收队列报文数：表示尚未被virtio网卡前端接收的报文数量。计算方法是used-\>idx \- last\_used\_idx；

C.网卡队列的last\_used\_idx：表示virtio网卡后端处理报文的进度；

virito网卡前端接收报文主要流程包括

a.网卡硬中断：硬中断会将napi加入到CPU的处理队列，并启用中断抑制，以及触发软中断；

b.net\_rx\_action：网络软中断入口函数；

c.virtnet\_poll：这个函数是virtio网卡的NAPI poll的回调函数。如果当前队列是发送队列，它将清理发送队列，也就是执行virtnet\_poll\_cleantx函数。如果当前队列是接收队列，它将进行报文的接收；

d.virtnet\_receive：根据used-\>idx 的值，从描述符环中读取报文数据，并更新 last\_used\_idx。内核会为报文数据分配skb，并进入GRO流程，进行报文的合并；e.try\_fill\_recv：要给 desc 环添加空的内存区域，并增加 avail-\>idx 的值，以确保接收队列始终有可用的内存；

f.virtqueue\_napi\_complete：当接收的报文数量少于预定的budget（一般为64）时，表示没有更多的数据可以接收。这时，调用virtqueue\_napi\_complete来表示单次napi处理完毕。同时，通过virtqueue\_enable\_cb\_prepare来关闭中断抑制

 virto网卡前端发送报文主要流程包括：

a.start\_xmit：virtio网卡驱动的报文发送入口函数会首先清理已发送的报文，即通过调用free\_old\_xmit\_skbs函数来释放描述符中的报文，直到avail-\>idx等于used-\>idx为止；

b.xmit\_skb：主要是为报文添加vnet\_hdr头部信息，并将skb以scatter-gather形式显示，以记录报文数据的地址和长度信息；

c.virtqueue\_add\_outbuf：进行DMA映射，将scatter-gather记录的报文数据地址和长度信息添加到desc环中，并增加avail-\>idx的值；

d.virtqueue\_notify：当发送队列存在数据，则通知后端。

## **Skb dev statistics**

[https://elixir.bootlin.com/linux/v4.19.90/source/net/openvswitch/actions.c\#L961](https://elixir.bootlin.com/linux/v4.19.90/source/net/openvswitch/actions.c#L961)

Skb dev 切换，开篇推测的无二致， tun 设备作为 ovs 注册的 netdev vport，并没有为其添加 dev-\>tx\_dropped, 仅有一处更新 dev-\>stats-\>tx\_error, 改值也不会进入 tx\_dropped
[**Ovs\_vport\_send**](https://elixir.bootlin.com/linux/v4.19.90/C/ident/ovs_vport_send) [https://elixir.bootlin.com/linux/v4.19.90/source/net/openvswitch/vport.c\#L484](https://elixir.bootlin.com/linux/v4.19.90/source/net/openvswitch/vport.c#L484)
调用 netdev vport 注册的回调函数，ops-\>send() , 真正意义上的发送数据包，此时 skb-\>dev 还未更新为 output port 对应的 netdev ，因此有可能增加 tx\_dropped 计数的逻辑都在此之后。

# **Tracing 结果**

|  |
| :- |

在 host 上抓包的结果：

### **可能的解决方法**

1. [https://elixir.bootlin.com/linux/v4.19.90/source/drivers/net/tun.c\#L840](https://elixir.bootlin.com/linux/v4.19.90/source/drivers/net/tun.c#L840)Tun 端口初始化时配置 tx\_queue\_len 1000, ptr\_ring size 对应 tun-\>dev-\>tx\_queue\_len 。 直接调节 tun dev tx queue\_len 可以缓解该问题。
   1. 类似的，当 tun dev tx queue len 为 0 ，则不初始化 tun \-\>tx\_ring, vhost rx\_ring 为 NULL， 则直接从 skb queue 读取，免去 tx queue full 造成的问题（？）。
2. 调大 cpu
   1. 针对 burst 造成的短时间丢包作用有限
3. Vm 内部数据路径上存在若干段 consumer /producer pair，且各个分段的 cpu 调度策略不同，burst 期间必然发生特定段 cpu 瓶颈，非常常见的是：1） softirq 处理瓶颈；2）socket 处理瓶颈；3）用户态程序读写瓶颈。
   1. Softirq 瓶颈调整 napi buget 值
   2. 调整 socket buffer
   3. 调整各段 cpu 映射

在 dogfood cpu 压力较大的集群，调整 tx\_queuelen 只能使得在短时间内无丢包，但最终队列还是会累积，重新开始丢包。

其他配置： Vhost exceed weight config ？

# **其他**

该文档也梳理明确了常见的 ethtool 以及 ip route 工具获取到的网络接口上的统计信息各项内容的来源以及实际意义，可以用做定位相关问题时的参考。
