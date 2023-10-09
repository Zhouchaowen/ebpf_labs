# TC

```bash
# 为目标网卡创建clsact
tc qdisc add dev [network-device] clsact

# 加载bpf程序
tc filter add dev [network-device] <direction> bpf da obj [object-name] sec [section-name]

# 查看
tc filter show dev [network-device] <direction>
```

```bash
# 最开始的状态
$ tc qdisc show dev [network-device]
qdisc noqueue 0: root refcnt 2

# 创建clsact
$ tc qdisc add dev [network-device] clsact

# 再次查看，观察有什么不同
$ tc qdisc show dev [network-device]
qdisc noqueue 0: root refcnt 2
qdisc clsact ffff: parent ffff:fff1

# 加载TC BPF程序到容器的veth网卡上
$ tc filter add dev [network-device] <ingress|egress> bpf da obj [object-name] sec [section-name]

# 再次查看，观察有什么不同
$ tc qdisc show dev veth09e1d2e
qdisc noqueue 0: root refcnt 2
qdisc clsact ffff: parent ffff:fff1

$ tc filter show dev veth09e1d2e egress
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-xdp-drop-tcp.o:[tc] direct-action not_in_hw id 24 tag 9c60324798bac8be jited
```

```bash
# 删除 分别从 ingress 和 egress 删除所有 attach 的程序
$ tc filter del dev [network-device] ingress
$ tc filter del dev [network-device] egress

# 从 [network-device] 删除整个 clsact qdisc
# 会隐式地删除 attach 到 ingress 和 egress hook 上面的所有程序
$ tc qdisc del dev [network-device] clsact
```



# Cilium

```c
#!/bin/sh

ip netns del ns1 2> /dev/null
ip netns del ns2 2> /dev/null

ip netns add ns1
ip netns add ns2

ip link add veth1 type veth peer name veth2

ip link set veth1 netns ns1
ip link set veth2 netns ns2

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up

ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2

ip netns exec ns1 ip link add vxlan1 type vxlan external dev veth1 dstport 0
ip netns exec ns2 ip link add vxlan2 type vxlan external dev veth2 dstport 0

ip netns exec ns1 ip link set dev vxlan1 up
ip netns exec ns2 ip link set dev vxlan2 up

ip netns exec ns1 ip link add dummy1 type dummy
ip netns exec ns2 ip link add dummy2 type dummy

ip netns exec ns1 ip link set dev dummy1 up
ip netns exec ns2 ip link set dev dummy2 up

ip netns exec ns1 ip addr add 10.0.1.1/24 dev dummy1
ip netns exec ns2 ip addr add 10.0.1.2/24 dev dummy2

ip netns exec ns1 ip route add default via 10.0.1.1
ip netns exec ns2 ip route add default via 10.0.1.2

NS1_DU=`ip netns exec ns1 cat /sys/class/net/dummy1/ifindex`
NS1_VX=`ip netns exec ns1 cat /sys/class/net/vxlan1/ifindex`

NS2_DU=`ip netns exec ns2 cat /sys/class/net/dummy2/ifindex`
NS2_VX=`ip netns exec ns2 cat /sys/class/net/vxlan2/ifindex`

cat <<EOF > /tmp/bpf.c
#include "bpf_api.h"

#define TX_XMIT	0
#define TX_FRWD	1

__section("vxlan1-ingress")
int cls_entry_vx1i(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};

	skb_get_tunnel_key(skb, &key, sizeof(key), 0);

	return redirect($NS1_DU, TX_FRWD);
}

__section("dummy1-egress")
int cls_entry_vx1e(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
//	char fmt[] = "du1e %u - %x\n";

//	if (skb->tc_index)
//		return TC_ACT_OK;

	key.tunnel_id = 42;
	key.remote_ipv4 = 0x0a000102; //10.0.1.2

	skb_set_tunnel_key(skb, &key, sizeof(key), 0);
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	clone_redirect(skb, $NS1_VX, TX_XMIT);
	return TC_ACT_STOLEN;
}

__section("vxlan2-ingress")
int cls_entry_vx2i(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
//	char fmt[] = "vx2i %u - %x\n";

	skb_get_tunnel_key(skb, &key, sizeof(key), 0);
//	skb->tc_index = 1;
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	return redirect($NS2_DU, TX_FRWD);
}

__section("dummy2-egress")
int cls_entry_vx2e(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
//	char fmt[] = "du2e %u - %x\n";

//	if (skb->tc_index)
//		return TC_ACT_OK;

	key.tunnel_id = 42;
	key.remote_ipv4 = 0x0a000101; //10.0.1.1

	skb_set_tunnel_key(skb, &key, sizeof(key), 0);
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	clone_redirect(skb, $NS2_VX, TX_XMIT);
	return TC_ACT_STOLEN;
}

BPF_LICENSE("GPL");
EOF

clang -O2 -emit-llvm -I./include/ -c /tmp/bpf.c -o - | llc -march=bpf -filetype=obj -o /tmp/bpf.o

# Still need this prio bandaid as we don't have prequeue yet, can become a bottleneck due to locking
ip netns exec ns1 tc qdisc add dev dummy1 root handle eeee: prio bands 3
ip netns exec ns1 tc qdisc add dev vxlan1 ingress

ip netns exec ns2 tc qdisc add dev dummy2 root handle eeee: prio bands 3
ip netns exec ns2 tc qdisc add dev vxlan2 ingress

ip netns exec ns1 tc filter add dev dummy1 parent eeee: bpf da obj /tmp/bpf.o sec dummy1-egress
ip netns exec ns1 tc filter add dev vxlan1 parent ffff: bpf da obj /tmp/bpf.o sec vxlan1-ingress

ip netns exec ns2 tc filter add dev dummy2 parent eeee: bpf da obj /tmp/bpf.o sec dummy2-egress
ip netns exec ns2 tc filter add dev vxlan2 parent ffff: bpf da obj /tmp/bpf.o sec vxlan2-ingress
```

**解释命令：**

```sh
ip netns exec ns1 ip link add vxlan1 type vxlan external dev veth1 dstport 0
```

这个命令涉及到 Linux 中的网络命名空间（network namespace）以及 VXLAN（Virtual Extensible LAN）虚拟网络技术。让我来解释每个部分的含义：

1. `ip netns exec ns1`: 这部分命令指示在名为 `ns1` 的网络命名空间中执行后续的命令。网络命名空间是一种隔离网络资源的机制，它允许在同一主机上创建多个独立的网络环境，各自有自己的网络接口、路由表等，从而实现网络资源的隔离。
2. `ip link add vxlan1 type vxlan external dev veth1 dstport 0`: 这是在 `ns1` 命名空间中执行的具体命令，该命令是在命名空间内添加一个名为 `vxlan1` 的 VXLAN 接口。
   - `type vxlan`: 这部分指定要创建的接口类型为 VXLAN。VXLAN 是一种用于在现有网络基础设施上建立虚拟网络的技术，它允许在不同的物理网络中通过隧道进行通信，从而创建一个扁平的、逻辑上隔离的网络。
   - `external`: 这表示该 VXLAN 接口是一个外部接口，通常用于连接到物理网络或其他 VXLAN 网络。
   - `dev veth1`: 这表示要使用 `veth1` 这个网络设备作为 VXLAN 接口的底层设备。`veth1` 可能是另一个网络命名空间中的虚拟网络设备，连接到该命名空间。
   - `dstport 0`: 这指定 VXLAN 封装数据包在传输时使用的目标 UDP 端口。指定为 0 表示由系统自动选择一个合适的端口。

综上所述，这个命令将在 `ns1` 这个网络命名空间中创建一个名为 `vxlan1` 的 VXLAN 接口，用于连接到另一个网络设备 `veth1`，并使用自动选择的 UDP 端口进行通信，从而实现了 `ns1` 命名空间与其他网络之间的虚拟隔离网络连接。

**解释命令：**

```shell
ip netns exec ns1 ip link add dummy1 type dummy
```

1. `ip netns exec ns1`: 这部分命令指示在名为 `ns1` 的网络命名空间中执行后续的命令。网络命名空间是一种隔离网络资源的机制，它允许在同一主机上创建多个独立的网络环境，各自有自己的网络接口、路由表等，从而实现网络资源的隔离。
2. `ip link add dummy1 type dummy`: 这是在 `ns1` 命名空间中执行的具体命令，该命令是在命名空间内添加一个名为 `dummy1` 的虚拟网络接口。
   - `type dummy`: 这部分指定要创建的接口类型为 Dummy。Dummy 接口是一种虚拟网络接口，它没有实际的硬件设备和网络功能，主要用于测试和占位。Dummy 接口通常被用来创建一个虚拟的网络节点，它在逻辑上存在但实际上不进行任何网络通信。

综上所述，这个命令将在 `ns1` 这个网络命名空间中创建一个名为 `dummy1` 的虚拟网络接口，这个接口不具备实际的网络功能，主要用于测试或者占位。在 `ns1` 命名空间内，你可以像使用其他网络接口一样配置和管理 `dummy1` 接口，但它并不会进行实际的网络通信

**解释命令：**

```bash
ip netns exec ns1 tc qdisc add dev dummy1 root handle eeee: prio bands 3
这个命令同样涉及到 Linux 中的网络命名空间（network namespace）。让我来解释每个部分的含义：
```

1. `ip netns exec ns1`: 这部分命令指示在名为 `ns1` 的网络命名空间中执行后续的命令。网络命名空间是一种隔离网络资源的机制，它允许在同一主机上创建多个独立的网络环境，各自有自己的网络接口、路由表等，从而实现网络资源的隔离。
2. `tc qdisc add dev dummy1`: 这是在 `ns1` 命名空间中执行的具体命令，该命令是在名为 `dummy1` 的网络设备上添加一个新的队列调度器（queueing discipline，简称 qdisc）。
   - `qdisc`: 队列调度器用于管理网络设备上的数据包排队和发送方式，从而影响网络流量的处理方式。
   - `add`: 表示要添加一个新的队列调度器。
   - `dev dummy1`: 这表示在名为 `dummy1` 的网络设备上添加队列调度器。前面解释过，`dummy1` 是在 `ns1` 命名空间中创建的虚拟网络接口。
3. `root`: 这部分指定新的队列调度器将作为根调度器，即它将是整个队列调度器层次结构的顶层。
4. `handle eeee:`: 这表示为根调度器指定一个唯一的标识符 `eeee`。这个标识符在队列调度器层次结构中用于引用根调度器。
5. `prio bands 3`: 这是根调度器的属性设置，表示它是一个优先级队列调度器，并且有 3 个优先级队列（bands）。优先级队列调度器将数据包根据优先级分配到不同的队列中，以便可以对不同优先级的流量进行不同程度的优先处理。

综上所述，这个命令将在 `ns1` 这个网络命名空间中的 `dummy1` 网络设备上添加一个优先级队列调度器，并将它设置为整个队列调度器层次结构的根调度器，这个根调度器包含 3 个优先级队列。

**解释命令：**

```
ip netns exec ns1 tc qdisc add dev vxlan1 ingress
```

这个命令同样涉及到 Linux 中的网络命名空间（network namespace）。让我来解释每个部分的含义：

1. `ip netns exec ns1`: 这部分命令指示在名为 `ns1` 的网络命名空间中执行后续的命令。网络命名空间是一种隔离网络资源的机制，它允许在同一主机上创建多个独立的网络环境，各自有自己的网络接口、路由表等，从而实现网络资源的隔离。
2. `tc qdisc add dev vxlan1`: 这是在 `ns1` 命名空间中执行的具体命令，该命令是在名为 `vxlan1` 的网络设备上添加一个新的队列调度器（queueing discipline，简称 qdisc）。
   - `qdisc`: 队列调度器用于管理网络设备上的数据包排队和发送方式，从而影响网络流量的处理方式。
   - `add`: 表示要添加一个新的队列调度器。
   - `dev vxlan1`: 这表示在名为 `vxlan1` 的网络设备上添加队列调度器。前面解释过，`vxlan1` 是在 `ns1` 命名空间中创建的 VXLAN 接口。
3. `ingress`: 这部分指定新的队列调度器将作为入口（ingress）队列调度器。入口队列调度器用于控制数据包进入网络设备之前的处理，它可以对数据包进行分类、过滤和处理。

综上所述，这个命令将在 `ns1` 这个网络命名空间中的 `vxlan1` 网络设备上添加一个入口队列调度器，用于控制进入该接口的数据包的处理方式。通过这个队列调度器，你可以对进入 `vxlan1` 接口的数据包进行不同的处理，比如分类、过滤、或者进行其他网络控制操作。



## 函数

**bpf_skb_store_bytes()**

函数的作用是将数据包的一部分数据复制到 BPF 虚拟机的内存空间中，从而使得 eBPF 程序可以访问和处理这些数据。

```c
int bpf_skb_store_bytes(struct __sk_buff *skb,
                        u32 offset,
                        const void *from,
                        u32 len,
                        u64 flags)
```

参数说明：

- `skb`: 指向数据包的 `__sk_buff` 结构的指针，它在 eBPF 程序中表示当前处理的数据包。
- `offset`: 指定将数据存储在 `skb` 数据包的偏移量位置，相对于数据包的起始位置。
- `from`: 指向要存储的源数据的指针。这是一个用户空间指针，需要通过 BPF 虚拟机的验证机制确保它是合法的。
- `len`: 要存储的数据的长度。
- `flags`: 一些额外的标志参数，目前在大多数情况下设置为 0。

使用 `bpf_skb_store_bytes()` 函数，eBPF 程序可以从数据包中读取感兴趣的部分数据，并对其进行处理。

**load_byte**

函数的定义如下:

```c
unsigned long long load_byte(void *skb,unsigned long long offset) asm("llvm.bpf.load.byte");
```

它的功能是：从 `skb` 指向的数据包指针中 offset 位置开始读取 **8-bits** 的数据。 跟 gcc 里的 `__builtin_bpf_load_byte` 函数的功能是一样的。

当想要从 `struct __sk_buff *skb` 中读取数据类型大小为 8-bits（1个字节） 的字段的值的时候， 可以使用 `load_byte` 直接从指针中读取对应的数据。

例子:

```c
__u8 protocol = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
```

**bpf_skb_load_bytes**

函数的原型如下：

```c
int bpf_skb_load_bytes(const struct __sk_buff *skb, u32 offset, void *to, u32 len);
```

参数说明：

- `skb`: 指向数据包的 `__sk_buff` 结构的指针，它在 eBPF 程序中表示当前处理的数据包。
- `offset`: 指定从数据包的哪个字节开始加载数据。
- `to`: 指向目标内存区域的指针，用于存储从数据包加载的字节数据。
- `len`: 要加载的字节数据的长度。

`bpf_skb_load_bytes` 允许 eBPF 程序从数据包中加载指定长度的字节数据，并将其复制到指定的内存位置，以供进一步处理或过滤。

```c
union v6addr {
        struct {
                __u32 p1;
                __u32 p2;
                __u32 p3;
                __u32 p4;
        };
        __u8 addr[16];
};
static inline __u16 derive_lxc_id(const union v6addr *addr)
{
	return ntohl(addr->p4) & 0xFFFF;
}
```

