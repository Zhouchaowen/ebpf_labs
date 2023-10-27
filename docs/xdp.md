# XDP

## 编译

> 内核态BPF

```bash
# 编译
clang -S \
    -target bpf \
    -D __BPF_TRACING__ \
    -I../libbpf/src/build/usr/include/ -I../libbpf/include/uapi \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Werror \
    -O2 -emit-llvm -c -g -o xdp_firewall_kern.ll xdp_firewall_kern.c
# 提取    
llc -march=bpf -filetype=obj -o xdp_firewall_kern.o xdp_firewall_kern.ll
```

> 用户态程序

```bash
cc -Wall -I../libbpf/src/build/usr/include/ \
-I../libbpf/include/uapi \
-g -L../libbpf/src/ \
-o xdp_firewall_cli ../common/common_libbpf.o ../common//common_params.o ../common/common_user_bpf_xdp.o \
xdp_firewall_cli.c -l:/libbpf.a -lelf -lz
```

## 加载

```bash
# 加载到 lo
# ip link set dev [nic] xdpgeneric obj [bpf-file.o] sec [sec_name]
ip link set dev lo xdpgeneric obj xdp_pass_kern.o sec xdp_drop

# 卸载
ip link set dev ens160 xdpgeneric off

# 查看 dubug 信息
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 示例

> XDP 结构

```c
/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 * XDP钩子上的eBPF程序可以访问的数据包元数据，md即meta data
 */
struct xdp_md {
	__u32 data; // 指向数据包的起点
	__u32 data_end; // 指向数据包的末尾
	__u32 data_meta; // ...
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex 网卡的序号，ip link显示的那个, 表示数据包从哪个网络接口接收到的。*/
	__u32 rx_queue_index;  /* rxq->queue_index 网卡接收队列的序号 */

	__u32 egress_ifindex;  /* txq->dev->ifindex 这个参数旧一些的内核是没有的 */
};
```

> 解析UDP包

```c
//go:build ignore
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_endian.h"
#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct event {
  __u8 protocol;
  __u32 s_addr;
  __u32 d_addr;
  __u16 source; // 源端口号（16 位），网络字节序；
  __u16 dest;   // 目的端口号（16 位），网络字节序；
  __u16 len;    // UDP 数据包的长度（16 位），包括 UDP
                // 头部和数据部分的长度，网络字节序；
  __u16 check;  // 校验和（16 位），网络字节序。
};

// 上传流量
static int send_data(struct iphdr *ip, struct udphdr *udp) {
  struct event *e;
  // 必需步骤 判断是否有足够空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->protocol = ip->protocol;
  e->s_addr = ip->saddr;
  e->d_addr = ip->daddr;
  e->source = bpf_ntohs(udp->source);
  e->dest = bpf_ntohs(udp->dest);
  e->len = bpf_ntohs(udp->len);
  e->check = bpf_ntohs(udp->check);

  // 写入数据
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("xdp_parse_udp")
int parse_udp_func(struct xdp_md *ctx) {
  void *data_end = (void *)(unsigned long)ctx->data_end;
  void *data = (void *)(unsigned long)ctx->data;

  // 边界检查：检查数据包是否大于完整的以太网 + ip 标头
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    return XDP_PASS;
  }

  struct ethhdr *eth = data;

  // 如果以太网协议不是基于 IP 的，则忽略数据包
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  struct iphdr *ip = data + sizeof(*eth);
  // 判断是否为 UDP 协议
  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  // 边界检查：检查数据包是否大于完整的以太网 + ip 标头 + udp
  struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)(udp + 1) > data_end) {
    return XDP_PASS;
  }

  bpf_printk("-------------UDP--------------");
  bpf_printk("src_host %d", ip->saddr);
  bpf_printk("src_port_host %d", udp->source);
  bpf_printk("dst_port_host %d %d", bpf_ntohs(udp->dest), bpf_htons(53));
  bpf_printk("udp_len_host %d", udp->len);
  bpf_printk("udp_csum_host %d", udp->check);

  send_data(ip, udp);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
```

## 常见网络协议

> vlan_hdr

```c
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
```

> ethhdr

```c
struct ethhdr
{
  unsigned char h_dest[ETH_ALEN]; //目的MAC地址
  unsigned char h_source[ETH_ALEN]; //源MAC地址
  __u16 h_proto ; //网络层所使用的协议类型
} __attribute__((packed)) //用于告诉编译器不要对这个结构体中的缝隙部分进行填充操作；
```

> icmp6hdr

```c
struct icmp6_hdr
{
  uint8_t     icmp6_type;   /* type field */
  uint8_t     icmp6_code;   /* code field */
  uint16_t    icmp6_cksum;  /* checksum field */
  union
  {
    uint32_t  icmp6_un_data32[1]; /* type-specific field */
    uint16_t  icmp6_un_data16[2]; /* type-specific field */
    uint8_t   icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
};
```

> ipv6hdr

```c
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};
```

> iphdr

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};
```

> udphdr

```c
struct udphdr {
	__be16	source; // 16位源端口号
	__be16	dest; // 16位目的端口号
	__be16	len; // 表示此次发送的数据报的长度，16位。
	__sum16	check; // 校验和。
};
```

> tcphdr

```c
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
```

