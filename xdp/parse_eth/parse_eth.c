//go:build ignore
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>

#include "common.h"
#include "bpf_endian.h"

// VLAN 最大深度
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

// 虚拟局域网标识符
#define VLAN_VID_MASK 0x0fff

// 通过parse_ethhdr_vlan解析后收集 VLAN 的结构
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

// 用于跟踪当前解析位置
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

// 请注意，parse_ethhdr（） 将通过推进 nh->pos 并返回下一个标头 EtherType 来跳过 VLAN 标记，但提供的 ethhdr 指针仍然指向以太网标头。
// 因此，呼叫者可以查看 eth->h_proto，以查看这是否是 VLAN 标记的数据包。
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh, // 当前解析位置
					     void *data_end,    // 数据末尾
					     struct ethhdr **eth,
					     struct collect_vlans *vlans) {

	struct ethhdr *eth_tmp = nh->pos; // 赋值
	int hdr_size = sizeof(*eth_tmp); // ethhdr 占用大小
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	// 字节计数边界检查;检查当前指针 + 标题大小是否在data_end之后
	if (nh->pos + hdr_size > data_end)
		return -1;

	nh->pos += hdr_size; // 更新解析位置
	*eth = eth_tmp;
	vlh = nh->pos;
	h_proto = eth_tmp->h_proto;

	// 使用循环展开来避免对循环的验证程序限制;支持多达 VLAN_MAX_DEPTH 层的 VLAN 封装。
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if ((void *)(vlh + 1) > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] = (bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh; // 更新解析位置
	return h_proto; // 网络字节顺序 协议ID
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr) {

	// 期望编译器删除收集 VLAN ID 的代码
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

SEC("xdp_parse_eth")
int parse_eth_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    int eth_type;
	struct ethhdr *eth;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
		goto out;
	}
	bpf_printk("------------ETH---------------");
    bpf_printk("[ETH] h_dest %s", eth->h_dest);
    bpf_printk("[ETH] h_source %s", eth->h_source);
    bpf_printk("[ETH] h_proto %d", bpf_htons(eth->h_proto));

	if (eth_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("------------IP---------------");
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("------------IP6---------------");
    }

out:
	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

