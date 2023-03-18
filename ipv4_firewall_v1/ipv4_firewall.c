#include "bpf_endian.h"
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} rules SEC(".maps");


SEC("xdp_ipv4_firewall")
int ipv4_firewall_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;
    __u32 sip = 0;
    __u8 *value = NULL;

    // 边界检查：检查数据包是否大于完整的以太网 + ip 标头
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;

    // 如果以太网协议不是基于 IP 的，则忽略数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }
    struct iphdr *ip = data + sizeof(*eth);

    sip = ip->saddr;

    value = bpf_map_lookup_elem(&rules, &sip);  // 判断攻击源是否 在黑名单中
    if (value)
    {
        if (*value)
        {
            // drop
            bpf_printk("intercept source ip %x\n", sip);
            return XDP_DROP;
        }

        return XDP_PASS;
    }

	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
