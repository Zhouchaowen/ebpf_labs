// +build ignore

#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define MAX_SOCKS 8

// Ensure map references are available.
/*
				These will be initiated from go and
				referenced in the end BPF opcodes by file descriptor
*/

struct bpf_map_def SEC("maps") xsks_map = {
		.type = BPF_MAP_TYPE_XSKMAP,
		.key_size = sizeof(int),
		.value_size = sizeof(int),
		.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") qidconf_map = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(int),
		.value_size = sizeof(int),
		.max_entries = MAX_SOCKS,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;

	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	if (bpf_map_lookup_elem(&qidconf_map, &index))
	{
		// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;
		struct ethhdr *eth = data;
		__u16 h_proto = eth->h_proto;
		if ((void *)eth + sizeof(*eth) > data_end)
			goto out;

		if (bpf_htons(h_proto) != ETH_P_IP)
			goto out;

		struct iphdr *ip = data + sizeof(*eth);
		if ((void *)ip + sizeof(*ip) > data_end)
			goto out;

		// Only UDP
		if (ip->protocol != IPPROTO_UDP)
			goto out;

		struct udphdr *udp = (void *)ip + sizeof(*ip);
		if ((void *)udp + sizeof(*udp) > data_end)
			goto out;

		if (udp->dest != bpf_htons(53))
		    goto out;

		// 解析 UDP 报头
        struct dns_hdr *dns = (void *)(udp + 1);
        if ((void *)(dns + 1) > data_end)
            goto out;

        bpf_printk("------------udp---------------");
        bpf_printk("[udp]       src_port %d", bpf_htons(udp->source));
        bpf_printk("[udp]       dst_port %d", bpf_htons(udp->dest));
        bpf_printk("[udp]        udp_len %d", bpf_htons(udp->len));
        bpf_printk("[udp]       udp_csum %d", bpf_htons(udp->check));
        bpf_printk("------------dns---------------");
        bpf_printk("[dns] transaction_id %d", bpf_htons(dns->transaction_id));
        bpf_printk("[dns]             rd %d", dns->rd);
        bpf_printk("[dns]             tc %d", dns->tc);
        bpf_printk("[dns]             aa %d", dns->aa);
        bpf_printk("[dns]         opcode %d", dns->opcode);
        bpf_printk("[dns]             qr %d", dns->qr);
        bpf_printk("[dns]         r_code %d", dns->r_code);
        bpf_printk("[dns]             cd %d", dns->cd);
        bpf_printk("[dns]             ad %d", dns->ad);
        bpf_printk("[dns]              z %d", dns->z);
        bpf_printk("[dns]             ra %d", dns->ra);
        bpf_printk("[dns]        q_count %d", bpf_htons(dns->q_count));
        bpf_printk("[dns]      ans_count %d", bpf_htons(dns->ans_count));
        bpf_printk("[dns]     auth_count %d", bpf_htons(dns->auth_count));
        bpf_printk("[dns]      add_count %d", bpf_htons(dns->add_count));
        return bpf_redirect_map(&xsks_map, index, 0);
	}

out:
	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
