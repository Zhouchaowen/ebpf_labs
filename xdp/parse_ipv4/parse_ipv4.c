//go:build ignore
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf_endian.h"
#include "common.h"

#define MAX_MAP_ENTRIES 16

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_MAP_ENTRIES);
  __type(key, __u32);   // source IPv4 address
  __type(value, __u32); // packet count
} ip_stats_map SEC(".maps");

/*
    Attempt to parse the IPv4 source address from the packet.
    Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx,
                                             __u32 *ip_src_addr) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // First, parse the ethernet header.
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return 0;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    return 0;
  }

  // Then parse the IP header.
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return 0;
  }

  // Return the source IP address in network byte order.
  *ip_src_addr = (__u32)(ip->saddr);
  return 1;
}

SEC("xdp_parse_ipv4")
int parse_ipv4_func(struct xdp_md *ctx) {
  __u32 ip;
  if (!parse_ip_src_addr(ctx, &ip)) {
    // Not an IPv4 packet, so don't count it.
    goto done;
  }

  __u32 *pkt_count = bpf_map_lookup_elem(&ip_stats_map, &ip);
  if (!pkt_count) {
    // No entry in the map for this IP address yet, so set the initial value to 1.
    __u32 init_pkt_count = 1;
    bpf_map_update_elem(&ip_stats_map, &ip, &init_pkt_count, BPF_ANY);
  } else {
    // Entry already exists for this IP address, so increment it atomically using an LLVM built-in.
    __sync_fetch_and_add(pkt_count, 1);
  }

done:
  // Try changing this to XDP_DROP and see what happens!
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
