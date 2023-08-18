//go:build ignore
#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} rules SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct event {
  __u8 protocol;
  __u8 flag; // 流量是否拦截   0未拦截 1 已拦截
  __u32 s_addr;
  __u32 d_addr;
  __u32 ingress_ifindex; /* rxq->dev->ifindex */
};

// 上传流量
static int send_data(struct ip_hdr *iph, __u8 flag,
                     __u32 ingress_ifindex /* rxq->dev->ifindex */) {

  struct event *e;
  // 必需步骤 判断是否有足够空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->ingress_ifindex = ingress_ifindex;
  e->protocol = iph->protocol;
  e->s_addr = iph->s_addr;
  e->d_addr = iph->d_addr;
  e->flag = flag;

  // 写入数据
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("xdp_ipv4_firewall")
int ipv4_firewall_func(struct xdp_md *ctx) {
  void *data_end = (void *)(unsigned long)ctx->data_end;
  void *data = (void *)(unsigned long)ctx->data;
  __u32 sip = 0;
  __u8 *value = NULL;

  // 边界检查：检查数据包是否大于完整的以太网 + ip 标头
  if (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) > data_end) {
    return XDP_PASS;
  }

  struct eth_hdr *eth = data;

  // 如果以太网协议不是基于 IP 的，则忽略数据包
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }
  struct ip_hdr *iph = data + sizeof(*eth);

  sip = iph->s_addr;

  value = bpf_map_lookup_elem(&rules, &sip); // 判断攻击源是否 在黑名单中
  if (value) {
    if (*value) {
      // drop
      bpf_printk("intercept source ip %d\n", sip);
      send_data(iph, 1, ctx->ingress_ifindex);
      return XDP_DROP;
    }
    return XDP_PASS;
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
