// go:build ignore
#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"

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
static int send_data(struct ip_hdr *ip, struct udp_hdr *udp) {
  struct event *e;
  // 必需步骤 判断是否有足够空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->protocol = ip->protocol;
  e->s_addr = ip->s_addr;
  e->d_addr = ip->d_addr;
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
  if (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) > data_end) {
    return XDP_PASS;
  }

  struct eth_hdr *eth = data;

  // 如果以太网协议不是基于 IP 的，则忽略数据包
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  struct ip_hdr *ip = data + sizeof(*eth);
  // 判断是否为 UDP 协议
  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  // 边界检查：检查数据包是否大于完整的以太网 + ip 标头 + udp
  struct udp_hdr *udp = data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr);
  if ((void *)(udp + 1) > data_end) {
    return XDP_PASS;
  }

  bpf_printk("-------------UDP--------------");
  bpf_printk("src_host %d", ip->s_addr);
  bpf_printk("src_port_host %d", udp->source);
  bpf_printk("dst_port_host %d %d", bpf_ntohs(udp->dest), bpf_htons(53));
  bpf_printk("udp_len_host %d", udp->len);
  bpf_printk("udp_csum_host %d", udp->check);

  send_data(ip, udp);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
