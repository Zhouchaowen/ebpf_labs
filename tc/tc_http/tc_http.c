// go:build ignore
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"


#define IP_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)

// BPF ringbuf map
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} tc_capture_events SEC(".maps");

static inline int capture_packets(struct __sk_buff *skb) {
  // Packet data
  void *data_end = (void *)(long)skb->data_end;
  void *data_start = (void *)(long)skb->data;

  // 边界检查：检查数据包是否大于完整以太网 + IP 报头
  if (data_start + ETH_HLEN + IP_HLEN + TCP_HLEN > data_end) {
    return TC_ACT_OK;
  }

  // Ethernet headers
  struct ethhdr *eth = (struct ethhdr *)data_start;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  // IP headers
  struct iphdr *iph = (struct iphdr *)(data_start + ETH_HLEN);
  if (iph->protocol != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  // 预分配 net_packet_event 占用大小内存
//  struct __sk_buff *ok = bpf_ringbuf_reserve(&tc_capture_events, sizeof(*skb), 0);
//  if (!ok) {
//    return TC_ACT_OK;
//  }
//  *ok = *skb;
  // 提交到ringbuf
//  bpf_ringbuf_submit(ok, 0);
  // long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
  bpf_ringbuf_output(&tc_capture_events,data_start,skb->len,0);
  return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb) { return capture_packets(skb); }

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb) { return capture_packets(skb); }

char _license[] SEC("license") = "GPL";

