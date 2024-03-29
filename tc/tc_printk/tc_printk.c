//go:build ignore
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stdio.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

typedef unsigned int		u32;

static __inline bool is_TCP(void *data_begin, void *data_end){
  bpf_printk("Entering is_TCP\n");
  struct ethhdr *eth = data_begin;

  // Check packet's size
  // the pointer arithmetic is based on the size of data type, current_address plus int(1) means:
  // new_address= current_address + size_of(data type)
  if ((void *)(eth + 1) > data_end) //
    return false;

  // Check if Ethernet frame has IP packet
  if (eth->h_proto == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
    if ((void *)(iph + 1) > data_end)
      return false;

    // extract src ip and destination ip
    u32 ip_src = iph->saddr;
    u32 ip_dst = iph->daddr;

    //
    bpf_printk("src ip addr1: %d.%d.%d\n",(ip_src) & 0xFF,(ip_src >> 8) & 0xFF,(ip_src >> 16) & 0xFF);
    bpf_printk("src ip addr2:.%d\n",(ip_src >> 24) & 0xFF);

    bpf_printk("dest ip addr1: %d.%d.%d\n",(ip_dst) & 0xFF,(ip_dst >> 8) & 0xFF,(ip_dst >> 16) & 0xFF);
    bpf_printk("dest ip addr2: .%d\n",(ip_dst >> 24) & 0xFF);

    // Check if IP packet contains a TCP segment
    if (iph->protocol == IPPROTO_TCP)
      return true;
  }
  return false;
}

SEC("tc")
int tc_drop_tcp(struct __sk_buff *skb)
{

  bpf_printk("Entering tc section\n");
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;


  if (is_TCP(data, data_end))
    return TC_ACT_SHOT;
  else
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";