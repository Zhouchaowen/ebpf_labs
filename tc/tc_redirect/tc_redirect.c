#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/in.h>


struct endpointKey {
  __u32 ip;
};

struct endpointInfo {
  __u32 ifIndex;
  __u32 lxcIfIndex;
  __u8 mac[8];
  __u8 nodeMac[8];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 255);
  __type(key, struct endpointKey);
  __type(value, struct endpointInfo);
  // 加了 SEC(".maps") 的话, clang 在编译时需要加 -g 参数用来生成调试信息
  // 这里 ding_lxc 是必须要和 bpftool map list 出来的那个 pinned
  // 中路径的名字一样
} ding_lxc SEC(".maps");

SEC("classifier/ingress")
int cls_main(struct __sk_buff *skb) {

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    return TC_ACT_UNSPEC;
  }

  struct ethhdr *eth = data;
  struct iphdr *ip = (data + sizeof(struct ethhdr));

  if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    return TC_ACT_UNSPEC;
  }

  // 在 go 那头儿往 ebpf 的 map 里存的时候我这个 arm 是按照小端序存的
  // 这里给转成网络的大端序
  //    __u32 src_ip = htonl(ip->saddr);
  __u32 dst_ip = ip->daddr;

  bpf_printk("dest ip: %d",dst_ip);
  bpf_printk("eth->h_source mac: %02x:%02x:%02x",eth->h_source[0],eth->h_source[1],eth->h_source[2]);
  bpf_printk("eth->h_source mac: %02x:%02x:%02x",eth->h_source[3],eth->h_source[4],eth->h_source[5]);
  bpf_printk("eth->h_dest   mac: %02x:%02x:%02x",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2]);
  bpf_printk("eth->h_dest   mac: %02x:%02x:%02x",eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);

  // 拿到 mac 地址
  __u8 src_mac[ETH_ALEN];
  __u8 dst_mac[ETH_ALEN];

  struct endpointKey epKey = {};
  epKey.ip = dst_ip;

  // 在 lxc 中查找
  struct endpointInfo *ep = bpf_map_lookup_elem(&ding_lxc, &epKey);
  if (ep) {
//    bpf_printk("ep->node mac: %02x:%02x:%02x",ep->nodeMac[0],ep->nodeMac[1],ep->nodeMac[2]);
//    bpf_printk("ep->node mac: %02x:%02x:%02x",ep->nodeMac[3],ep->nodeMac[4],ep->nodeMac[5]);
//    bpf_printk("ep->ns   mac: %02x:%02x:%02x",ep->mac[0],ep->mac[1],ep->mac[2]);
//    bpf_printk("ep->ns   mac: %02x:%02x:%02x",ep->mac[3],ep->mac[4],ep->mac[5]);

    // 如果能找到说明是要发往本机其他 pod 中的，把 mac 地址改成目标 pod 的两对儿 veth 的 mac 地址
    __builtin_memcpy(src_mac, ep->nodeMac, ETH_ALEN);
    __builtin_memcpy(dst_mac, ep->mac, ETH_ALEN);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac,ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN,0);

    return bpf_redirect_peer(ep->lxcIfIndex, 0);
  }
  return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
