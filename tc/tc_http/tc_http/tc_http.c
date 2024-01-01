// go:build ignore
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define DNS_HLEN sizeof(struct dns_hdr)

#define TC_PACKET_MIN_SIZE 36
enum tc_type { Egress, Ingress };

struct http_data_event {
  enum tc_type type;
  __u32 data_len;
};

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 10240);
} skb_events SEC(".maps");


static __inline int capture_packets(struct __sk_buff *skb,enum tc_type type) {
    // Packet data
    void *data_start = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Bounds Check: Check if the packet is larger than the full Ethernet + IP header
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

    struct http_data_event event = {0};

    event.type = type;
    event.data_len = skb->len;

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)skb->len << 32;
    size_t pkt_size = TC_PACKET_MIN_SIZE;
    bpf_perf_event_output(skb, &skb_events, flags, &event, pkt_size);
    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb) { return capture_packets(skb,Egress); }

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb) { return capture_packets(skb,Ingress); }

char _license[] SEC("license") = "GPL";