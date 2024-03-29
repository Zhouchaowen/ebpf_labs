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

#define HTTP_DATA_MIN_SIZE 91
#define TC_PACKET_MIN_SIZE 8
enum tc_type { Egress, Ingress };

struct http_data_event {
  enum tc_type type;
  u32 data_len;
};

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 10240);
} skb_events SEC(".maps");

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
                                                uint8_t **head, uint8_t **tail,
                                                const u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

static __inline int capture_packets(struct __sk_buff *skb,enum tc_type type) {
    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    if (data_start + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    uint32_t l4_hdr_off;

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;

    // Simple length check
    if ((data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end) {
        return TC_ACT_OK;
    }

    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off)) {
        return TC_ACT_OK;
    }

    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));
    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    // In theory this is the minimum packet size of an http packet
    if (len <= HTTP_DATA_MIN_SIZE){
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