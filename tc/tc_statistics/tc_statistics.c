// go:build ignore
#include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

struct pair {
    __u32 lip; // local IP
    __u32 rip; // remote IP
};

struct stats {
    __u64 tx_cnt;
    __u64 tx_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2048);
  __type(key, struct pair);
  __type(value, struct stats);
//  __uint(pinning, 1 /* LIBBPF_PIN_BY_NAME */); // 钉住让cilium/ebpf可以访问
} trackers SEC(".maps");

static bool parse_ipv4(void* data, void* data_end, struct pair *pair){
    bpf_printk("Entering parse_ipv4\n");
    struct ethhdr *eth = data;
    struct iphdr *ip;

    if(data + sizeof(struct ethhdr) > data_end)
        return false;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    ip = data + sizeof(struct ethhdr);

    if ((void*) ip + sizeof(struct iphdr) > data_end)
        return false;

    bpf_printk("src ip addr1: %d.%d.%d\n",(ip->saddr) & 0xFF,(ip->saddr >> 8) & 0xFF,(ip->saddr >> 16) & 0xFF);
    bpf_printk("src ip addr2:.%d\n",(ip->saddr >> 24) & 0xFF);

    bpf_printk("dest ip addr1: %d.%d.%d\n",(ip->daddr) & 0xFF,(ip->daddr >> 8) & 0xFF,(ip->daddr >> 16) & 0xFF);
    bpf_printk("dest ip addr2: .%d\n",(ip->daddr >> 24) & 0xFF);

    pair->lip = ip->saddr;
    pair->rip = ip->daddr;

    return true;
}

static void update_stats(struct pair *key, long long bytes){
    struct stats *stats, newstats = {0,0};

    stats = bpf_map_lookup_elem(&trackers, key);
    if(stats){
        stats->tx_cnt++;
        stats->tx_bytes += bytes;
    }else{
        newstats.tx_cnt = 1;
        newstats.tx_bytes = bytes;
        bpf_map_update_elem(&trackers, key, &newstats, BPF_NOEXIST);
    }
}

SEC("tc")
int track_tx(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct pair pair;

    if(!parse_ipv4(data,data_end,&pair))
        return TC_ACT_OK;

    // Update TX statistics
    update_stats(&pair,data_end-data);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";