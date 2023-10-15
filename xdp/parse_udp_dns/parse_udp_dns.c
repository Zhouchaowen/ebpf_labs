// go:build ignore
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct dns_query {
  __u16 q_type;
  __u16 q_class;
};

// #issues/1 @cody0704 这样就可以跟Go程序式正确解析相同的结构的长度，就不要用额外做对齐
#pragma pack(push, 1)
struct event {
  __u8 protocol;
  __u8 rd;     // 所需的递归
  __u8 tc;     // 截断
  __u8 aa;     // 权威答案
  __u8 opcode; // 操作码
  __u8 qr;     // 查询响应标志
  __u8 r_code; // 响应代码
  __u8 cd;     // 检查已禁用
  __u8 ad;     // 经过身份验证的数据
  __u8 z;      // Z 保留位
  __u8 ra;     // 递归可用
  __u16 transaction_id;
  __u16 q_count;   // 问题数量
  __u16 add_count; // 资源 RR 数
  __u16 q_type;    // DNS查询类型
  __u16 q_class;   // DNS查询类
  __u16 source;    // 源端口号（16 位），网络字节序；
  __u16 dest;      // 目的端口号（16 位），网络字节序；
  __u32 s_addr;
  __u32 d_addr;
  char name[256];
};
#pragma pack(pop)

// 数组拷贝
static __inline void *memcpy(void *dest, const void *src, u64 count) {
  char *pdest = (char *)dest;
  const char *psrc = (const char *)src;
  if (psrc > pdest || pdest >= psrc + count) {
    while (count--)
      *pdest++ = *psrc++;
  } else {
    while (count--)
      *(pdest + count) = *(psrc + count);
  }
  return dest;
}

SEC("xdp_parse_dns")
int parse_dns_func(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // 解析以太网报头
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  //  判断是否为 IPv4 协议
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // 解析 IP 报头
  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // 判断是否为 UDP 协议
  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  // 解析 UDP 报头
  struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)(udp + 1) > data_end) {
    return XDP_PASS;
  }

  // 判断是否为 53 端口
  if (udp->dest != bpf_htons(53))
    return XDP_PASS;

  // 解析 UDP 报头
  struct dnshdr *dns = (void *)(udp + 1);
  if ((void *)(dns + 1) > data_end) {
    return XDP_PASS;
  }

  bpf_printk("------------udp---------------");
  bpf_printk("[udp]       src_host %d", ip->saddr);
  bpf_printk("[udp]       des_host %d", ip->daddr);
  bpf_printk("[udp]       src_port %d", bpf_htons(udp->source));
  bpf_printk("[udp]       dst_port %d", bpf_htons(udp->dest));
  bpf_printk("[udp]        udp_len %d", bpf_htons(udp->len));
  bpf_printk("[udp]       udp_csum %d", bpf_htons(udp->check));

  bpf_printk("------------dns---------------");
  bpf_printk("[dns] transaction_id %d", dns->transaction_id);
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

  // 获取 dns query 起始指针位置
  void *cursor = (void *)(dns + 1);
  if ((void *)(cursor + 1) > data_end) {
    return XDP_PASS;
  }

  // 解析 dns query name
  int name_pos = 0;
  char name[256];
  for (int i = 0; i < 256; i++) {
    // 游标的边界检查。验证者在此处需要 +1。
    // 可能是因为我们在循环结束时推进了指针
    if (cursor + 1 > data_end) {
      bpf_printk("Error: boundary exceeded while parsing DNS query name");
      break;
    }

    // 如果分隔符为零，我们已经到达域查询的末尾
    if (*(char *)(cursor) == 0) {
      bpf_printk("break parse DNS query cursor %p data_end %p len %d", cursor,
                 data_end, data_end - cursor);
      break;
    }

    name[name_pos] = *(char *)(cursor);
    cursor++;
    name_pos++;
  }

  // 解析 DNS 查询类型和类
  struct dns_query *query = (void *)(cursor + 1);
  if ((void *)(query + 1) > data_end) {
    bpf_printk("[err] cursor + sizeof(struct dns_query) > end");
    return XDP_PASS;
  }

  bpf_printk("DNS q_type: %d, q_class %d", bpf_htons(query->q_type),
             bpf_htons(query->q_class));

  // 判断ringbuf是否有充足空间
  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!e) {
    bpf_printk("RingBuf No enough space");
    return XDP_PASS;
  }

  // 赋值数据
  e->protocol = ip->protocol;
  e->rd = dns->rd;
  e->tc = dns->tc;
  e->aa = dns->aa;
  e->opcode = dns->opcode;
  e->qr = dns->qr;
  e->r_code = dns->r_code;
  e->cd = dns->cd;
  e->ad = dns->ad;
  e->z = dns->z;
  e->ra = dns->ra;
  e->transaction_id = bpf_htons(dns->transaction_id);
  e->q_count = bpf_htons(dns->q_count);
  e->add_count = bpf_htons(dns->add_count);
  e->q_type = bpf_htons(query->q_type);
  e->q_class = bpf_htons(query->q_class);
  e->source = bpf_htons(udp->source);
  e->dest = bpf_htons(udp->dest);
  e->s_addr = ip->saddr;
  e->d_addr = ip->daddr;

  memcpy(e->name, name, name_pos);

  bpf_printk("DNS len : %d name: %s", name_pos, e->name);

  // 提交数据到用户RingBuf空间
  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
