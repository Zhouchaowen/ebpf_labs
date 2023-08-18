// go:build ignore
#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"
#include <netinet/in.h>

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

SEC("xdp_parse_dns")
int parse_dns_func(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // 解析以太网报头
  struct eth_hdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  //  判断是否为 IPv4 协议
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // 解析 IP 报头
  struct ip_hdr *ip = data + sizeof(struct eth_hdr);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // 判断是否为 UDP 协议
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }


  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
