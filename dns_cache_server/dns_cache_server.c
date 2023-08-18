//go:build ignore
#define DEFAULT_ACTION XDP_PASS

#include "bpf_endian.h"
#include "common.h"
#include "protocol_hdr.h"
#include <bpf_elf.h>
#include <netinet/in.h>
#include <stdint.h>

#define A_RECORD_TYPE 0x0001
#define DNS_CLASS_IN 0x0001

#ifdef EDNS
struct ar_hdr {
  __u8 name;
  __u16 type;
  __u16 size;
  __u32 ex_rcode;
  __u16 rcode_len;
} __attribute__((packed));
#endif

// Used as key in our hashmap
struct dns_query {
  __u16 record_type;
  __u16 class;
  char name[MAX_DNS_NAME_LENGTH];
};

// Used as a generic DNS response
struct dns_response {
  __u16 query_pointer;
  __u16 record_type;
  __u16 class;
  __u32 ttl;
  __u16 data_length;
} __attribute__((packed));

// Used as value of our A record hashmap
struct a_record {
  struct in_addr ip_addr;
  __u32 ttl;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct dns_query);
  __type(value, struct a_record);
} rules SEC(".maps");

static int match_a_records(struct xdp_md *ctx, struct dns_query *q, struct a_record *a);
static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q);
static void create_query_response(struct a_record *a, char *dns_buffer, size_t *buf_size);
#ifdef EDNS
static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer, size_t *buf_size);
static inline int parse_ar(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct ar_hdr *ar);
#endif
static inline void modify_dns_header_response(struct dns_hdr *dns_hdr);
static inline void update_ip_checksum(void *data, int len, __u16 *checksum_location);
static inline void copy_to_pkt_buf(struct xdp_md *ctx, void *dst, void *src, size_t n);
static inline void swap_mac(__u8 *src_mac, __u8 *dst_mac);

char dns_buffer[512];

SEC("xdp_dns_cache")
int xdp_dns_cache_func(struct xdp_md *ctx) {
#ifdef DEBUG // 开启DEBUG模式
  uint64_t start = bpf_ktime_get_ns();
#endif

  // 数据尾指针和头指针
  void *data_end = (void *)(unsigned long)ctx->data_end;
  void *data = (void *)(unsigned long)ctx->data;

  // 边界检查：检查数据包是否大于完整以太网 + IP 报头
  if (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) > data_end) {
    return DEFAULT_ACTION;
  }

  // 以太网报文头
  struct eth_hdr *eth = data;

  // 如果以太网协议不是基于 IP 的，则忽略数据包
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return DEFAULT_ACTION;
  }

  // IP报文头
  struct ip_hdr *ip = data + sizeof(*eth);

  // 只处理UDP协议数据包
  if (ip->protocol == IPPROTO_UDP) {
    // UDP报文头
    struct udp_hdr *udp;
    // UDP的边界检查
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end) {
      return DEFAULT_ACTION;
    }

    udp = data + sizeof(*eth) + sizeof(*ip);

    // 检查目标端口是否等于 53
    if (udp->dest == bpf_htons(53)) {
#ifdef DEBUG
      bpf_printk("Packet dest port 53");
      bpf_printk("Data pointer starts at %u", data);
#endif

      // 最小 DNS 标头的边界检查
      if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end) {
        return DEFAULT_ACTION;
      }

      // DNS报文头
      struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

      // 检查标头是否包含标准查询
      if (dns_hdr->qr == 0 && dns_hdr->opcode == 0) {
#ifdef DEBUG
        bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));
#endif

        // 获取指向 DNS 查询开始的指针
        void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

        // 我们现在只解析一个查询
        struct dns_query q;
        int query_length = 0;
        query_length = parse_query(ctx, query_start, &q);
        if (query_length < 1) {
          return DEFAULT_ACTION;
        }

        // 检查查询是否与哈希表中的记录匹配
        struct a_record a_record;
        int res = match_a_records(ctx, &q, &a_record);

        // 如果查询匹配
        if (res == 0) {
          size_t buf_size = 0;

          // 将 DNS 标头更改为有效的响应标头
          modify_dns_header_response(dns_hdr);

          // 创建 DNS 响应并添加到临时缓冲区
          create_query_response(&a_record, &dns_buffer[buf_size], &buf_size);

#ifdef EDNS
          // 如果存在其他记录
          if (dns_hdr->add_count > 0) {
            // 解析 AR 记录
            struct ar_hdr ar;
            if (parse_ar(ctx, dns_hdr, query_length, &ar) != -1) {
              // 创建 AR 响应并添加到临时缓冲区
              create_ar_response(&ar, &dns_buffer[buf_size], &buf_size);
            }
          }
#endif

          // 在标头之外开始我们的响应 [query_length] 字节
          void *answer_start = (void *)dns_hdr + sizeof(struct dns_hdr) + query_length;
          // 确定数据包缓冲区的增量
          int tail_adjust = answer_start + buf_size - data_end;

          // 相应地调整数据包长度
          if (bpf_xdp_adjust_tail(ctx, tail_adjust)) {
#ifdef DEBUG
            bpf_printk("Adjust tail fail");
#endif
          } else {
            // 由于我们调整了数据包长度，因此内存地址可能会更改
            // Reinit 指针，因为验证者会抱怨其他情况
            data = (void *)(unsigned long)ctx->data;
            data_end = (void *)(unsigned long)ctx->data_end;

            // 将字节从我们的临时缓冲区复制到数据包缓冲区
            copy_to_pkt_buf(ctx, data + sizeof(struct eth_hdr) +
                                sizeof(struct ip_hdr) + sizeof(struct udp_hdr) +
                                sizeof(struct dns_hdr) + query_length,
                            &dns_buffer[0], buf_size);

            eth = data;
            ip = data + sizeof(struct eth_hdr);
            udp = data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr);

            // 执行新的边界检查
            if (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) +
                    sizeof(struct udp_hdr) >
                data_end) {
#ifdef DEBUG
              bpf_printk("Error: Boundary exceeded");
#endif
              return DEFAULT_ACTION;
            }

            // 调整 UDP 长度和 IP 长度
            __u16 ip_len = (data_end - data) - sizeof(struct eth_hdr);
            __u16 udp_len = (data_end - data) - sizeof(struct eth_hdr) -
                           sizeof(struct ip_hdr);
            ip->tot_len = bpf_htons(ip_len);
            udp->len = bpf_htons(udp_len);

            // Swap eth macs
            swap_mac((__u8 *)eth->h_source, (__u8 *)eth->h_dest);

            // Swap src/dst IP
            __u32 src_ip = ip->s_addr;
            ip->s_addr = ip->d_addr;
            ip->d_addr = src_ip;

            // Set UDP checksum to zero
            udp->check = 0;

            // Swap udp src/dst ports
            __u16 tmp_src = udp->source;
            udp->source = udp->dest;
            udp->dest = tmp_src;

            // Recalculate IP checksum
            update_ip_checksum(ip, sizeof(struct ip_hdr), &ip->check);

#ifdef DEBUG
            bpf_printk("XDP_TX");
#endif

#ifdef DEBUG
            uint64_t end = bpf_ktime_get_ns();
            uint64_t elapsed = end - start;
            bpf_printk("Time elapsed: %d", elapsed);
#endif

            // 发出修改后的数据包
            return XDP_TX;
          }
        }
      }
    }
  }

  return DEFAULT_ACTION;
}

static int match_a_records(struct xdp_md *ctx, struct dns_query *q,
                           struct a_record *a) {
#ifdef DEBUG
  bpf_printk("DNS record type: %i", q->record_type);
  bpf_printk("DNS class: %i", q->class);
  bpf_printk("DNS name: %s", q->name);
#endif

  struct a_record *record;
  record = bpf_map_lookup_elem(&rules, q); // 从 rules 中获取记录

  // 如果记录指针不为零，匹配成功
  if (record > 0) {
#ifdef DEBUG
    bpf_printk("DNS query matched");
#endif
    // 赋值记录
    a->ip_addr = record->ip_addr;
    a->ttl = record->ttl;

    return 0;
  }

  return -1;
}

// Parse query and return query length
static int parse_query(struct xdp_md *ctx, void *query_start,
                       struct dns_query *q) {
  // 获取整个数据报末尾指针地址
  void *data_end = (void *)(long)ctx->data_end;

#ifdef DEBUG
  bpf_printk("Parsing query");
#endif

  __u16 i;
  void *cursor = query_start;
  int namepos = 0; // 标志位

  // Fill dns_query.name with zero bytes
  // Not doing so will make the verifier complain when dns_query is used as a
  // key in bpf_map_lookup
  memset(&q->name[0], 0, sizeof(q->name));
  // Fill record_type and class with default values to satisfy verifier
  q->record_type = 0;
  q->class = 0;

  // We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name
  // size). We'll loop through the packet byte by byte until we reach '0' in
  // order to get the dns query name
  //  我们将逐字节循环数据包，直到达到“0”，以便获取 dns 查询名称
  for (i = 0; i < MAX_DNS_NAME_LENGTH; i++) {

    // Boundary check of cursor. Verifier requires a +1 here.
    // Probably because we are advancing the pointer at the end of the loop
    if (cursor + 1 > data_end) {
#ifdef DEBUG
      bpf_printk("Error: boundary exceeded while parsing DNS query name");
#endif
      break;
    }

    /*
    #ifdef DEBUG
    bpf_printk("Cursor contents is %u\n", *(char *)cursor);
    #endif
    */

    // If separator is zero we've reached the end of the domain query
    if (*(char *)(cursor) == 0) {

      // We've reached the end of the query name.
      // This will be followed by 2x 2 bytes: the dns type and dns class.
      if (cursor + 5 > data_end) {
#ifdef DEBUG
        bpf_printk("Error: boundary exceeded while retrieving DNS record type "
                   "and class");
#endif
      } else { // 获取record_type和class
        q->record_type = bpf_htons(*(__u16 *)(cursor + 1));
        q->class = bpf_htons(*(__u16 *)(cursor + 3));
      }

      // Return the bytecount of (namepos + current '0' byte + dns type + dns
      // class) as the query length.
      return namepos + 1 + 2 + 2;
    }

    // Read and fill data into struct
    q->name[namepos] = *(char *)(cursor);
    namepos++;
    cursor++;
  }

  return -1;
}

#ifdef EDNS
// 解析附加记录 additonal
static inline int parse_ar(struct xdp_md *ctx, struct dns_hdr *dns_hdr,
                           int query_length, struct ar_hdr *ar) {
#ifdef DEBUG
  bpf_printk("Parsing additional record in query");
#endif

  void *data_end = (void *)(long)ctx->data_end;

  // Parse ar record
  ar = (void *)dns_hdr + query_length + sizeof(struct dns_response);
  if ((void *)ar + sizeof(struct ar_hdr) > data_end) {
#ifdef DEBUG
    bpf_printk("Error: boundary exceeded while parsing additional record");
#endif
    return -1;
  }

  return 0;
}

static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer,
                                     size_t *buf_size) {
  // Check for OPT record (RFC6891)
  if (ar->type == bpf_htons(41)) {
#ifdef DEBUG
    bpf_printk("OPT record found");
#endif
    struct ar_hdr *ar_response = (struct ar_hdr *)&dns_buffer[0];
    // We've received an OPT record, advertising the clients' UDP payload size
    // Respond that we're serving a payload size of 512 and not serving any
    // additional records.
    // 我们收到了一条 OPT 记录，通告客户端的 UDP 有效负载大小 响应我们提供的有效负载大小为 512，并且不提供任何其他记录。
    ar_response->name = 0;
    ar_response->type = bpf_htons(41);
    ar_response->size = bpf_htons(512);
    ar_response->ex_rcode = 0;
    ar_response->rcode_len = 0;

    *buf_size += sizeof(struct ar_hdr);
  } else {
    return -1;
  }

  return 0;
}
#endif

static void create_query_response(struct a_record *a, char *dns_buffer,
                                  size_t *buf_size) {
  // Formulate a DNS response. Currently defaults to hardcoded query pointer +
  // type a + class in + ttl + 4 bytes as reply. 制定 DNS
  // 响应。当前默认为硬编码查询指针 + type a + class in + ttl + 4 bytes as reply
  struct dns_response *response = (struct dns_response *)&dns_buffer[0];
  response->query_pointer = bpf_htons(0xc00c);
  response->record_type = bpf_htons(0x0001);
  response->class = bpf_htons(0x0001);
  response->ttl = bpf_htonl(a->ttl);
  response->data_length = bpf_htons((__u16)sizeof(a->ip_addr));
  *buf_size += sizeof(struct dns_response);
  // Copy IP address
  __builtin_memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(struct in_addr));
  *buf_size += sizeof(struct in_addr);
}

// Update IP checksum for IP header, as specified in RFC 1071
// The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len,
                                      __u16 *checksum_location) {
  __u32 accumulator = 0;
  int i;
  for (i = 0; i < len; i += 2) {
    __u16 val;
    // If we are currently at the checksum_location, set to zero
    if (data + i == checksum_location) {
      val = 0;
    } else {
      // Else we load two bytes of data into val
      val = *(__u16 *)(data + i);
    }
    accumulator += val;
  }

  // Add 16 bits overflow back to accumulator (if necessary)
  __u16 overflow = accumulator >> 16;
  accumulator &= 0x00FFFF;
  accumulator += overflow;

  // If this resulted in an overflow again, do the same (if necessary)
  accumulator += (accumulator >> 16);
  accumulator &= 0x00FFFF;

  // Invert bits and set the checksum at checksum_location
  __u16 chk = accumulator ^ 0xFFFF;

#ifdef DEBUG
  bpf_printk("Checksum: %u", chk);
#endif

  *checksum_location = chk;
}

static inline void modify_dns_header_response(struct dns_hdr *dns_hdr) {
  // 设置查询响应
  dns_hdr->qr = 1;
  // 设置截断为 0
  // dns_hdr->tc = 0;
  // 将权威设置为零
  // dns_hdr->aa = 0;
  // 设置递归可用
  dns_hdr->ra = 1;
  // 设置一个答案
  dns_hdr->ans_count = bpf_htons(1);
}

//__builtin_memcpy only supports static size_t
// The following function is a memcpy wrapper that uses __builtin_memcpy when
// size_t n is known. Otherwise it uses our own naive & slow memcpy routine
// __builtin_memcpy仅支持静态size_t
// 以下函数是一个 memcpy 包装器，它在已知 size_t n 时使用 __builtin_memcpy。
static inline void copy_to_pkt_buf(struct xdp_md *ctx, void *dst, void *src,
                                   size_t n) {
  // Boundary check
  if ((void *)(long)ctx->data_end >= dst + n) {
    int i;
    char *cdst = dst;
    char *csrc = src;

    // For A records, src is either 16 or 27 bytes, depending if OPT record is
    // requested. Use __builtin_memcpy for this. Otherwise, use our own slow,
    // naive memcpy implementation.
    //  对于 A 记录，src 为 16 或 27 个字节，具体取决于是否请求 OPT 记录。
    //  为此使用__builtin_memcpy。否则，请使用我们自己缓慢、幼稚的 memcpy 实现。
    switch (n) {
    case 16:
      __builtin_memcpy(cdst, csrc, 16);
      break;

    case 27:
      __builtin_memcpy(cdst, csrc, 27);
      break;

    default:
      for (i = 0; i < n; i += 1) {
        cdst[i] = csrc[i];
      }
    }
  }
}

static inline void swap_mac(__u8 *src_mac, __u8 *dst_mac) {
  int i;
  for (i = 0; i < 6; i++) {
    __u8 tmp_src;
    tmp_src = *(src_mac + i);
    *(src_mac + i) = *(dst_mac + i);
    *(dst_mac + i) = tmp_src;
  }
}

char __license[] SEC("license") = "Dual MIT/GPL";
