//go:build ignore
#include "bpf_endian.h"
#include "common.h"

static volatile const __u32 arg;

SEC("xdp")
int xdp_simple_func(struct xdp_md *ctx) {
  bpf_printk("xdp pass, hello xdp %d",arg);
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
