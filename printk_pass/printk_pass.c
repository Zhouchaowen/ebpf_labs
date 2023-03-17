#include "bpf_endian.h"
#include "common.h"

SEC("xdp")
int xdp_simple(struct xdp_md *ctx)
{
    bpf_printk("xdp pass, hello xdp\n");
	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

