#include "vmlinux.h"

#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 msg = 123;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &msg, sizeof(u64));
    return 0;
}

char _license[] SEC("license") = "GPL";