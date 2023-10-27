/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

struct str_t {
	__u32 pid;
	char str[MAX_LINE_SIZE];
};

// Force emitting struct event into the ELF.
const struct str_t *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("uretprobe/readline")
int BPF_KRETPROBE(printret, const void *ret) {
	struct str_t data;
	char comm[TASK_COMM_LEN];
	u32 pid;

	if (!ret)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h' || comm[4] != 0 )
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;
	bpf_probe_read_user_str(&data.str, sizeof(data.str), ret);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
};

char LICENSE[] SEC("license") = "GPL";