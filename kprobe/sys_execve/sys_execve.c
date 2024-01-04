// +build ignore

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

struct event {
	int pid;
	u8 comm[80];
};

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, 80);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";