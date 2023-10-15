#include "vmlinux.h"

#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TASK_COMM_LEN 16

struct event_t {
    u32 host_pid;  // pid in host pid namespace
    u32 host_ppid; // ppid in host pid namespace

    char comm[TASK_COMM_LEN]; // the name of the executable (excluding the path)
};

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 /* 16 KB */);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(
    struct trace_event_raw_sys_enter *ctx) {
    char name[TASK_COMM_LEN];
    bpf_get_current_comm(&name, sizeof(name));

    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->host_pid = bpf_get_current_pid_tgid() >> 32;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";