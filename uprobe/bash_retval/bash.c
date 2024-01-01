#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_DATA_SIZE_BASH 256

struct event {
    u32 pid;
    u32 uid;
    u8 line[MAX_DATA_SIZE_BASH];
    u32 retval;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct event);
    __uint(max_entries, 1024);
} events_t SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    struct event event = {};
    event.pid = pid;
    event.uid = uid;
    bpf_probe_read_user(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_map_update_elem(&events_t, &pid, &event, BPF_ANY);

    return 0;
}
SEC("uretprobe/bash_retval")
int uretprobe_bash_retval(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    int retval = (int)PT_REGS_RC(ctx);

    struct event *event_p = bpf_map_lookup_elem(&events_t, &pid);

    if (event_p) {
        event_p->retval = retval;
        bpf_map_delete_elem(&events_t, &pid);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event_p, sizeof(struct event));
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
