//go:build ignore

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_DATA_SIZE_POSTGRES 256

struct data_t {
    u64 pid;
    u64 timestamp;
    char query[MAX_DATA_SIZE_POSTGRES];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct data_t *unused __attribute__((unused));

// https://github.com/postgres/postgres/blob/7b7ed046cb2ad9f6efac90380757d5977f0f563f/src/backend/tcop/postgres.c#L987-L992
// hook function exec_simple_query
// versions 10 - now
// static void exec_simple_query(const char *query_string)
SEC("uprobe/pg_parse_query")
int postgres_query(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    struct data_t data = {};
    data.pid = pid;  // only process id
    data.timestamp = bpf_ktime_get_ns();

    char *sql_string = (char *)PT_REGS_PARM1(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.query, sizeof(data.query), sql_string);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
