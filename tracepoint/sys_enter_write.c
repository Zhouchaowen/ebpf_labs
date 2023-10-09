#include <linux/bpf.h>
#include <bpf_helpers.h>

int _pid = 0;

SEC("tracepoint/syscalls/sys_enter_write")
int hello_bpf(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (_pid != pid) return 0;

    bpf_printk("BPF triggered from PID %d\n", pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";