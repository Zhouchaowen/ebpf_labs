# Tracepoint

可以通过查看 `/sys/kernel/debug/tracing/available_events` 文件的内容找到 tracepoint 可监控的事件。 文件中每行内容的格式是:

```bash
# <category>:<name>
syscalls:sys_enter_execve
```

## 引用方式

tracepoint 事件对应的 SEC 格式为:

```c
// SEC("tracepoint/<category>/<name>")/SEC("tp/<category>/<name>")
// 比如:
SEC("tracepoint/syscalls/sys_enter_fchmodat")
SEC("tp/syscalls/sys_enter_fchmodat") // 等同
```

> `<category>` 和 `<name>` 的值均取值前面 available_events 文件中列出的内容。

## 参数类型

如何确定 tracepoint 事件处理函数的参数类型，获取对应的内核调用参数? 

假设，我们想通过 tracepoint 监控 `chmod` 这个命令涉及的 `fchmodat` 系统调用, 比如拿到操作文件名称以及操作的权限 mode 的值。

第一步，先确定 `chmod` 所使用的系统调用，这个比较简单，有很多种方法可以做到，比如通过 `strace` 命令:

```bash
$ strace chmod 600 a.txt
...
fchmodat(AT_FDCWD, "a.txt", 0600)       = 0
...
```

第二步，找到针对这个系统调用可以使用的 tracepoint 事件:

```bash
$ sudo cat /sys/kernel/debug/tracing/available_events |grep fchmodat
syscalls:sys_exit_fchmodat
syscalls:sys_enter_fchmodat
```

可以看到，有 `sys_enter_fchmodat` (进入)和 `sys_exit_fchmodat` (退出)这两个事件。

第三步，确定函数的参数类型：这个需要到 `vmlinux.h` 文件中进行查找， 一般 `sys_enter_xx` 对应 `trace_event_raw_sys_enter` ， `sys_exit_xx` 对应 `trace_event_raw_sys_exit` ， 其他的一般对应 `trace_event_raw_<name>` ，如果没找到的话，可以参考 `trace_event_raw_sys_enter` 的例子找它相近的 struct。

 对于 `sys_enter_fchmodat` ，我们使用 `trace_event_raw_sys_enter` 这个 struct:

```c
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};
```

其中 `args` 中就存储了事件相关的我们可以获取的信息，至于里面包含了哪些信息就是第四步需要确定的信息。

第四步，确定事件本身可以获取到哪些信息，虽然我们知道 `fchmodat` 系统调用需要提供文件名称和 mode 信息， 但是，我们不确定是否可以在 ebpf 程序中获取到这些信息。

可以通过查看 `/sys/kernel/debug/tracing/events/<category>/<name>/format` 文件获取到我们可以获取哪些信息。 比如 `sys_enter_fchmodat` 这个事件的内容如下:

```bash
$ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_fchmodat/format
name: sys_enter_fchmodat
ID: 647
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:umode_t mode;     offset:32;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode))
```

`print fmt` 中引用的字段都是我们可以在 ebpf 程序中获取的信息。 从上面可以看到，我们可以获取 `sys_enter_fchmodat` 事件的 `dfd` 、 `filename` 以及 `mode` 信息， 这里就包含了前面所说的文件名称以及权限 mode 信息。 

这些字段的值可以通过 `trace_event_raw_sys_enter` 的 `args` 数组获取，即通过 `args[0]` 获取 `dfd` , `args[1]` 获取 `filename` 以此类推。

信息都确定好了，就可以写程序了。比如上面 `sys_enter_fchmodat` 事件的示例 ebpf 程序如下:

```c
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->host_pid = bpf_get_current_pid_tgid() >> 32;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);
    event->mode = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```



## Reference

[本文来源] https://mozillazg.com/2022/05/ebpf-libbpf-tracepoint-common-questions.html



