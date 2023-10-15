# KProbe

内核而言，hook 会尽可能选在 tracepoint，如果没有 tracepoint，会考虑使用 kprobe。

tracepoint 的范围有限，而内核函数又太多，基于各种需求场景，kprobe 的出场机会较多；但需要注意的，并不是所有的内核函数都可以选做 hook 点，inline 函数无法被 hook，static 函数也有可能被优化掉；如果想知道究竟有哪些函数可以选做 hook 点，在 Linux 机器上，可以通过`less /proc/kallsyms`查看。

使用 eBPF 时，内核代码 kprobe 的书写范例如下：

```c
SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *regs)
{
    struct file *file
    file = (struct file *)PT_REGS_PARM1(regs);
    // ...
}
```

COPY

其中 pt_regs 的结构体如下：

```c
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
    unsigned long orig_ax;
/* Return frame for iretq */
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
/* top of stack page */
};
```

通常来说，我们要获取的参数，均可通过诸如 PT_REGS_PARM1 这样的宏来拿到，宏定义如下：



## Reference

[本文来源] https://www.cnxct.com/using-ebpf-kprobe-to-file-notify/



