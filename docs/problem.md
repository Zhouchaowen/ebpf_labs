# eBPF编写场景问题

## 1.C结构体转Go结构体

```c
const struct event *unused __attribute__((unused));
```

这句eBPF的C语言代码是一个声明，用于定义一个名为`unused`的指向`struct event`类型的指针，并通过`__attribute__((unused))`标记该变量未被使用。这个标记告诉编译器，即使在代码中没有使用这个变量，也不要生成任何未使用变量的警告。

在eBPF程序中，这种用法可能是为了声明一个占位符变量，以防将来可能需要使用它，同时又避免编译器生成未使用变量的警告信息。这在一些情况下可能有用，因为eBPF程序可能会根据特定条件进行动态修改，因此某些变量可能在某些路径上未被使用。标记为`unused`并使用`__attribute__((unused))`可以帮助保持代码的清晰度，并且在需要时可以轻松地引入变量而不引发编译警告。

> 注意可能有内存对齐问题。

## 2.查找跟踪点

[参考](https://kiosk007.top/post/ebpf%E8%B6%85%E4%B9%8E%E4%BD%A0%E6%83%B3%E8%B1%A1/#ebpf-%E7%9A%84%E6%9C%AA%E6%9D%A5%E6%88%98%E5%9C%BA-cloud-native)

- **tracepoint**

```bash
# bpftrace -l 列出所有探针
$ sudo bpftrace -l 'tracepoint:syscalls:*'

# 查看 sys_enter_openat 详细的数据结构
$ sudo bpftrace -lv tracepoint:syscalls:sys_enter_openat
```

- **kprobe & kretprobe**

kprobes允许开发者在几乎所有的内核指令中以最小的开销设置动态的标记或中断。通过[kprobes](https://www.kernel.org/doc/html/latest/trace/kprobes.html)，你可以动态在内核函数执行前设置断点，甚至几乎可以在任何内核代码地址处设置断点，并且指定在断点被执行时要执行的处理函数。kprobe生效原理：

1. 创建并设置kprobe回调函数，调用时触发bpf程序执行。

2. 把目标地址替换成breakpoint指令(e.g., int3 on i386 and x86_64).

3. 当程序指令执行到breakpoint指令时，执行kprobe handler

4. bpf指令被执行，执行完成后返回到原来的目标地址。

5. 当unload kprobe时把目标地址恢复到原状。

- **uprobe&uretprobe**

```bash
# 如：查找postgres二进制文件的跟踪点，目标跟踪点: pg_parse_query
$ bpftrace -l 'uprobe:/usr/lib/postgresql/12/bin/postgres'

# 容器内查找
$ find /var/lib/docker/overlay2/ -name <postgres 目标文件>
$ bpftrace -l 'uprobe:/var/lib/docker/overlay2/.../bin/postgres:*'

# 执行跟踪
$ sudo bpftrace -e 'uprobe:/usr/lib/postgresql/12/bin/postgres:pg_parse_query { printf("sql: %s\n", str(arg0)); }'
```

## 3.符号表寻找跟踪函数

[参考](http://arthurchiao.art/blog/linux-tracing-basis-zh/)

```bash
# 查看有多少函数可以被跟踪
$ readelf -s <二进制文件> | grep "Symbol table"
Symbol table '.dynsym' contains 8 entries:
Symbol table '.symtab' contains 67 entries:

# 过滤目标函数
$ readelf -s postgres | grep pg_parse_query
```

## 4.查看编译后的ELF

```bash
# 编译时带 -g 参数。编译后文件会携带 debug_info 信息
 clang \
 -target bpf \
 -I../../headers \
 -g \
 -O2 -c xxx.c

# 查看编译后的elf
$ file xxx.o
xxx.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped

# 查看字节码与代码的映射，需要有(with debug_info)的消息才能查看
$ llvm-objdump -S xxx.bpf.o
```

## 5.verifier验证问题

[参考](https://zhuanlan.zhihu.com/p/590851484)

- 在 for 循环前面添加 #pragma unroll，进行循环展开，避免指令回跳，但在5.10内核版本是支持有限循环的，所以5.10以下版本有效。
- verifier 会保存栈内存的状态，所以栈的大小是有限的，目前是 512 字节。当栈内存大小超过 512 字节时，则会被 verifier 拒绝。
- 当访问栈时采用变量偏移，会导致无法推测寄存器的状态。所以 4.19 版本只支持常量偏移。下面是使用变量偏移的错误示例
- 直接使用bpf_trace_printk打印字符串，ebpf运行时问题。替换为：bpf_printk 

```
libbpf: prog 'pdm_main': bad map relo against '.rodata.str1.1' in section '.rodata.str1.1'
ERROR: opening BPF object file failed
Unable to load program
```



