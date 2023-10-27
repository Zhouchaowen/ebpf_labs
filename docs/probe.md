# Probe

## 读取内核结构体字段

[参考1](http://arthurchiao.art/blog/bpf-portability-and-co-re-zh/#3-bpf-co-re%E9%AB%98%E5%B1%82%E6%9C%BA%E5%88%B6) [参考2](https://mozillazg.com/2021/05/ebpf-gobpf-get-function-argument-values-from-pt_regs.html)

最常见和最典型的场景就是从某些内核结构体中读取一个字段。

**例子：读取 `task_struct->pid` 字段**

假设我们想**读取 task_struct 中的 pid 字段**。

> **方式一：BCC（可移植）**

用 BCC 实现，代码很简单：

```c
pid_t pid = task->pid;
```

BCC 有强大的代码重写（rewrite）能力，能自动将以上代码**转换成一次 bpf_probe_read() 调用** （但**有时重写之后的代码并不能正确**，具体取决于表达式的复杂程度）。

`libbpf` 没有 BCC 的代码重写魔法（code-rewriting magic），但提供了几种其他方式来 实现同样的目的。

> **方式二：`libbpf` + `BPF_PROG_TYPE_TRACING`（不可移植）**

如果使用的是最近新加的 `BTF_PROG_TYPE_TRACING` 类型 BPF 程序，那校验器已经足够智 能了，能原生地理解和记录 BTF 类型、跟踪指针，直接（安全地）读取内核内存 ，

```c
pid_t pid = task->pid;
```

从而**避免了调用 bpf_probe_read()**，格式和语法更为自然，而且**无需编译器重写**（rewrite）。 但此时，这段代码还不是可移植的。

> **方式三：`BPF_PROG_TYPE_TRACING` + CO-RE（可移植）**

要将以上 `BPF_PROG_TYPE_TRACING` 代码其变成可移植的，只需将待访问字段 `task->pid` 放到编译器内置的一个名为 `__builtin_preserve_access_index()` 的宏中：

```c
pid_t pid = __builtin_preserve_access_index(({ task->pid; }));
```

这就是全部工作了：这样的程序在不同内核版本之间是可移植的。

> **方式四：libbpf + CO-RE `bpf_core_read()`（可移植）**

如果使用的内核版本还没支持 `BPF_PROG_TYPE_TRACING`，就必须显式地使用 `bpf_probe_read()` 来读取字段。

Non-CO-RE libbpf 方式：

```c
pid_t pid;
bpf_probe_read(&pid, sizeof(pid), &task->pid);
```

有了 CO-RE+libbpf，我们有两种方式实现这个目的。

第一种，直接将 `bpf_probe_read()` 替换成 `bpf_core_read()`：

```c
pid_t pid;
bpf_core_read(&pid, sizeof(pid), &task->pid);
```

`bpf_core_read()` 是一个很简单的宏，直接展开成以下形式：

```c
bpf_probe_read(&pid, sizeof(pid), __builtin_preserve_access_index(&task->pid));
```

可以看到，第三个参数（`&task->pid`）放到了前面已经介绍过的编译器 built-int 中， 这样 clang 就能记录该字段的重定位信息，实现可移植。

第二种方式是使用 `BPF_CORE_READ()` 宏，我们通过下面的例子来看。

**例子：读取 `task->mm->exe_file->f_inode->i_ino` 字段**

这个字段表示的是当前进程的可执行文件的 inode。 来看一下访问嵌套层次如此深的结构体字段时，面临哪些问题。

> **方式一：BCC（可移植）**

用 BCC 实现的话可能是下面这样：

```c
u64 inode = task->mm->exe_file->f_inode->i_ino;
```

BCC 会对这个表达式进行重写（rewrite），转换成 4 次 bpf_probe_read()/bpf_core_read() 调用， 并且每个中间指针都需要一个额外的临时变量来存储。

> **方式二：BPF CO-RE（可移植）**

下面是 BPF CO-RE 的方式，仍然很简洁，但无需 BCC 的代码重写（code-rewriting magic）：

```c
u64 inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
```

另外一个变种是：

```c
u64 inode;
BPF_CORE_READ_INTO(&inode, task, mm, exe_file, f_inode, i_ino);
```

**其他与字段读取相关的 CO-RE 宏**

- `bpf_core_read_str()`：可以直接替换 Non-CO-RE 的 `bpf_probe_read_str()`。

- `BPF_CORE_READ_STR_INTO()`：与 `BPF_CORE_READ_INTO()` 类似，但会对最后一个字段执行 `bpf_probe_read_str()`。

- `bpf_core_field_exists()`：判断字段是否存在，

  ```c
  pid_t pid = bpf_core_field_exists(task->pid) ? BPF_CORE_READ(task, pid) : -1;
  ```

- `bpf_core_field_size()`：判断字段大小，同一字段在不同版本的内核中大小可能会发生变化，

  ```
  u32 comm_sz = bpf_core_field_size(task->comm); /* will set comm_sz to 16 */
  ```

- `BPF_CORE_READ_BITFIELD()`：通过**直接内存读取**（direct memory read）方式，读取比特位字段

- `BPF_CORE_READ_BITFIELD_PROBED()`：底层会调用 `bpf_probe_read()`

  ```
  struct tcp_sock *s = ...;
  
  /* with direct reads */
  bool is_cwnd_limited = BPF_CORE_READ_BITFIELD(s, is_cwnd_limited);
  
  /* with bpf_probe_read()-based reads */
  u64 is_cwnd_limited;
  BPF_CORE_READ_BITFIELD_PROBED(s, is_cwnd_limited, &is_cwnd_limited);
  ```

## 获取进程名称

```c
char name[TASK_COMM_LEN];
bpf_get_current_comm(&name, sizeof(name));
```

## 获取进程信息

大多数基于 ebpf 技术的程序都有需要在 ebpf 程序中获取相应事件发生时触发该事件的进程信息的需求，在 linux 中， [task_struct](https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L657) 结构体包含了进程相关的信息，所以我们可以从 [bpf-helpers](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) 中也提供的辅助函数 `bpf_get_current_task()` 获取到的 task 实例中获取想要的进程信息：比如 pid、ppid、进程名称、进程 namespace 信息等信息。

**获取 host 层面的 pid 信息**

获取 host 层面的 pid 信息，之所以加个 host 层面是因为在类似容器的场景，进程有两个 pid 信息，一个是 host 上看到的 pid，另一个是容器中特定 pid namespace 下看到的 pid。

可以通过 bpf-helpers 提供的 `bpf_get_current_pid_tgid()` 函数（**封装了对 `task->tgid` 和 `task->pid` 的调用**）获取对应的 host 层面的 pid 信息：

```c
u32 host_pid = bpf_get_current_pid_tgid() >> 32;
```

有了 pid，一般也会需要 ppid 即父进程的 pid。ppid 我们就只能从 task 从获取了。 首先是需要通过 `task->real_parent` 拿到父进程的 task 信息，然后再通过 `task->tgid` 获取对应的 pid 信息:

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
u32 host_ppid = task->real_parent->tgid;
```

**获取 userspace（用户态） 层面的 pid 信息**

如上面所说，在容器等使用了独立的 pid namspace 的场景下，会出现对应 pid namespace 下看到的的 pid 跟 host 上的 pid 不一样的情况，所以我们也需要获取一下这个 userspace（用户态） 层面的 pid 信息。

主要是通过 `task->nsproxy` 拿到 [nsproxy](https://elixir.bootlin.com/linux/v5.13/source/include/linux/nsproxy.h#L31) 信息， `nsproxy` 的结构体定义如下：

```c
struct nsproxy {
    atomic_t count;
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
    struct net           *net_ns;
    struct time_namespace *time_ns;
    struct time_namespace *time_ns_for_children;
    struct cgroup_namespace *cgroup_ns;
};
```

可以看到 `nsproxy` 中包含了进程相关的各种 namespace 信息。可以通过下面的方法获取到所需要的 userspace 层面的 pid 信息:

```c
unsigned int level = task->nsproxy->pid_ns_for_children->level;
u32 pid = task->group_leader->thread_pid->numbers[level].nr;
```

获取对应的 ppid 的方法也是类似的:

```c
unsigned int p_level = task->real_parent->nsproxy->pid_ns_for_children->level;
u32 ppid = task->real_parent->group_leader->thread_pid->numbers[p_level].nr;
```

**获取 namespace 信息**

前面已经看到了 `nsproxy` 中包含了各种 namespace 信息，所以可以直接通过它就拿到 namspace 相关的信息。 比如获取 pid namespace 的 id:

```c
u32 pid_ns_id = task->nsproxy->pid_ns_for_children->ns.ium
```

## 读取数据宏

```bash
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), di)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), si)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), dx)
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((x), cx)
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((x), r8)
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), sp)
#define PT_REGS_FP_CORE(x) BPF_CORE_READ((x), bp)
#define PT_REGS_RC_CORE(x) BPF_CORE_READ((x), ax)
#define PT_REGS_SP_CORE(x) BPF_CORE_READ((x), sp)
#define PT_REGS_IP_CORE(x) BPF_CORE_READ((x), ip)
```

寄存器如下 (这里对比 x86_64 做说明):

```bash
R0: RAX, 存放函数返回值或程序退出状态码
R1: RDI，第一个实参
R2: RSI，第二个实参
R3: RDX，第三个实参
R4: RCX，第四个实参
R5: R8，第五个实参 （别问为啥没有第六个实参）
R6: RBX, callee saved
R7: R13, callee saved （别问为啥没有R12）
R8: R14, callee saved
R9: R15, callee saved
R10: RBP, 只读栈帧
```

通过寄存器的设计，我们可以看到，每个函数调用允许5个参数，这些参数只允许立即数或者指向自己的ebpf栈（通用内核栈是不被允许的）上的指针，所有的内存访问必须先把数据放到ebpf自己的栈上（512字节的栈），才能被ebpf程序进一步操作。

## 不能include结构体header读取结构体数据

尝试 debug 用户态程序的时候，往往遇到用户态程序参数是结构体，这个时候不能 include header 的话，怎么办呢？上 offset.

比如说：

```c
# include <stdio.h>
# include <unistd.h>

struct exp_s {
  int num;
  char name[35];
};

void accept_exp(struct exp_s *t) {
  printf("num: %d, name %s\n", t->num, t->name);
}

int main() {
  struct exp_s s = {
    .num = 1,
    .name = "keqing",
  };

  while(1) {
    s.num ++;
    accept_exp(&s);
    sleep(5);
  }

  return 0;
}
```

我们可以用如下的 bpftrace script 来抓 exp_s->name:

```c
bpftrace -e 'uprobe:./exp:accept_exp { $m = (uint8*)arg0; printf("%s\n", str($m+4));}'
```



## Reference

https://blog.gmem.cc/ebpf

