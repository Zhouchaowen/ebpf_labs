# bpf-helpers

## bpf_map_lookup_elem

```c
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
```

**Description:**

在映射中查找与键关联的条目

**Return:**

映射与键关联的值，如果未找到条目，则为 NULL。

##bpf_map_update_elem

```c
long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
```

**Description:**

使用值添加或更新与映射中的键相关联的条目的值。 flags是以下之一：

- BPF_NOEXIST: key 的条目不得存在于映射中。
- BPF_EXIST: key 的条目必须已存在于地图中。
- BPF_ANY: 密钥条目的存在没有条件。

标志值 BPF_NOEXIST 不能用于 BPF_MAP_TYPE_ARRAY 或 BPF_MAP_TYPE_PERCPU_ARRAY 类型的映射（所有元素始终存在），帮助器将返回错误。

**Return:**

成功时为 0，失败时为负错误。

## bpf_map_delete_elem

```c
long bpf_map_delete_elem(struct bpf_map *map, const void *key)
```

**Description:**

从地图中删除带有键的条目。

**Return:**

成功时为 0，失败时为负错误。

##bpf_probe_read

```c
long bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)
```

**Description:**

对于跟踪程序，安全地尝试从内核空间地址 unsafe_ptr 读取 size 字节并将数据存储在 dst 中。

通常，使用 bpf_probe_read_user() 或 bpf_probe_read_kernel() 代替。

**Return:**

成功时为 0，失败时为负错误。

## bpf_ktime_get_ns

```c
u64 bpf_ktime_get_ns(void)
```

**Description:**

返回自系统启动以来经过的时间（以纳秒为单位）。 不包括系统暂停的时间。 请参阅：clock_gettime(CLOCK_MONOTONIC)。

**Return:**

当前 ktime。

## bpf_trace_printk

```c
long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
```

**Description:**

**Return:**

## bpf_get_prandom_u32

```c
u32 bpf_get_prandom_u32(void)
```

**Description:**

获取一个伪随机数。

从安全角度来看，该帮助程序使用其自己的伪随机内部状态，并且不能用于推断内核中其他随机函数的种子。 然而，必须注意的是，助手使用的生成器在加密上并不安全。

**Return:**

随机 32 位无符号值。

## bpf_get_smp_processor_id

```c
u32 bpf_get_smp_processor_id(void)
```

**Description:**

获取 SMP（对称多处理）处理器 ID。 请注意，所有程序都在禁用迁移的情况下运行，这意味着 SMP 处理器 ID 在程序的所有执行过程中都是稳定的。

**Return:**

运行程序的处理器的 SMP id。

## bpf_skb_store_bytes

```c
long bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const
       void *from, u32 len, u64 flags)
```

**Description:**

将地址 from 中的 len 个字节存储到与 skb 关联的数据包中，偏移量处。

flags 是 BPF_F_RECOMPUTE_CSUM（存储字节后自动重新计算数据包的校验和）和 BPF_F_INVALIDATE_HASH（将 skb->hash、skb->swhash 和 skb->l4hash 设置为 0）的组合。

调用此帮助程序很容易更改底层数据包缓冲区。 因此，在加载时，如果助手与直接数据包访问结合使用，则验证者先前对指针进行的所有检查都会无效，并且必须再次执行。

**Return:**

成功时为 0，失败时为负错误。

## bpf_l3_csum_replace

```c
long bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64
       from, u64 to, u64 size)
```

**Description:**

用于重新计算与`skb`相关的网络数据包的第3层（例如IP）校验和。这个函数是增量计算的，因此它需要知道以前被修改的头部字段的旧值（`from`），新值（`to`）以及这个字段的字节数（通常是2或4），这些信息都由`size`参数提供。另外，您还可以通过将`from`和`size`都设置为0，将旧值和新值的差值存储在`to`中。不管使用哪种方法，`offset`参数指示了在数据包中IP校验和的位置。

需要注意的是，这个辅助函数与`bpf_csum_diff()` 协同工作。`bpf_csum_diff()` 用于计算校验和的差异，但不会原地更新校验和。它提供更灵活的选项，并且可以处理大于2或4字节的校验和更新。

需要谨慎使用这个辅助函数，因为它有可能改变底层的数据包缓冲区。因此，在加载时，由验证器以前执行的所有指针检查都将无效，如果将这个辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_l4_csum_replace

```c
 long bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64
       from, u64 to, u64 flags)
```

**Description:**

用于重新计算与`skb`相关的网络数据包的第4层（例如TCP、UDP或ICMP）校验和。这个函数是增量计算的，因此它需要知道以前被修改的头部字段的旧值（`from`），新值（`to`），以及这个字段的字节数（通常是2或4），这些信息都由`flags`参数提供。另外，您还可以通过将`from`和`flags`的最低4位都设置为0，将旧值和新值的差值存储在`to`中。不管使用哪种方法，`offset`参数指示了在数据包中IP校验和的位置。

`flags`参数不仅包含字段大小的信息（存储在最低的四位中），还可以通过按位OR运算添加实际的标志。以下是可能的标志选项：

- `BPF_F_MARK_MANGLED_0`：如果启用此标志，将保留空的校验和（除非还添加了`BPF_F_MARK_ENFORCE`），并且对于导致空校验和的更新，值将设置为`CSUM_MANGLED_0`。
- `BPF_F_PSEUDO_HDR`：如果启用此标志，表示校验和应该根据伪标头计算。

这个函数通常与`bpf_csum_diff()` 协同工作。`bpf_csum_diff()` 用于计算校验和的差异，但不会原地更新校验和。它提供更灵活的选项，并且可以处理大于2或4字节的校验和更新。

需要注意的是，这个辅助函数可能会更改底层的数据包缓冲区。因此，在加载时，之前由验证器执行的所有指针检查都将失效，如果将这个辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_tail_call

```c
long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)
```

**Description:**

用于触发一个“尾调用”，也就是说，跳转到另一个eBPF程序中。它使用相同的堆栈帧（但是不会访问调用者的堆栈上的值和寄存器中的值）。这个机制允许程序链接，无论是为了提高可用eBPF指令的最大数量，还是为了在条件块中执行给定的程序。出于安全原因，存在可以执行的连续尾调用数量的上限。

使用这个辅助函数时，程序会尝试跳转到`prog_array_map`中索引为`index`的程序中。`prog_array_map`是一种特殊类型的映射，称为`BPF_MAP_TYPE_PROG_ARRAY`，它包含了eBPF程序的数组。此外，它将`ctx`作为指向上下文的指针传递。

如果调用成功，内核将立即运行新程序的第一条指令。这不是一个函数调用，它不会返回到先前的程序。如果调用失败，那么辅助函数没有效果，调用者将继续运行其后续的指令。调用可能失败的原因包括：目标程序不存在（即`index`大于`prog_array_map`中的条目数量），或者已经达到了这一程序链的最大尾调用数量。这个限制在内核中由`MAX_TAIL_CALL_CNT` 宏定义（不可由用户空间访问），当前设置为33。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_clone_redirect

```c
long bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)
```

**Description:**

用于克隆并将与`skb`相关的数据包重定向到另一个具有索引`ifindex`的网络设备上。它支持对入口和出口接口进行重定向。`flags` 参数中的 `BPF_F_INGRESS` 标志用于区分入口路径和出口路径（如果该标志存在，则选择入口路径，否则选择出口路径）。目前，这是唯一支持的标志。

与 `bpf_redirect()` 辅助函数相比，`bpf_clone_redirect()` 需要复制数据包缓冲区，因此有一定的成本，但它可以在eBPF程序之外执行。相反，`bpf_redirect()` 更高效，但它通过一个操作代码进行处理，重定向仅在eBPF程序返回后发生。

需要注意的是，这个辅助函数可能会更改底层的数据包缓冲区。因此，在加载时，之前由验证器执行的所有指针检查都将失效，如果将这个辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_get_current_pid_tgid

```c
u64 bpf_get_current_pid_tgid(void)
```

**Description:**

用于获取当前进程（task）的PID（进程ID）和TGID（线程组ID）。

**Return:**

返回一个u64的数,通过如下算法计算:

```c
current_task->tgid << 32 | current_task->pid
```

其中，`current_task->tgid` 表示当前线程组的ID，`current_task->pid` 表示当前进程的ID。将它们合并为一个64位整数允许在BPF程序中方便地获取这两个值的组合。

## bpf_get_current_uid_gid

```c
u64 bpf_get_current_uid_gid(void)
```

**Description:**

用于获取当前进程（task）的UID（用户ID）和GID（组ID）。

**Return:**

返回一个u64的数,通过如下算法计算:

```c
current_gid << 32 | current_uid
```

其中，`current_gid` 表示当前进程的组ID，`current_uid` 表示当前进程的用户ID。将它们合并为一个64位整数允许在BPF程序中方便地获取这两个值的组合。

## bpf_get_current_comm

```c
long bpf_get_current_comm(void *buf, u32 size_of_buf)
```

**Description:**

用于将当前任务的`comm`属性复制到`buf`中，`buf`的大小由`size_of_buf`参数指定。`comm`属性包含了当前任务的可执行文件的名称（不包括路径部分）。`size_of_buf`必须严格为正数。在成功时，此辅助函数确保`buf`以NUL（空字符）结尾。在失败时，它会将`buf`填充为零。

- `buf`：指向存储任务名称的缓冲区的指针。
- `size_of_buf`：缓冲区的大小，以字节为单位。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_get_cgroup_classid

```c
u32 bpf_get_cgroup_classid(struct sk_buff *skb)
```

**Description:**

用于检索当前任务的net_cls cgroup的类别ID（classid），也就是与`skb`相关的net_cls cgroup的类别ID。

net_cls cgroup允许根据用户提供的标识符标记所有来自属于相关cgroup的任务的网络数据包。这个辅助函数可以在TC（Traffic Control）出口路径上使用，但不能在入口路径上使用。

需要注意的是，Linux内核有两个版本的cgroups：cgroups v1和cgroups v2。用户可以同时使用这两个版本，但是net_cls cgroup仅适用于cgroups v1。这使其与在cgroups上运行的BPF程序不兼容，因为后者是仅适用于cgroups v2的功能。

此外，要使用此辅助函数，内核必须使用`CONFIG_CGROUP_NET_CLASSID` 配置选项设置为"y"或"m"来编译。如果内核未启用此选项，该函数可能不可用。

**Return:**

返回值是一个32位整数，表示当前任务的net_cls cgroup的类别ID。如果任务未配置net_cls cgroup，则返回0，表示默认未配置的类别ID。

## bpf_skb_vlan_push

```c
long bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
```

**Description:**

用于向与`skb`相关的数据包推送一个 VLAN 标签（VLAN tag），并更新校验和。

- `skb`：指向要修改的网络数据包的`struct sk_buff`结构体的指针。
- `vlan_proto`：要推送的 VLAN 协议的16位整数表示，通常是`ETH_P_8021Q`（0x8100）或`ETH_P_8021AD`（0x88A8）。
- `vlan_tci`：VLAN Tag Control Information（TCI）的16位整数表示，包括VLAN ID和VLAN优先级。

如果`vlan_proto`不等于`ETH_P_8021Q`和`ETH_P_8021AD`，它会被视为`ETH_P_8021Q`。

需要注意的是，调用这个函数可能会更改底层数据包缓冲区。因此，在加载时，之前由验证器执行的所有指针检查都将失效，如果将这个辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_skb_vlan_pop

```c
long bpf_skb_vlan_pop(struct sk_buff *skb)
```

**Description:**

用于从与 `skb` 关联的数据包中弹出一个 VLAN 标签（VLAN header）。

这个函数将会从数据包中移除 VLAN 标签，并且需要注意，调用这个函数可能会更改底层数据包缓冲区。因此，在加载时，之前由验证器执行的所有指针检查都将失效，如果将这个辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

如果操作成功，它将返回0，否则将返回一个负数错误代码。

## bpf_skb_get_tunnel_key

```c
long bpf_skb_get_tunnel_key(struct sk_buff *skb, struct
       bpf_tunnel_key *key, u32 size, u64 flags)
```

**Description:**

**Return:**

## bpf_skb_set_tunnel_key

```c
long bpf_skb_set_tunnel_key(struct sk_buff *skb, struct
       bpf_tunnel_key *key, u32 size, u64 flags)
```

**Description:**

**Return:**

## bpf_perf_event_read

```c
u64 bpf_perf_event_read(struct bpf_map *map, u64 flags)
```

**Description:**

用于读取性能事件计数器的值。这个函数依赖于一个类型为 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 的映射（map）。性能事件计数器的特性是在将map与性能事件文件描述符更新时选择的。该映射是一个数组，其大小等于可用CPU的数量，每个单元格包含与一个CPU相关的值。要检索的值由 `flags` 参数指示，该参数包含要查找的CPU索引，掩码为 `BPF_F_INDEX_MASK`。或者，将 `flags` 设置为 `BPF_F_CURRENT_CPU` 可以表示应该检索当前CPU的值。

需要注意的是，在Linux 4.13之前，只能检索硬件性能事件。

另外，需要注意的是，在一般情况下，推荐使用较新的辅助函数 `bpf_perf_event_read_value()`，而不是 `bpf_perf_event_read()`。后者具有一些ABI怪癖，其中错误和计数器值被用作返回代码（这样做是错误的，因为范围可能重叠）。较新的 `bpf_perf_event_read_value()` 解决了这个问题，并在 `bpf_perf_event_read()` 接口上提供了更多功能。

**Return:**

返回从映射中读取的性能事件计数器的值，或者在失败的情况下返回负数错误代码。

## bpf_redirect

```c
long bpf_redirect(u32 ifindex, u64 flags)
```

**Description:**

用于将数据包重定向到另一个具有索引 `ifindex` 的网络设备上。这个辅助函数类似于 `bpf_clone_redirect()`，但不会克隆数据包，因此提供了更高的性能。

- `ifindex`：要重定向到的网络设备的索引。
- `flags`：标志参数，可以包含 `BPF_F_INGRESS`。`BPF_F_INGRESS` 用于区分入口路径和出口路径（如果标志存在，则选择入口路径，否则选择出口路径）。对于XDP（eXpress Data Path），只支持重定向到出口接口，不接受任何标志。

除了XDP之外，可以在入口和出口接口上使用此辅助函数进行重定向。

需要注意的是，如果想要在更通用的情况下使用重定向，可以使用更通用的 `bpf_redirect_map()` 辅助函数，它使用BPF映射来存储重定向目标，而不是直接提供给辅助函数。

**Return:**

对于XDP，如果操作成功，该辅助函数返回`XDP_REDIRECT`，如果出现错误，则返回`XDP_ABORTED`。对于其他程序类型，如果操作成功，返回值是`TC_ACT_REDIRECT`，如果出现错误，则返回`TC_ACT_SHOT`。

## bpf_get_route_realm

```c
u32 bpf_get_route_realm(struct sk_buff *skb)
```

**Description:**

用于检索与 `skb` 相关的数据包的目的地的路由领域（realm），也就是目的地的 `tclassid` 字段。检索到的标识符是用户提供的标签，类似于与 `net_cls` cgroup（请参阅 `bpf_get_cgroup_classid()` 辅助函数的描述）一起使用的标签，但在这里，该标签由路由（目的地条目）持有，而不是由任务持有。

可以在 `clsact` TC 出口 hook 上使用此辅助函数（请参考 `tc-bpf(8)`），或者也可以在传统的有类别的出口 qdisc 上使用，但不能在 TC 入口路径上使用。在 `clsact` TC 出口 hook 的情况下，这样做的优势在于，在传输路径中目的地条目尚未被丢弃。因此，不需要通过 `netif_keep_dst()` 来人为地保留目的地条目，直到 skb 被释放。

要使用此辅助函数，内核必须使用 `CONFIG_IP_ROUTE_CLASSID` 配置选项编译。

**Return:**

该函数返回与数据包的目的地关联的路由的领域（realm），如果没有找到则返回0。



```c
long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64
       flags, void *data, u64 size)
```

**Description:**

用于将原始数据块写入由`map`维护的特殊BPF性能事件（perf event）。该性能事件的类型必须是 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`。这个性能事件必须具有以下属性：

- `PERF_SAMPLE_RAW` 作为 `sample_type`
- `PERF_TYPE_SOFTWARE` 作为 `type`
- `PERF_COUNT_SW_BPF_OUTPUT` 作为 `config`

以下是该函数的参数和描述：

- `ctx`：程序的上下文。
- `map`：包含性能事件的BPF映射。
- `flags`：标志参数，可以包含`BPF_F_INDEX_MASK`以指示要放置值的映射中的索引，或者可以设置为`BPF_F_CURRENT_CPU`以指示使用当前CPU核心的索引。
- `data`：要写入的数据的指针。
- `size`：数据的大小。

在用户空间，要读取这些值的程序需要在性能事件上调用 `perf_event_open()`（可以是一个或所有CPU的性能事件），并将文件描述符存储到映射中。这必须在eBPF程序可以将数据发送到性能事件之前完成。

`bpf_perf_event_output()` 在与用户空间共享数据方面比`bpf_trace_printk()` 具有更好的性能，并且更适用于从eBPF程序中流式传输数据。

需要注意的是，这个辅助函数不仅适用于跟踪用例，还可以用于连接到TC或XDP的程序，它允许将数据传递给用户空间的监听器。数据可以是自定义结构、数据包有效负载，或两者的组合。

**Return:**

函数返回0表示成功，或者返回负数错误代码表示失败。



```c
long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len)
```

**Description:**

用于从数据包中加载数据。它可以用于从与 `skb` 关联的数据包中的指定偏移量加载长度为 `len` 字节的数据，并将其放入 `to` 指向的缓冲区中。

然而，自从Linux 4.7版本开始，这个辅助函数的使用大部分被"直接数据包访问"所取代，允许使用 `skb->data` 和 `skb->data_end` 分别指向数据包数据的第一个字节和数据包数据的最后一个字节之后的字节。不过，如果希望一次从数据包中读取大量数据到eBPF栈中，仍然可以使用这个辅助函数。

**Return:**

函数返回0表示成功，或者返回负数错误代码表示失败。



```c
long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags)
```

**Description:**

用于遍历用户或内核堆栈并返回其ID。为了实现这一目标，这个辅助函数需要 `ctx`，它是一个指向执行跟踪程序的上下文的指针，以及一个指向类型为 `BPF_MAP_TYPE_STACK_TRACE` 的映射的指针。

最后一个参数 `flags` 保存要跳过的堆栈帧数（从0到255），使用 `BPF_F_SKIP_FIELD_MASK` 进行掩码处理。下面的位可以用于设置以下标志的组合：

- `BPF_F_USER_STACK`：收集用户空间堆栈而不是内核堆栈。
- `BPF_F_FAST_STACK_CMP`：仅通过哈希比较堆栈。
- `BPF_F_REUSE_STACKID`：如果两个不同的堆栈哈希为相同的 `stackid`，则丢弃旧的 `stackid`。

检索到的堆栈ID是一个32位的长整数句柄，可以进一步与其他数据（包括其他堆栈ID）组合，并用作映射的键。这对于生成各种图表（例如火焰图或离CPU图）非常有用。

对于遍历堆栈，这个辅助函数优于 `bpf_probe_read()`，后者可以与展开的循环一起使用，但效率不高且消耗大量的eBPF指令。相反，`bpf_get_stackid()` 可以收集最多 `PERF_MAX_STACK_DEPTH` 个内核和用户帧。请注意，此限制可以通过sysctl程序进行控制，应手动增加以便对长用户堆栈进行分析（例如Java程序的堆栈）。要这样做，请使用以下命令：

```bash
# sysctl kernel.perf_event_max_stack=<new value>
```

**Return:**

函数返回正数或零表示成功的堆栈ID，或者返回负数错误代码表示失败。



```c
s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)
```

**Description:**

用于计算两个原始缓冲区之间的校验和差异。具体来说，它从由 `from` 指针指向的原始缓冲区（长度为 `from_size`，必须是4的倍数）计算校验和差异，然后将结果应用到由 `to` 指针指向的原始缓冲区（大小为 `to_size`，同样需要是4的倍数）。还可以选择添加一个种子（seed）到值中，这可以级联使用，种子可以来自先前对该辅助函数的调用。

这个函数非常灵活，可以用于多种情况：

- 当 `from_size` 为0，`to_size` 大于0且种子设置为校验和时，可以用于向数据包中添加新数据。
- 当 `from_size` 大于0，`to_size` 为0且种子设置为校验和时，可以用于从数据包中删除数据。
- 当 `from_size` 大于0，`to_size` 大于0且种子设置为0时，可以用于计算差异。请注意，`from_size` 和 `to_size` 不需要相等。

这个辅助函数可以与 `bpf_l3_csum_replace()` 和 `bpf_l4_csum_replace()` 结合使用，可以将 `bpf_csum_diff()` 计算的差异传递给它们，从而实现更复杂的校验和更新操作。

**Return:**

函数返回校验和的结果，或者在失败的情况下返回负数错误代码。



```c
long bpf_skb_get_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)
```

**Description:**

用于检索与 `skb` 关联的数据包的隧道选项元数据，并将原始隧道选项数据存储到大小为 `size` 的缓冲区 `opt` 中。

这个辅助函数可以与能够以“收集元数据”模式操作的封装设备一起使用（请参考 `bpf_skb_get_tunnel_key()` 描述中的相关说明以获取更多详细信息）。一个特殊的示例是与Geneve封装协议结合使用，它允许从eBPF程序中推送（使用 `bpf_skb_get_tunnel_opt()` 辅助函数）并检索任意TLV（Type-Length-Value标头）。这允许对这些标头进行完全自定义。

**Return:**

函数返回检索到的选项数据的大小。



```c
long bpf_skb_set_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)
```

**Description:**

**Return:**



```c
long bpf_skb_change_proto(struct sk_buff *skb, __be16 proto, u64 flags)
```

**Description:**

用于更改 `skb` 的协议为指定的 `proto`。目前支持从IPv4到IPv6的转换以及从IPv6到IPv4的转换。该辅助函数负责进行协议转换的基本工作，包括调整套接字缓冲区的大小。eBPF程序应通过 `skb_store_bytes()` 填充新的标头（如果有的话），并使用 `bpf_l3_csum_replace()` 和 `bpf_l4_csum_replace()` 重新计算校验和。这个辅助函数的主要用例是在eBPF程序中执行NAT64操作。

在内部，GSO（Generic Segmentation Offload）类型被标记为可疑，以便GSO/GRO（Generic Receive Offload）引擎检查标头并重新计算段。GSO目标的大小也会相应调整。

所有的 `flags` 值都保留供将来使用，必须保持为零。

调用这个辅助函数可能会更改底层数据包缓冲区。因此，在加载时，验证器之前对指针执行的所有检查都会失效，如果辅助函数与直接数据包访问结合使用，必须重新执行这些检查。

**Return:**

函数在成功时返回0，否则在失败时返回负数错误代码。



```c
long bpf_skb_change_type(struct sk_buff *skb, u32 type)
```

**Description:**

用于更改与 `skb` 关联的数据包的数据包类型。它实际上是将 `skb->pkt_type` 设置为 `type`，但是除了这个辅助函数外，eBPF程序没有对 `skb->pkt_type` 的写访问权限。使用这个辅助函数可以优雅地处理错误。

主要用例是以编程方式将传入的 `skb` 更改为 **PACKET_HOST**，而不是通过 `redirect(..., BPF_F_INGRESS)` 等方式重新传递。

请注意，`type` 只允许特定的值。目前，它们包括：

- **PACKET_HOST**：数据包是给我们的。
- **PACKET_BROADCAST**：将数据包发送到所有设备。
- **PACKET_MULTICAST**：将数据包发送到多播组。
- **PACKET_OTHERHOST**：将数据包发送给其他设备。

**Return:**

函数在成功时返回0，否则在失败时返回负数错误代码。



```c
long bpf_skb_under_cgroup(struct sk_buff *skb, struct bpf_map *map, u32 index)
```

**Description:**

用于检查 `skb` 是否是类型为 `BPF_MAP_TYPE_CGROUP_ARRAY` 的地图 `map` 中的索引 `index` 处的cgroup2的后代。

**Return:**

函数的返回值取决于测试的结果：

- 如果 `skb` 未通过cgroup2的后代测试，则返回0。
- 如果 `skb` 通过了cgroup2的后代测试，则返回1。
- 如果发生错误，则返回负数错误代码。



```c
u32 bpf_get_hash_recalc(struct sk_buff *skb)
```

**Description:**

用于检索数据包的哈希值 `skb->hash`。如果哈希值未设置，特别是如果哈希值由于操作而被清除（例如操纵操作），则重新计算此哈希值。随后可以直接使用 `skb->hash` 访问哈希值。

在某些操作可能会清除哈希值并触发下一次调用 `bpf_get_hash_recalc()` 时进行新的计算。这些操作包括：

- 调用 `bpf_set_hash_invalid()`。
- 使用 `bpf_skb_change_proto()` 更改数据包的协议。
- 使用带有 `BPF_F_INVALIDATE_HASH` 标志的 `bpf_skb_store_bytes()`。

**Return:**

函数返回32位哈希值。



```c
u64 bpf_get_current_task(void)
```

**Description:**

获取当前任务。

**Return:**

指向当前任务结构的指针。



```c
long bpf_probe_write_user(void *dst, const void *src, u32 len)
```

**Description:**

它试图以安全的方式将长度为 `len` 字节的数据从内核中的 `src` 缓冲区写入用户空间中的 `dst` 地址。这个函数只能在处于用户上下文的线程中使用，并且 `dst` 必须是有效的用户空间地址。

需要注意的是，这个辅助函数不应该用于实现任何类型的安全机制，因为存在 TOC-TOU（Time-Of-Check to Time-Of-Use）攻击的风险。它主要用于调试、转发和操作半合作进程的执行。

此功能主要用于实验，并且有导致系统崩溃和运行程序失败的风险。因此，当附加了使用此辅助函数的eBPF程序时，内核日志中会打印包含PID和进程名称的警告信息。

**Return:**

函数返回0表示成功，或者返回负数错误代码表示失败。



```c
long bpf_current_task_under_cgroup(struct bpf_map *map, u32 index)
```

**Description:**

**Return:**



**Description:**

**Return:**

**Description:**

**Return:**

**Description:**

**Return:**

**Description:**

**Return:**



**Description:**

**Return:**

**Description:**

**Return:**



**Description:**

**Return:**



**Description:**

**Return:**

**Description:**

**Return:**



**Description:**

**Return:**



```c

```



```c

```



```c

```

