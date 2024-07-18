```c
struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, 
                                   struct bpf_sock_tuple *tuple, 
                                   u32 tuple_size, 
                                   u64 netns, 
                                   u64 flags)
```

查找 TCP 套接字匹配元组，可以选择在子网络命名空间 netns 中。 必须检查返回值，如果非 NULL，则通过 bpf_sk_release() 释放。ctx应该指向程序的上下文，例如skb或socket（取决于使用的钩子）。 这用于确定查找的基本网络命名空间。

tuple_size 必须是以下之一：

sizeof(tuple->ipv4) 查找 IPv4 套接字。

sizeof(tuple->ipv6) 查找 IPv6 套接字。          

如果 netns 是带负号的 32 位整数，则将使用与 ctx 关联的 netns 中的套接字查找表。 对于 TC hooks，这是 skb 中设备的 netns。 对于套接字挂钩，这是套接字的网络。 如果 netns 是大于或等于 0 的任何其他有符号 32 位值，则它指定相对于与 ctx 关联的 netns 的 netns 的 ID。 超出 32 位整数范围的 netns 值被保留以供将来使用。标志的所有值都保留供将来使用，并且必须保留为零。仅当使用 CONFIG_NET 配置选项编译内核时，此帮助程序才可用。