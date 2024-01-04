// +build ignore

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

#define READ_KERN(ptr)                                 \
  ({                                                   \
    typeof(ptr) _val;                                  \
    __builtin_memset((void *)&_val, 0, sizeof(_val));  \
    bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
    _val;                                              \
  })

#define READ_USER(ptr)                                      \
  ({                                                        \
    typeof(ptr) _val;                                       \
    __builtin_memset((void *)&_val, 0, sizeof(_val));       \
    bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
    _val;                                                   \
  })

struct event
{
    u32 sip;    //源IP
    u32 dip;    //目的IP
    u16 sport;  //源端口
    u16 dport;  //目的端口
    int family; //协议
    int pid;
	  u8 comm[80];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/tcp_connect")
int kb_tcp_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}


	struct sock_common sk_common = READ_KERN(sk->__sk_common);
	event->dip = READ_KERN(sk_common.skc_daddr);
	event->sip = READ_KERN(sk_common.skc_rcv_saddr);
	event->sport = READ_KERN(sk_common.skc_num);
	event->dport = bpf_ntohs(READ_KERN(sk_common.skc_dport));
	event->family = READ_KERN(sk_common.skc_family);

  event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, 80);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";