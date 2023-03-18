# printk_pass
当有流量访问网卡时，通过bpf_printk打印"xdp pass, hello xdp"

## generate
执行`make gen`，通过bpf2go编译xdp程序，生成golang相关问文件。
```bash
root@imianba:~/xdp_labs/printk_pass# make gen
go generate ./...
Compiled /root/xdp_labs/printk_pass/bpf_bpfeb.o
Stripped /root/xdp_labs/printk_pass/bpf_bpfeb.o
Wrote /root/xdp_labs/printk_pass/bpf_bpfeb.go
Compiled /root/xdp_labs/printk_pass/bpf_bpfel.o
Stripped /root/xdp_labs/printk_pass/bpf_bpfel.o
Wrote /root/xdp_labs/printk_pass/bpf_bpfel.go
root@imianba:~/xdp_labs/printk_pass# 
```

## run
执行`make run`运行，注意可能需要更改网卡名称，默认为lo
```bash
root@imianba:~/xdp_labs/printk_pass# make run
go run -exec sudo main.go bpf_bpfel.go -n lo
2023/03/18 08:46:14 Attached XDP program to iface "lo" (index 1)
2023/03/18 08:46:14 Press Ctrl-C to exit and remove the program
2023/03/18 08:46:14 Successfully started! Please run "sudo cat /sys/kernel/debug/tracing/trace_pipe" to see output of the BPF programs


```

## trace_pipe
新开终端，ping挂载的网卡对应的ip，默认为lo对应ip为127.0.0.1
```bash
root@imianba:~# ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.064 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.077 ms
```
新开终端，查看trace_pipe打印的日志信息。
```bash
root@imianba:~# sudo cat /sys/kernel/debug/tracing/trace_pipe
            ping-156842  [001] d.s11 3808758.716803: bpf_trace_printk: xdp pass, hello xdp
            ping-156842  [001] d.s11 3808758.716826: bpf_trace_printk: xdp pass, hello xdp
            ping-156842  [001] d.s11 3808759.731813: bpf_trace_printk: xdp pass, hello xdp
            ping-156842  [001] d.s11 3808759.731835: bpf_trace_printk: xdp pass, hello xdp
```

## reference
https://tonybai.com/2022/07/19/develop-ebpf-program-in-go/
https://github.com/xdp-project/xdp-tutorial