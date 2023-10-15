

# ebpf_labs

A series of ebpf_labs experiments

# how to compile

## require

- Kernel >= 5.4.0
- ghcr.io/cilium/ebpf-builder@1694533004

## clone
```bash
git clone 
```

## compile
> 示例：编译 ebpf_labs/xdp/printk_pass
```bash
cd ebpf_labs/xdp/printk_pass && make build
```

## Reference

https://github.com/asavie/xdp

https://github.com/cody0704/xdp-examples

https://rexrock.github.io/post/af_xdp1/

https://github.com/lixiangzhong/xdp/blob/master/example/af_xdp_kern.c

https://github.com/sudoamin2/sparrow

https://colobu.com/2023/04/17/use-af-xdp-socket/

https://colobu.com/2023/04/02/support-1m-pps-with-zero-cpu-usage/



