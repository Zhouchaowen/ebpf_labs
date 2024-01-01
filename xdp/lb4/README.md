# Lb4
通过xdp实现L4负载均衡

## generate
执行`make gen`，通过bpf2go编译xdp程序，生成golang相关问文件。
```bash
$ cd ebpf/xdp/lb4 && make build
```

## run

> 保证docker当前没有运行任何容器,因为lb4.c中的所有IP地址为硬编码(数字为IP地址最后一位)
>
> ```c
> #define BACKEND_A 2
> #define BACKEND_B 3
> #define CLIENT 4
> #define LB 5
> ```

Terminal1：backend-A

```bash
$ docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
```

Terminal1：backend-B

```bash
$ docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
```

Terminal2：client

```bash
$ docker run -itd --name client -h client --env TERM=xterm-color ubuntu:22.04 sh
```

Terminal3：lb4

```bash
$ docker run -itd --name lb4 -h lb4 --privileged --env TERM=xterm-color ubuntu:22.04 sh
```

Attach xdp

```bash
$ nsenter -t $(docker inspect -f {{.State.Pid}} lb4) -n

$ make run NIC=eth0
```

curl

```bash
$ nsenter -t $(docker inspect -f {{.State.Pid}} client) -n

$ curl 172.17.0.5
```

## reference

https://github.com/lizrice/lb-from-scratch
