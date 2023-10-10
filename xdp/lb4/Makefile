# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

NIC=lo
IMAGE=ghcr.io/cilium/ebpf-builder:1694533004
CURRENT_DIR := $(shell pwd)
PARENT_DIR := $(abspath $(CURRENT_DIR)/..)
GRANDPARENT_DIR := $(abspath $(PARENT_DIR)/..)

format:
	find . -type f -name "*.c" | xargs clang-format -i

env:
	go env -w GOPROXY=https://goproxy.cn,direct

# $BPF_CLANG is used in go:generate invocations.
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS)
gen: env
	go generate ./...

run:
	go run -exec sudo main.go bpf_bpfel.go -n $(NIC)

build:
	docker run --rm  -v $(GRANDPARENT_DIR):/root/ebpf_labs $(IMAGE) bash -c "cd /root/ebpf_labs/xdp/lb4 && make gen"