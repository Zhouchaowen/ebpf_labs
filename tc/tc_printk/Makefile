# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DEV ?= lo

define attach_tc
    tc qdisc add dev $(DEV) clsact;
    tc filter add dev $(DEV) egress bpf da obj bpf_bpfel.o sec tc;
    tc filter show dev $(DEV) egress;
    echo "Please run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see output of the BPF programs";
endef

format:
	find . -type f -name "*.c" | xargs clang-format -i

# $BPF_CLANG is used in go:generate invocations.
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS)
gen:
	go generate ./...

attach:
	@$(attach_tc)

detach:
	tc qdisc del dev $(DEV) clsact

run:
	go run -exec sudo main.go bpf_bpfel.go -n lo
