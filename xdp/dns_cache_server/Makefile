# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
CFLAGS := -O2 -g -Wall -Werror -D DEBUG $(CFLAGS)

# The network card name
NET=lo

format:
	find . -type f -name "*.c" | xargs clang-format -i

# $BPF_CLANG is used in go:generate invocations.
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS)
gen:
	go generate ./...

run:
	go run -exec sudo main.go bpf_bpfel.go -n $(NET)
