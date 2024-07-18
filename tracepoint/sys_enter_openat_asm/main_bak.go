package main

import (
	"fmt"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf sys_enter_openat.c -- -I../../headers
func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("load bpf: %v", err)
	}
	fmt.Printf("spec:%+v", spec.Programs["tracepoint_openat"])

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	<-stopper

}
