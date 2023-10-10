package main

import (
	"bufio"
	"context"
	"flag"
	"github.com/cilium/ebpf/link"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf printk_pass.c -- -I../../headers -Ilb4.h

var (
	InterfaceName string
)

func init() {
	flag.StringVar(&InterfaceName, "n", "lo", "a network interface name")
}

func main() {
	flag.Parse()

	if len(InterfaceName) == 0 {
		log.Fatalf("Please specify a network interface")
	}
	// Look up the network interface by name.
	iface, err := net.InterfaceByName(InterfaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", InterfaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs\n")

	// Wait for a signal and close the XDP program,
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	cxt, cancel := context.WithCancel(context.Background())
	go func(cxt context.Context) {
		f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
		if err != nil {
			log.Panicf("open file failed, %v", err)
		}
		defer f.Close()

		r := bufio.NewReader(f)
		for {
			select {
			case <-cxt.Done():
				return
			default:
				// ReadLine is a low-level line-reading primitive.
				// Most callers should use ReadBytes('\n') or ReadString('\n') instead or use a Scanner.
				bytes, _, err := r.ReadLine()
				if err == io.EOF {
					break
				}
				if err != nil {
					panic(err)
				}
				log.Println(string(bytes))
			}
		}
	}(cxt)

	<-stopper
	cancel()
	log.Println("Received signal, exiting XDP program..")
}
