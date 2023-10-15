// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
// https://mozillazg.com/2022/05/ebpf-libbpf-tracepoint-common-questions.html
// https://github.com/zq-david-wang/linux-tools/blob/main/ebpf/libbpf-bootstrap/conn.c
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type conn_event bpf connect_accept.c -- -I../../headers

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/tracing/events/syscalls/sys_enter_fchmodat
	kpEnterConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceEnterConnect, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpEnterConnect.Close()

	kpEnterAccept, err := link.Tracepoint("syscalls", "sys_enter_accept", objs.TraceEnterAccept, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpEnterAccept.Close()

	kpExitAccept, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceExitAccept, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpExitAccept.Close()

	kpEnterAccept4, err := link.Tracepoint("syscalls", "sys_enter_accept4", objs.TraceEnterAccept4, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpEnterAccept4.Close()

	kpExitAccept4, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceExitAccept4, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpExitAccept4.Close()

	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Println("Waiting for events..")
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Conns)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event bpfConnEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event error: %s", err)
			continue
		}

		if event.Addr[0] == 2 && event.Addr[1] == 0 {
			var sockAddr SockAddrIn
			// 解析二进制数据
			sockAddr.SinFamily = binary.LittleEndian.Uint16(event.Addr[0:2])
			sockAddr.SinPort = binary.BigEndian.Uint16(event.Addr[2:4])
			copy(sockAddr.SinAddr[:], event.Addr[4:8])

			// 将IP地址解析为字符串
			ip := net.IP(sockAddr.SinAddr[:])
			if event.Pid < 0 {
				log.Printf("accept connection from: %s:%d  Pid: %d\n", ip.String(), sockAddr.SinPort, event.Pid)
			} else {
				if sockAddr.SinPort > 0 {
					log.Printf("try to connect: %s:%d  Pid: %d\n", ip.String(), sockAddr.SinPort, event.Pid)
				} else {
					log.Printf("try to reach: %s:%d  Pid: %d\n", ip.String(), sockAddr.SinPort, event.Pid)
				}
			}
		} else if event.Addr[0] == 1 && event.Addr[1] == 0 {
			var sockAddr SockAddrIn6

			// 解析二进制数据
			sockAddr.Sin6Family = binary.BigEndian.Uint16(event.Addr[0:2])
			sockAddr.Sin6Port = binary.BigEndian.Uint16(event.Addr[2:4])
			sockAddr.Sin6FlowInfo = binary.BigEndian.Uint32(event.Addr[4:8])
			copy(sockAddr.Sin6Addr[:], event.Addr[8:24])

			// 将IPv6地址解析为字符串
			ip := net.IP(sockAddr.Sin6Addr[:])

			// 打印结果
			if event.Pid < 0 {
				log.Printf("accept connection from: %s:%d  Pid: %d\n", ip.String(), sockAddr.Sin6Port, event.Pid)
			} else {
				if sockAddr.Sin6Port > 0 {
					log.Printf("try to connect: %s:%d  Pid: %d\n", ip.String(), sockAddr.Sin6Port, event.Pid)
				} else {
					log.Printf("try to reach: %s:%d  Pid: %d\n", ip.String(), sockAddr.Sin6Port, event.Pid)
				}
			}
		}
	}
}

type SockAddrIn struct {
	SinFamily uint16  // Address family, AF_INET
	SinPort   uint16  // Port number (in network byte order)
	SinAddr   [4]byte // IPv4 address
	SinZero   [8]byte // Padding for structure size
}

type SockAddrIn6 struct {
	Sin6Family   uint16   // Address family, AF_INET6
	Sin6Port     uint16   // Port number (in network byte order)
	Sin6FlowInfo uint32   // IPv6 flow information
	Sin6Addr     [16]byte // IPv6 address
	Sin6ScopeId  uint32   // Scope ID
}
