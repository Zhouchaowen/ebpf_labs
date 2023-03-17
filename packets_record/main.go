package main

import (
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"os"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf packets_record.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPassFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	type DataRec struct {
		RxPackets uint64
		RxBytes   uint64
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	log.Println("Waiting for events..")
	for range ticker.C {
		var dataRecs []DataRec
		if err := objs.XdpStatsMap.Lookup(uint32(2), &dataRecs); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		var rxPackets uint64
		var rxBytes uint64

		for _, v := range dataRecs {
			rxPackets += v.RxPackets
			rxBytes += v.RxBytes
		}

		log.Printf("CUP CORE %d RxPackets %d RxBytes %d\n", len(dataRecs), rxPackets, rxBytes)
	}
}
