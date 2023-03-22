package main

import (
	"flag"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf packets_record.c -- -I../headers

var (
	InterfaceName string
	Option        string
)

func init() {
	flag.StringVar(&InterfaceName, "n", "lo", "a network interface name")
	flag.StringVar(&Option, "o", "xdp_pass", "xdp option xdp_pass|xdp_drop|xdp_abort")
}

func main() {
	flag.Parse()

	if len(InterfaceName) == 0 || len(Option) == 0 {
		log.Fatalf("Please specify a network interface and xdp option")
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

	// Choose differently xdp option
	var xdpFunc *ebpf.Program
	var OptionKey uint32

	switch Option {
	case "xdp_pass":
		xdpFunc = objs.XdpPassFunc
		OptionKey = 2
	case "xdp_drop":
		xdpFunc = objs.XdpDropFunc
		OptionKey = 1
	case "xdp_abort":
		xdpFunc = objs.XdpAbortFunc
		OptionKey = 0
	default:
		log.Fatalf("xdp option error, only support xdp_pass|xdp_drop|xdp_abort")
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	log.Println("Waiting for events..")
	for range ticker.C {
		var dataRecs []bpfDataRec
		if err := objs.XdpStatsMap.Lookup(OptionKey, &dataRecs); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		var rxPackets uint64
		var rxBytes uint64

		for _, v := range dataRecs {
			rxPackets += v.RxPackets
			rxBytes += v.RxBytes
		}

		log.Printf("Option %s CUP CORE %d RxPackets %d RxBytes %d\n", Option, len(dataRecs), rxPackets, rxBytes)
	}
}
