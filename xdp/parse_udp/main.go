package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"net"
	"os"
	"os/signal"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf parse_udp.c -- -I../../headers

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
		Program:   objs.ParseUdpFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Rb)
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

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Println("Waiting for events..")

	type bpfEvent struct {
		// ipv4——firewall.c event.protocol定义为u8但是由于golang内存对齐导致读取错位, 所以必须要补齐位数 uint32
		Protocol uint8 `json:"protocol"`
		_        [3]uint8
		SAddr    uint32 `json:"s_addr"`
		DAddr    uint32 `json:"d_addr"`
		Source   uint16 `json:"source"`
		Dest     uint16 `json:"dest"`
		Len      uint16 `json:"len"`
		Check    uint16 `json:"check"`
	}

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s\n", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("protocol %s s_addr %s:%d d_addr %s:%d data_len %d chcek %d\n",
			IPProtocolMap[IPProtocol(event.Protocol)],
			uint32ToIp(event.SAddr), event.Source,
			uint32ToIp(event.DAddr), event.Dest,
			event.Len, event.Check)
	}

	<-stopper
	log.Println("Received signal, exiting XDP program..")
}

func uint32ToIp(ipValue uint32) string {
	ipValue = (ipValue&0xff)<<24 | (ipValue&0xff00)<<8 |
		(ipValue&0xff0000)>>8 | (ipValue&0xff000000)>>24

	// 将 uint32 值按照大端字节序拆分成 4 个字节
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ipValue >> 24)
	ipBytes[1] = byte(ipValue >> 16)
	ipBytes[2] = byte(ipValue >> 8)
	ipBytes[3] = byte(ipValue)

	// 将字节序列转换为 IP 地址
	ip := net.IP(ipBytes)
	return ip.String()
}
