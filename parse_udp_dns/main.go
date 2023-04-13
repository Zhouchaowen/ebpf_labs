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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf parse_udp_dns.c --type event -- -I../headers

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
		Program:   objs.ParseDnsFunc,
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
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs")
	log.Printf("Waiting for events..")

	type bpfEvent struct {
		Protocol      uint8      `json:"protocol"`
		Rd            uint8      `json:"rd"`
		Tc            uint8      `json:"tc"`
		Aa            uint8      `json:"aa"`
		Opcode        uint8      `json:"opcode"`
		Qr            uint8      `json:"qr"`
		RCode         uint8      `json:"r_code"`
		Cd            uint8      `json:"cd"`
		Ad            uint8      `json:"ad"`
		Z             uint8      `json:"z"`
		Ra            uint8      `json:"ra"`
		TransactionId uint16     `json:"transaction_id"`
		QCount        uint16     `json:"q_count"`
		AddCount      uint16     `json:"add_count"`
		QType         uint16     `json:"q_type"`
		QClass        uint16     `json:"q_class"`
		Source        uint16     `json:"source"`
		Dest          uint16     `json:"dest"`
		SAddr         uint32     `json:"s_addr"`
		DAddr         uint32     `json:"d_addr"`
		Name          [256]uint8 `json:"name"`
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

		log.Printf("protocol %d s_addr %s:%d d_addr %s:%d dns_id %d dns_query %s "+
			"dns_flags %d-%d-%d-%d-%d-%d-%d-%d-%d-%d "+
			"dns_qdcount %d dns_qtype %d dns_qclass %d\n",
			event.Protocol, uint32ToIp(event.SAddr), event.Source, uint32ToIp(event.DAddr), event.Dest,
			event.TransactionId, uint8ToDomain(event.Name),
			event.Rd, event.Tc, event.Aa, event.Opcode, event.Qr, event.RCode, event.Cd, event.Ad, event.Z, event.Ra,
			event.QCount, event.QType, event.QClass)
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

func uint8ToDomain(query [256]uint8) string {
	var domain bytes.Buffer
	for i, v := range query {
		if (v > 47 && v < 58) ||
			(v > 64 && v < 91) ||
			(v > 69 && v < 123) {
			domain.Write([]byte{v})
		} else if v == 0 && i != 0 { // 快速退出
			break
		} else {
			if i != 0 {
				domain.Write([]byte{'.'})
			}
		}
	}
	return domain.String()
}
