package main

import (
	"flag"
	"fmt"
	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf parse_udp_dns_af_xdp.c -- -I../../headers

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

	program := &xdp.Program{Program: objs.XdpSockProg, Queues: objs.QidconfMap, Sockets: objs.XsksMap}
	defer program.Close()
	if err := program.Attach(iface.Index); err != nil {
		log.Fatalf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer program.Detach(iface.Index)

	var queueID int
	xsk, err := xdp.NewSocket(iface.Index, queueID, &xdp.SocketOptions{
		NumFrames:              204800,
		FrameSize:              4096,
		FillRingNumDescs:       8192,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         8192,
		TxRingNumDescs:         64,
	})
	if err != nil {
		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
		return
	}

	// Register our XDP socket file descriptor with the eBPF program so it can be redirected packets
	if err := program.Register(queueID, xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer program.Unregister(queueID)

	go udpProcess()
	go sendResponse(xsk)
	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-stopper
		program.Detach(iface.Index)
		log.Println("Received signal, exiting XDP program..")
		os.Exit(1)
	}()

	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n))
		}
		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		// log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)
			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				pktData := xsk.GetFrame(rxDescs[i])
				limits <- pktData
			}
		}
	}
}

var limits = make(chan []byte)
var count int

func udpProcess() {
	for pktData := range limits {
		if len(pktData) < 37 {
			log.Println("pkt data ignore")
			continue
		}
		fmt.Printf("array %+v\n", pktData)
		eth := &layers.Ethernet{}
		ipv4 := &layers.IPv4{}
		stack := []gopacket.DecodingLayer{eth, ipv4}
		nf := gopacket.NilDecodeFeedback
		data := pktData
		for _, d := range stack {
			_ = d.DecodeFromBytes(data, nf)
			data = d.LayerPayload()
		}

		fmt.Printf("[ETH]       SrcMAC: %s\n", eth.SrcMAC)
		fmt.Printf("[ETH]       DstMAC: %s\n", eth.DstMAC)
		fmt.Printf("[ETH] EthernetType: %s\n", eth.EthernetType)
		fmt.Printf("[IPV4]     Version: %d\n", ipv4.Version)
		fmt.Printf("[IPV4]         IHL: %d\n", ipv4.IHL)
		fmt.Printf("[IPV4]      Length: %d\n", ipv4.Length)
		fmt.Printf("[IPV4]         TOS: %d\n", ipv4.TOS)
		fmt.Printf("[IPV4]    Protocol: %s\n", ipv4.Protocol)
		fmt.Printf("[IPV4]    Checksum: %d\n", ipv4.Checksum)
		fmt.Printf("[IPV4]       SrcIP: %s\n", ipv4.SrcIP)
		fmt.Printf("[IPV4]       DstIP: %s\n", ipv4.DstIP)

		if ipv4.Protocol != layers.IPProtocolUDP {
			continue
		}
		udp := &layers.UDP{}
		stack = []gopacket.DecodingLayer{udp}
		for _, d := range stack {
			_ = d.DecodeFromBytes(data, nf)
			data = d.LayerPayload()
		}
		fmt.Printf("[UDP]      SrcPort: %d\n", udp.SrcPort)
		fmt.Printf("[UDP]      DstPort: %d\n", udp.DstPort)
		fmt.Printf("[UDP]       Length: %d\n", udp.Length)
		fmt.Printf("[UDP]     Checksum: %d\n", udp.Checksum)

		if udp.DstPort != 53 {
			continue
		}
		dns := &layers.DNS{}
		stack = []gopacket.DecodingLayer{dns}
		for _, d := range stack {
			_ = d.DecodeFromBytes(data, nf)
			data = d.LayerPayload()
		}
		fmt.Printf("[DNS]           ID: %d\n", dns.ID)
		fmt.Printf("[DNS]           QR: %t\n", dns.QR)
		fmt.Printf("[DNS]       OpCode: %s\n", dns.OpCode)
		fmt.Printf("[DNS]           AA: %t\n", dns.AA)
		fmt.Printf("[DNS]           TC: %t\n", dns.TC)
		fmt.Printf("[DNS]           RD: %t\n", dns.RD)
		fmt.Printf("[DNS]           RA: %t\n", dns.RA)
		fmt.Printf("[DNS]            Z: %d\n", dns.Z)
		fmt.Printf("[DNS] ResponseCode: %d\n", dns.ResponseCode)
		fmt.Printf("[DNS]      QDCount: %d\n", dns.QDCount)
		fmt.Printf("[DNS]      ANCount: %d\n", dns.ANCount)
		fmt.Printf("[DNS]      NSCount: %d\n", dns.NSCount)
		fmt.Printf("[DNS]      ARCount: %d\n", dns.ARCount)
		for _, v := range dns.Questions {
			fmt.Printf("[DNS]   Quest Name: %s\n", v.Name)
			fmt.Printf("[DNS]   Quest Type: %s\n", v.Type)
			fmt.Printf("[DNS]  Quest Class: %s\n", v.Class)
		}
		pck := Package{
			eth:  eth,
			ipv4: ipv4,
			udp:  udp,
			dns:  dns,
		}
		packages <- pck
	}
}

type Package struct {
	eth  *layers.Ethernet
	ipv4 *layers.IPv4
	udp  *layers.UDP
	dns  *layers.DNS
}

var packages = make(chan Package, 10)

func sendResponse(xsk *xdp.Socket) {
	for {
		select {
		case p := <-packages:
			eth := p.eth
			ethTmp := eth.SrcMAC
			eth.SrcMAC = ethTmp
			eth.DstMAC = eth.SrcMAC

			ip := p.ipv4
			ipTmp := ip.SrcIP
			ip.SrcIP = ip.DstIP
			ip.DstIP = ipTmp

			udp := p.udp
			udpTmp := udp.SrcPort
			udp.SrcPort = udp.DstPort
			udp.DstPort = udpTmp
			udp.SetNetworkLayerForChecksum(ip)

			dns := p.dns
			dns.QR = true
			dns.RA = true
			dns.ANCount = 1
			dns.Answers = []layers.DNSResourceRecord{
				{
					Name:  dns.Questions[0].Name,
					Type:  dns.Questions[0].Type,
					Class: dns.Questions[0].Class,
					TTL:   300,
					IP:    net.ParseIP("10.2.0.105"),
				},
			}
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns)
			if err != nil {
				panic(err)
			}

			frameLen := len(buf.Bytes())
			fmt.Printf("response buf: %+v\n", buf)
			// Fill all the frames in UMEM with the pre-generated DNS query frame.

			descs := xsk.GetDescs(math.MaxInt32)
			for i := range descs {
				frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
				break
			}

			descstmp := xsk.GetDescs(xsk.NumFreeTxSlots())
			for i := range descstmp {
				descstmp[i].Len = uint32(frameLen)
			}
			xsk.Transmit(descstmp)

			_, _, err = xsk.Poll(1)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Response DNS queries from %v (%v) to %v (%v) for domain name\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC)
		}
	}
}
