/*
senddnsqueries pre-generates a frame with a DNS query and starts sending it in
and endless loop to given destination as fast as possible.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// ...
var (
	NIC        string
	QueueID    int
	SrcMAC     string
	DstMAC     string
	SrcIP      string
	DstIP      string
	DomainName string
)

func main() {
	flag.StringVar(&NIC, "interface", "ens160", "Network interface to attach to.")
	flag.IntVar(&QueueID, "queue", 0, "The queue on the network interface to attach to.")
	flag.StringVar(&SrcMAC, "srcmac", "0050568d6a0b", "Source MAC address to use in sent frames.")
	flag.StringVar(&DstMAC, "dstmac", "0050568d1d20", "Destination MAC address to use in sent frames.")
	flag.StringVar(&SrcIP, "srcip", "10.2.0.108", "Source IP address to use in sent frames.")
	flag.StringVar(&DstIP, "dstip", "10.2.0.105", "Destination IP address to use in sent frames.")
	flag.StringVar(&DomainName, "domain", "qq.com", "Domain name to use in the DNS query.")
	flag.Parse()

	fmt.Printf("SrcIP:%s SrcMAC:%s DstIP:%s DstMAC:%s DomainName:%s\n", SrcIP, SrcMAC, DstIP, DstMAC, DomainName)

	// Initialize the XDP socket.
	iface, err := net.InterfaceByName(NIC)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", NIC, err)
	}

	xsk, err := xdp.NewSocket(iface.Index, QueueID, nil)
	if err != nil {
		panic(err)
	}

	// Pre-generate a frame containing a DNS query.

	srcMAC, _ := hex.DecodeString(SrcMAC)
	dstMAC, _ := hex.DecodeString(DstMAC)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC),
		DstMAC:       net.HardwareAddr(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(SrcIP).To4(),
		DstIP:    net.ParseIP(DstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: 1234,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(DomainName), dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		panic(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	frameLen := len(buf.Bytes())
	fmt.Printf("buf: %+v\n", buf)
	// Fill all the frames in UMEM with the pre-generated DNS query frame.

	descs := xsk.GetDescs(math.MaxInt32)
	for i := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
	}

	// Start sending the pre-generated frame as quickly as possible in an
	// endless loop printing statistics of the number of sent frames and
	// the number of sent bytes every second.

	fmt.Printf("sending DNS queries from %v (%v) to %v (%v) for domain name %s...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC, DomainName)

	go func() {
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		var numPkts uint64
		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1) * time.Second)
			cur, err = xsk.Stats()
			if err != nil {
				panic(err)
			}
			numPkts = cur.Completed - prev.Completed
			fmt.Printf("%d packets/s (%d bytes/s)\n", numPkts, numPkts*uint64(frameLen))
			prev = cur
		}
	}()

	descstmp := xsk.GetDescs(xsk.NumFreeTxSlots())
	for i := range descstmp {
		descstmp[i].Len = uint32(frameLen)
	}
	xsk.Transmit(descstmp)

	_, _, err = xsk.Poll(1)
	if err != nil {
		panic(err)
	}
}

/*
array [0 80 86 141 29 32 0 80 86 141 106 11 8 0 69 0 0 52 0 0 0 0 64 17 101 225 10 2 0 108 10 2 0 105 4 210 0 53 0 32 232 160 184 70 1 0 0 1 0 0 0 0 0 0 2 113 113 3 99 111 109 0 0 1 0 1]
2023/04/26 09:30:23 [dns] src_ip: 10.2.0.108
[dns] src_port: 1234
[dns] dst_ip: 10.2.0.105
[dns] dst_port: 53
[dns] udp_len: 32
[dns] udp_csum: 59552
[dns] transaction_id 47174
[dns] flag 256
[dns] q_count 1
[dns] ans_count 0
[dns] auth_count 0
[dns] add_count 0
[dns] domain qq.com

buf: &{data:[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 80 86 141 29 32 0 80 86 141 106 11 8 0 69 0 0 52 0 0 0 0 64 17 101 225 10 2 0 108 10 2 0 105 4 210 0 53 0 32 232 160 184 70 1 0 0 1 0 0 0 0 0 0 2 113 113 3 99 111 109 0 0 1 0 1] start:30 prepended:96 appended:0 layers:[2 45 20 17]}
*/

////////////////////////////////////////////////////////////																			   eth [0 80 86 141 29 32 0 80 86 141 106 11 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
////////////////////////////////////////////////////////////						 ip  [69 0 0 80 0 0 0 0 64 17 101 197 10 2 0 108 10 2 0 105 0 80 86 141 29 32 0 80 86 141 106 11 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
//////////////////////////////////////////////////////////// udp [4 210 0 53 0 88 168 120 69 0 0 80 0 0 0 0 64 17 101 197 10 2 0 108 10 2 0 105 0 80 86 141 29 32 0 80 86 141 106 11 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// msg [0 38 1 0 0 1 0 0 0 0 0 0 2 113 113 3 99 111 109 0 0 1 0 1 4 210 0 53 0 88 168 120 69 0 0 80 0 0 0 0 64 17 101 197 10 2 0 108 10 2 0 105 0 80 86 141 29 32 0 80 86 141 106 11 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]

// ebpf [0 80 86 141 29 32 0 80 86 141 106 11 8 0 69 0 0 52 0 0 0 0 64 17 101 225 10 2 0 108 10 2 0 105 4 210 0 53 0 32 232 160 184 70 1 0 0 1 0 0 0 0 0 0 2 113 113 3 99 111 109 0 0 1 0 1]
// send [0 80 86 141 29 32 0 80 86 141 106 11 8 0 69 0 0 52 0 0 0 0 64 17 101 225 10 2 0 108 10 2 0 105 4 210 0 53 0 32 232 160 184 70 1 0 0 1 0 0 0 0 0 0 2 113 113 3 99 111 109 0 0 1 0 1]
//       0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0  填充
