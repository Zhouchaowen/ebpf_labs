package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
)

const absoluteTS string = "15:04:05.000"

type Output struct {
	tcType map[int]string
	neti   *NetInterface
}

func NewOutput(neti *NetInterface) *Output {
	o := &Output{}
	o.tcType = make(map[int]string)
	o.tcType[1] = "INGRESS"
	o.tcType[0] = "EGRESS"
	o.neti = neti
	return o
}

func (o *Output) PrintHeader() {
	fmt.Printf("%-16s %-16s %-10s %-16s %-10s %-10s %-16s %-6s -> %-16s %-6s\n",
		"Time",
		"Ifindex",
		"Protocol",
		"Flag",
		"Len",
		"Direction",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
	)
}

func (o *Output) Print(event bpfNetPacketEvent) {

	fmt.Printf("%-16s %-16s %-10s %-16s %-10d %-10s %-16s %-6d -> %-16s %-6d\n",
		time.Now().Format(absoluteTS),
		o.ifIndexToName(int(event.Ifindex)),
		protoToStr(event.Protocol),
		getFlagString(event),
		event.Len,
		o.tcType[int(event.Ingress)],
		intToIP(event.Sip),
		event.Sport,
		intToIP(event.Dip),
		event.Dport)
}

func (o *Output) ifIndexToName(ifIndex int) string {
	if i, ok := o.neti.interfaces[ifIndex]; ok {
		return i.name
	}
	return ""
}

func protoToStr(proto uint32) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	default:
		return ""
	}
}

func getFlagString(event bpfNetPacketEvent) string {
	fStr := ""
	if event.Syn == 1 {
		fStr += "SYN|"
	}
	if event.Ack == 1 {
		fStr += "ACK|"
	}
	if event.Psh == 1 {
		fStr += "PSH|"
	}
	if event.Rst == 1 {
		fStr += "RST|"
	}

	if event.Fin == 1 {
		fStr += "FIN|"
	}

	if strings.HasSuffix(fStr, "|") {
		return fStr[:strings.LastIndex(fStr, "|")]
	}
	return fStr
}
