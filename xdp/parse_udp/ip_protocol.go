package main

type IPProtocol uint8

const (
	IPProtocolICMP IPProtocol = 1
	IPProtocolTCP  IPProtocol = 6
	IPProtocolUDP  IPProtocol = 17
	IPProtocolIPv6 IPProtocol = 41
	IPProtocolGRE  IPProtocol = 47
)

var IPProtocolMap = map[IPProtocol]string{
	IPProtocolICMP: "icmp",
	IPProtocolTCP:  "tcp",
	IPProtocolUDP:  "udp",
	IPProtocolIPv6: "ipv6",
	IPProtocolGRE:  "gre",
}
