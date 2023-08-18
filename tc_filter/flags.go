package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// 设置flag获取uint16类型数据
type uint16Value uint16

func newUint16Value(val uint16, p *uint16) *uint16Value {
	*p = val
	return (*uint16Value)(p)
}

func Uint16Var(p *uint16, name string, value uint16, usage string) {
	flag.Var(newUint16Value(value, p), name, usage)
}

func (i *uint16Value) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 16)
	*i = uint16Value(v)
	return err
}

func (i *uint16Value) Get() any { return uint16(*i) }

func (i *uint16Value) String() string { return strconv.FormatUint(uint64(*i), 10) }

type Flags struct {
	KernelBTF string

	FilterInterface string
	FilterProto     string
	FilterSrcIP     string
	FilterDstIP     string
	FilterSrcPort   uint16
	FilterDstPort   uint16
	FilterPort      uint16

	DropPackage bool
}

type FilterConfig struct {
	// Filter l3
	FilterSrcIP [4]byte
	FilterDstIP [4]byte

	// Filter l4
	FilterProto   uint8
	FilterSrcPort uint16
	FilterDstPort uint16
	FilterPort    uint16

	IsDrop byte
}

// GetConfig 设置 BPF常量CFG 配置
func GetConfig(flags *Flags) FilterConfig {
	cfg := FilterConfig{}

	// 源端口与目录端口
	if flags.FilterPort > 0 {
		cfg.FilterPort = flags.FilterPort
	} else {
		if flags.FilterSrcPort > 0 {
			cfg.FilterSrcPort = flags.FilterSrcPort
		}
		if flags.FilterDstPort > 0 {
			cfg.FilterDstPort = flags.FilterDstPort
		}
	}

	// 协议
	switch strings.ToLower(flags.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	}

	// 源ip
	if flags.FilterSrcIP != "" {
		ip := net.ParseIP(flags.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}
		copy(cfg.FilterSrcIP[:], ip.To4()[:])
	}

	// 目的ip
	if flags.FilterDstIP != "" {
		ip := net.ParseIP(flags.FilterDstIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-dst-ip")
		}
		copy(cfg.FilterDstIP[:], ip.To4()[:])
	}

	// 是否Drop
	if flags.DropPackage {
		cfg.IsDrop = 1
	}

	return cfg
}
