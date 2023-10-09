package main

import (
	"encoding/json"
	"flag"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type net_packet_event bpf tc_filter.c -- -I../../headers

var f = &Flags{}

func init() {
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringVar(&f.FilterInterface, "filter-if", "", "filter net interface")
	flag.StringVar(&f.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp)")
	flag.StringVar(&f.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	flag.StringVar(&f.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	Uint16Var(&f.FilterSrcPort, "filter-src-port", 0, "filter source port")
	Uint16Var(&f.FilterDstPort, "filter-dst-port", 0, "filter destination port")
	Uint16Var(&f.FilterPort, "filter-port", 0, "filter either destination or source port")
	flag.BoolVar(&f.DropPackage, "drop-skb", false, "drop filtered skb")
}

func main() {
	flag.Parse()

	fBytes, _ := json.MarshalIndent(f, "", "\t")
	log.Printf("\n%s\n", string(fBytes))

	// 获取所有网卡信息
	neti := NewNetInterface()
	neti.LoadIfInterface()
	for k, v := range neti.interfaces {
		log.Printf("interface key:%+v,value:+%v", k, v)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 获取主机信息
	uname, _ := GetOSUnamer()
	unameBytes, _ := json.MarshalIndent(uname, "", "\t")
	log.Printf("\n%s\n", string(unameBytes))

	log.Printf("TC-Filter Start...")
	log.Printf("Process PID: %d", os.Getpid())

	o := NewOutput(neti)
	p := NewTcProbe(neti, o)

	p.Start(f)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	p.Stop()

	log.Println("Received signal, exiting program..")
}
