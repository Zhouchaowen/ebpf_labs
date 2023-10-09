package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tc_statistics.c --type pair --type stats -- -I../../headers

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

	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		log.Fatalf("create net link failed: %v", err)
	}

	inf, err := attachTC(link, objs.TrackTx, "tc", netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatalf("attach tc ingress failed, %v", err)
	}
	defer netlink.FilterDel(inf)

	log.Printf("Attached TC program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Printf("Waiting for events..")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key bpfPair
		var value bpfStats
		var entries = objs.bpfMaps.Trackers.Iterate()
		for entries.Next(&key, &value) {
			log.Printf("src_ip: %+v, des_ip: %+v, cnt: %+v, bytes: %+v\n",
				intToIP(key.Lip), intToIP(key.Rip),
				value.TxCnt, value.TxBytes)
		}

		if err := entries.Err(); err != nil {
			panic(fmt.Sprint("Iterator encountered an error:", err))
		}
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// 替换 Qdisc 队列
func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

// 加载 TC 程序
func attachTC(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) (*netlink.BpfFilter, error) {
	if err := replaceQdisc(link); err != nil {
		return nil, fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("replacing tc filter: %w", err)
	}

	return filter, nil
}
