package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tc_http.c -- -I../../headers

var (
	InterfaceName string
	Debug         bool
	Verbose       bool
)

func init() {
	flag.StringVar(&InterfaceName, "n", "lo", "a network interface name")
	flag.BoolVar(&Debug, "d", false, "output debug information")
	flag.BoolVar(&Verbose, "v", false, "output more detailed information")
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

	infIngress, err := attachTC(link, objs.IngressClsFunc, "classifier/ingress", netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatalf("attach tc ingress failed, %v", err)
	}
	defer netlink.FilterDel(infIngress)

	infEgress, err := attachTC(link, objs.EgressClsFunc, "classifier/egress", netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		log.Fatalf("attach tc egress failed, %v", err)
	}
	defer netlink.FilterDel(infEgress)

	log.Printf("Attached TC program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs\n")

	// Wait for a signal and close the XDP program,
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := perf.NewReader(objs.SkbEvents, os.Getpagesize()*1024*4)
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
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

	type perfHttpDataEvent struct {
		Type    uint32
		DataLen uint32
		payload []byte
	}

	ctx, cancel := context.WithCancel(context.Background())
	// mage http data
	saveChan := make(chan model, 100)
	go MageHttp(ctx, saveChan)

	go func() {
		for {
			select {
			case m := <-saveChan:
				fmt.Printf("%+v\n", m)
			case <-ctx.Done():
				return
			}
		}
	}()

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
		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		data := perfHttpDataEvent{}
		buf := bytes.NewBuffer(record.RawSample)
		if err = binary.Read(buf, binary.LittleEndian, &data.Type); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &data.DataLen); err != nil {
			return
		}
		tmpData := make([]byte, data.DataLen)
		if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
			return
		}
		fmt.Printf("data len:%d\n", data.DataLen)
		ParseHttp(tmpData)
	}

	<-stopper
	cancel()
	log.Println("Received signal, exiting TC program..")
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
