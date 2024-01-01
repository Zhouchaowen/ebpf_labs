// This program demonstrates attaching an eBPF program to
// a cgroupv2 path and using sockops to process TCP socket events.

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type sock_key bpf socket_to_socket.c -- -I../../headers

const MapsPinpath = "/sys/fs/bpf/"

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Find the path to a cgroup enabled to version 2
	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	var options ebpf.CollectionOptions
	options.Maps.PinPath = MapsPinpath

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &options); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockOpsMap.FD(),
		Program: objs.BpfRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.SockOpsMap.FD(),
			Program: objs.BpfRedir,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		if err != nil {
			log.Fatalf("error detaching '%s'\n", err)
		}

		log.Fatal("closing redirect prog...\n")
	}()

	// Attach ebpf program to a cgroupv2
	linkSockOps, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.BpfSockmap,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer linkSockOps.Close()

	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs\n")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"Family",
	)
	go func() {
		//var value int
		for range ticker.C {
			var key bpfSockKey
			data, err := objs.SockOpsMap.NextKeyBytes(key)
			for len(data) != 0 && err == nil {
				if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &key); err != nil {
					log.Printf("parsing data: %s", err)
				}
				log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
					intToIP(key.Sip),
					intToPort(key.Sport),
					intToIP(key.Dip),
					intToPort(key.Dport),
					key.Family,
				)
				data, err = objs.SockOpsMap.NextKeyBytes(key)
			}

			if err != nil {
				log.Printf("Empty hash shouldn't return an error:%+v", err)
			} else if key.Sip != 0 {
				log.Printf("")
			}
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Wait
	<-stopper

	if err := objs.SockOpsMap.Unpin(); err != nil {
		log.Printf("Unpin map error:%+v", err)
	}
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// intToPort converts number to Port
func intToPort(PortNum uint32) uint32 {
	var port = make([]byte, 4)
	binary.LittleEndian.PutUint32(port, PortNum)
	return binary.BigEndian.Uint32(port)
}
