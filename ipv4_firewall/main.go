package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ipv4_firewall.c -- -I../headers

var (
	InterfaceName string
	Ip            string
	Port          int
)

func init() {
	flag.StringVar(&InterfaceName, "n", "lo", "a network interface name")
	flag.StringVar(&Ip, "i", "0.0.0.0", "server ip")
	flag.IntVar(&Port, "p", 8080, "server port")
}

func printHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
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
		Program:   objs.Ipv4FirewallFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	mu := http.NewServeMux()
	mu.HandleFunc("/add", func(w http.ResponseWriter, req *http.Request) {
		ipAddr := req.URL.Query().Get("ip")
		interceptStr := req.URL.Query().Get("inter")

		intercept, err := strconv.ParseInt(interceptStr, 10, 10)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]string{
			"add_ip": ipAddr,
			"msg":    "success",
		}

		jsonBytes, err := json.Marshal(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		ip := net.ParseIP(ipAddr).To4()
		if ip == nil {
			log.Printf("ip addrs %s format error \n", ipAddr)
			jsonBytes, _ := json.Marshal(map[string]string{
				"msg": ipAddr + " ip format error",
			})
			w.Write(jsonBytes)
			return
		}

		// []byte 类型转换为uint32
		ipUint32 := binary.LittleEndian.Uint32(ip)

		if intercept == 0 {
			err = objs.Rules.Delete(ipUint32)
			if err != nil {
				log.Printf("delete ip address map rules error %s \n", err)
				jsonBytes, _ := json.Marshal(map[string]string{
					"msg": fmt.Sprintf("add ip address %s to map rules error %s", ipAddr, err),
				})
				w.Write(jsonBytes)
				return
			}
		} else {
			err = objs.Rules.Put(ipUint32, uint8(intercept))
			if err != nil {
				log.Printf("add ip address map rules error %s \n", err)
				jsonBytes, _ := json.Marshal(map[string]string{
					"msg": fmt.Sprintf("add ip address %s to map rules error %s", ipAddr, err),
				})
				w.Write(jsonBytes)
				return
			}
		}

		var res uint8
		objs.Rules.Lookup(ipUint32, &res)
		log.Printf("add ip address %s, ip to uint32 value %d,is intercept %d", ipAddr, ipUint32, res)

		w.Write(jsonBytes)
		return
	})

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", Ip, Port),
		Handler: mu,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Println("server start failed")
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	<-stopper

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Println("server shutdown failed")
	}
}
