package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

	mu := http.NewServeMux()
	mu.Handle("/add", AddIPV4Handler(objs))

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

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
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

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Listening and serving HTTP on %s:%d", Ip, Port)
	log.Printf("Press Ctrl-C to exit and remove the program")
	log.Println("Waiting for events..")

	type bpfEvent struct {
		// ipv4——firewall.c event.protocol定义为u8但是由于golang内存对齐导致读取错位, 所以必须要补齐位数 uint32
		Protocol       uint8 `json:"protocol"`
		Flag           uint8 `json:"flag"` // 流量是否拦截   0未拦截 1 已拦截
		_              [2]uint8
		SAddr          uint32 `json:"s_addr"`
		DAddr          uint32 `json:"d_addr"`
		IngressIfIndex uint32 `json:"ingress_if_index"`
	}

	var event bpfEvent
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

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("protocol %s s_addr %s d_addr %s flag %d\n",
			IPProtocolMap[IPProtocol(event.Protocol)], uint32ToIp(event.SAddr), uint32ToIp(event.DAddr), event.Flag)
	}

	<-stopper

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Println("server shutdown failed")
	}
}

func AddIPV4Handler(objs bpfObjects) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
}

func uint32ToIp(ipValue uint32) string {
	ipValue = (ipValue&0xff)<<24 | (ipValue&0xff00)<<8 |
		(ipValue&0xff0000)>>8 | (ipValue&0xff000000)>>24

	// 将 uint32 值按照大端字节序拆分成 4 个字节
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ipValue >> 24)
	ipBytes[1] = byte(ipValue >> 16)
	ipBytes[2] = byte(ipValue >> 8)
	ipBytes[3] = byte(ipValue)

	// 将字节序列转换为 IP 地址
	ip := net.IP(ipBytes)
	return ip.String()
}
