package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type dns_query -type a_record bpf dns_cache_server.c -- -I../headers

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
		Program:   objs.XdpDnsCacheFunc,
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
	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Listening and serving HTTP on %s:%d", Ip, Port)
	log.Printf("Press Ctrl-C to exit and remove the program")

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

type Record struct {
	// Rules Map Key
	RecordType string `json:"record_type"`
	Class      string `json:"class"`
	Name       string `json:"name"`

	// Rules Map Value
	IpAddr string `json:"ip_addr"`
	Ttl    uint32 `json:"ttl"`

	// 是否cache
	Status bool `json:"status"`
}

func (r *Record) String() string {
	return fmt.Sprintf("[Status %t RecordType %s Class %s"+
		" Name: %s Ip %s Ttl %d]", r.Status, r.RecordType, r.Class, r.Name, r.IpAddr, r.Ttl)
}

func (ar *bpfA_record) String() string {
	return fmt.Sprintf("[Ip %d Ttl %d]", ar.IpAddr, ar.Ttl)
}

func (dq *bpfDnsQuery) String() string {
	return fmt.Sprintf("[RecordType %d Class %d Name: %s]", dq.RecordType, dq.Class, int8sToDomain(dq.Name))
}

func AddIPV4Handler(objs bpfObjects) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var rc Record
		err = json.Unmarshal(buf, &rc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		var value bpfA_record
		var key bpfDnsQuery
		ip := net.ParseIP(rc.IpAddr).To4()
		if ip == nil {
			log.Printf("ip addrs %s format error \n", rc.IpAddr)
			jsonBytes, _ := json.Marshal(map[string]string{
				"msg": rc.IpAddr + " ip format error",
			})
			w.Write(jsonBytes)
			return
		}

		// []byte 类型转换为uint32
		ipUint32 := binary.LittleEndian.Uint32(ip)
		value.IpAddr = struct{ S_addr uint32 }{S_addr: ipUint32}
		value.Ttl = rc.Ttl
		key.RecordType = 1
		key.Class = 1
		key.Name = domainToInt8s(rc.Name)

		if rc.Status {
			err = objs.Rules.Put(key, value)
			if err != nil {
				log.Printf("add record %+v rules map error %s \n", rc, err)
				jsonBytes, _ := json.Marshal(map[string]string{
					"msg": fmt.Sprintf("add record %+v to map rules error %+v", rc, err),
				})
				w.Write(jsonBytes)
				return
			}
		} else {
			err = objs.Rules.Delete(key)
			if err != nil {
				log.Printf("delete rules map by key:%s error %s \n", key.String(), err)
				jsonBytes, _ := json.Marshal(map[string]string{
					"msg": fmt.Sprintf("delete record %+v from map rules error %s", rc, err),
				})
				w.Write(jsonBytes)
				return
			}
		}

		var ret bpfA_record
		objs.Rules.Lookup(key, &ret)
		log.Printf("cache %t key %s, value %s \n", rc.Status, key.String(), ret.String())

		w.Write(buf)
		return
	})
}

// 按协议封装域名 RFC1035 4.1.2
func domainToInt8s(name string) [256]int8 {
	var ret [256]int8
	var i int
	var cnt = 0

	for i = 0; i < len(name); i++ {
		if name[i] == 46 || name[i] == 0 {
			ret[i-cnt] = int8(cnt)
			if name[i] == 0 {
				cnt = i + 1
				break
			}
			cnt = -1
		}
		ret[i+1] = int8(name[i])

		cnt++
	}
	ret[i-cnt] = int8(cnt)
	return ret
}

// 按协议解析域名 RFC1035 4.1.2
func int8sToDomain(name [256]int8) string {
	var buf = make([]byte, 256)
	var i int
	var labelLen = name[0]

	for i = 1; i < len(name); i++ {
		if name[i] == 0 {
			buf[i-1] = 0
			break
		} else if labelLen == 0 {
			buf[i-1] = '.'
			labelLen = name[i]
		} else {
			buf[i-1] = byte(name[i])
			labelLen--
		}
	}
	return string(buf)
}
