package main

import (
	"net"
)

type NetInterface struct {
	// interfaces atomic.Value
	interfaces map[int]NetInfo
}

type NetInfo struct {
	index int
	name  string
	ip    string
}

func NewNetInterface() *NetInterface {
	neti := &NetInterface{
		interfaces: make(map[int]NetInfo),
	}

	return neti
}

func (neti *NetInterface) LoadIfInterface() {

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // 忽略禁用的网卡
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // 忽略loopback回路接口
		}

		addrs, ierr := iface.Addrs()
		if ierr != nil {
			err = ierr
			return
		}

		for _, addr := range addrs {

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // 不是ipv4地址，放弃
			}

			n := NetInfo{
				index: iface.Index,
				name:  iface.Name,
				ip:    ip.String(),
			}
			neti.interfaces[n.index] = n
		}
	}

}
