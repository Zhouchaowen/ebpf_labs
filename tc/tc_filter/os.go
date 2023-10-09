package main

import "golang.org/x/sys/unix"

type UnameInfo struct {
	SysName    string `json:"SysName"`
	Nodename   string `json:"Nodename"`
	Release    string `json:"Release"`
	Version    string `json:"Version"`
	Machine    string `json:"Machine"`
	Domainname string `json:"Domainname"`
}

func GetOSUnamer() (*UnameInfo, error) {
	u := unix.Utsname{}
	e := unix.Uname(&u)
	if e != nil {
		return nil, e
	}
	ui := UnameInfo{}
	ui.SysName = charsToString(u.Sysname)
	ui.Nodename = charsToString(u.Nodename)
	ui.Release = charsToString(u.Release)
	ui.Version = charsToString(u.Version)
	ui.Machine = charsToString(u.Machine)
	ui.Domainname = charsToString(u.Domainname)

	return &ui, nil
}

func charsToString(ca [65]byte) string {
	s := make([]byte, len(ca))
	var lens int
	for ; lens < len(ca); lens++ {
		if ca[lens] == 0 {
			break
		}
		s[lens] = uint8(ca[lens])
	}
	return string(s[0:lens])
}
