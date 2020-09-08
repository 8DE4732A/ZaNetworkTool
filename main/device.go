package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
)

func main() {
	fmt.Println(dev())
	fmt.Println()
	fmt.Println(devPcap())
}

func dev() []net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return ifs
}

func devPcap() []pcap.Interface {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}
	return ifs
}
