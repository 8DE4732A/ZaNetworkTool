package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
)

var iface = flag.String("i", "\\Device\\NPF_{540078E3-B5F2-4E7A-9D21-EE154E21E2E8}", "Interface to read packets from")

func main() {
	flag.Parse()
	filterStr := fmt.Sprintf("(ether proto 0x888e)")
	fmt.Println(*iface)
	handle, err := pcap.OpenLive(*iface, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filterStr)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	var userName, passWord []byte
	for userName == nil || passWord == nil {
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			panic(err)
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if eapLayer := packet.Layer(layers.LayerTypeEAP); eapLayer != nil {
			eap := eapLayer.(*layers.EAP)
			switch eap.Code {
			case layers.EAPCodeResponse:
				switch eap.Type {
				case layers.EAPTypeIdentity:
					userName = eap.TypeData
					fmt.Printf("%s", string(userName))
				case 0x66:
					passWord = eap.TypeData
					fmt.Println()
					fmt.Printf("%x", passWord)
				default:
					fmt.Println("unknown eap type:", eap.Type)
				}
			case layers.EAPCodeSuccess:
			case layers.EAPCodeFailure:
				return
			default:
				fmt.Println("unknown epa code:", eap.Code)
			}
		}
	}

	userName = append(userName, 0xff)
	userName = append(userName, passWord...)
	e := ioutil.WriteFile("password.bin", userName, 0644)
	if e != nil {
		panic(e)
	}
}
