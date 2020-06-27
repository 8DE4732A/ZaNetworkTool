package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:\n -conn <interface> <username> <password> \n -interface")
	} else {
		if os.Args[1] == "-conn" {
			if len(os.Args) < 5 {
				fmt.Println("Usage:\n -conn <interface> <username> <password>")
				return
			} else {
				authentication(os.Args[2])
			}

		} else if os.Args[1] == "-interface" {
			fmt.Println(dev())
			return
		}
	}

}

func dev() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	result := make([]string, 0, 0)
	for _, intf := range ifaces {
		result = append(result, intf.Name)
	}
	return result
}

func authentication(dev string) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		panic(err)
	}
	fmt.Println("hardware addr:", iface.HardwareAddr)

	filterStr := fmt.Sprintf(
		"(ether proto 0x888e) and (ether dst host %s)", iface.HardwareAddr)
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filterStr)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	stop := make(chan int)
	go readEap(handle, stop)
	defer close(stop)

	for {
		select {
		case _ = <-stop:
			return
		default:
			broadcast(handle, iface)
		}
	}

}

func readEap(handle *pcap.Handle, stop chan int) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			eapLayer := packet.Layer(layers.LayerTypeEAP)
			if eapLayer == nil {
				continue
			}
			eap := eapLayer.(*layers.EAP)
			fmt.Println("eap data: ", eap)

			switch eap.Code {
			case layers.EAPCodeRequest:
				switch eap.Type {
				case layers.EAPTypeIdentity:
					break
				case 0x66:
					break
				default:
					break
				}
				break
			case layers.EAPCodeSuccess:
				stop <- 1
				fmt.Println("epa success")
				break
			case layers.EAPCodeFailure:
				fmt.Println("eap failure")
				break
			default:
				break
			}
		}
	}
}

func broadcast(handle *pcap.Handle, iface *net.Interface) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: 0x888e,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
		Length:  0x00,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eapol)
	fmt.Println("broadcast ")
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func sendUserName(handle *pcap.Handle, iface *net.Interface, username string) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: 0x888e,
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       0x1,
		Length:   uint16(len([]byte(username))),
		Type:     layers.EAPTypeIdentity,
		TypeData: []byte(username),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eap)
	fmt.Println("send username ", username)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil

}

func sendAuth(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	return nil
}
