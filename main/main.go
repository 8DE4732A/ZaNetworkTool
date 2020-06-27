package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"sync"
	"time"
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
				authentication(os.Args[2], os.Args[3], os.Args[4])
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

func authentication(dev string, username string, passwd string) {
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
	go readEap(handle, iface, stop, username, passwd)
	defer close(stop)

exter:
	for {
		select {
		case _ = <-stop:
			break exter
		default:
			broadcast(handle, iface)
			time.Sleep(5 * time.Second)
		}
	}
	fmt.Println("wait forever!")
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func readEap(handle *pcap.Handle, iface *net.Interface, stop chan int, username string, passwd string) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				return
			}
			eth := ethLayer.(*layers.Ethernet)
			srcMac := eth.SrcMAC

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
					sendUserName(handle, iface, srcMac, eap.Id, username)
					break
				case 0x66:
					sendPasswd(handle, iface, srcMac, eap.Id, username)
					break
				default:
					fmt.Println("unknown eap type:", eap.Type)
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
				fmt.Println("unknown epa code:", eap.Code)
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

func sendUserName(handle *pcap.Handle, iface *net.Interface, srcMac net.HardwareAddr, id uint8, username string) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       srcMac,
		EthernetType: 0x888e,
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
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

func sendPasswd(handle *pcap.Handle, iface *net.Interface, destMac net.HardwareAddr, id uint8, passwd string) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       destMac,
		EthernetType: 0x888e,
	}
	passwdByte := []byte{
		0x10, 0x96, 0x8e, 0xb4, 0x94, 0x7a,
		0x9a, 0xc2, 0x04, 0x66, 0x6f, 0xaf, 0x57, 0x1a,
		0x6c, 0x3e, 0xd0, 0x79, 0x6c, 0x69, 0x75, 0x70,
		0x69, 0x6e, 0x67, 0x2f, 0x5a, 0x41, 0x4f, 0x4e,
		0x4c, 0x49, 0x4e, 0x45, 0x2e, 0x43, 0x4f, 0x4d,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x41, 0x34, 0x52, 0x54,
		0x39, 0x44, 0x54, 0x47, 0x48, 0x4d, 0x52, 0x4d,
		0x54, 0x55, 0x5a, 0x42, 0x54, 0x51, 0x56, 0x5a,
		0x57, 0x34, 0x42, 0x52, 0x56, 0x57, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x4c, 0x53, 0x37, 0x51,
		0x45, 0x59, 0x56, 0x54}

	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
		Length:   uint16(len(passwdByte)),
		Type:     layers.EAPTypeIdentity,
		TypeData: passwdByte,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eap)
	fmt.Println("send passwrod ", passwd)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
