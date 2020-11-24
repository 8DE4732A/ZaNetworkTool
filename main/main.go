package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	interfaceName string
	localMac      string
)

func init() {
	flag.StringVar(&interfaceName, "interface", "", "interface name")
	flag.StringVar(&localMac, "mac", "", "mac address")
}

//https://github.com/google/gopacket/issues/456
func main() {
	flag.Parse()
	authentication(interfaceName, localMac)

}

func authentication(interfaceName string, localMac string) {

	filterStr := fmt.Sprintf(
		"(ether proto 0x888e) and (ether dst host %s)", localMac)
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filterStr)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	hwAddr, err := net.ParseMAC(localMac)
	if err != nil {
		panic(err)
	}

	data, err := ioutil.ReadFile("password.bin")
	if err != nil {
		panic(err)
	}
	var index int
	for i, v := range data {
		if v == byte(0xff) {
			index = i
		}
	}
	username := string(data[0:index])
	passwd := data[index+1:]

	stop := make(chan int)
	defer close(stop)
	time.Sleep(3000)

	go broadcast(handle, hwAddr, stop)

	readEap(handle, hwAddr, stop, username, passwd)
}

func readEap(handle *pcap.Handle, localMac net.HardwareAddr, stop chan int, username string, password []byte) {
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
					sendUserName(handle, localMac, srcMac, eap.Id, username)
				case 0x66:
					sendPassword(handle, localMac, srcMac, eap.Id, password)
				default:
					fmt.Println("unknown eap type:", eap.Type)
				}
			case layers.EAPCodeSuccess:
				stop <- 1
				fmt.Println("epa success")
			case layers.EAPCodeFailure:
				fmt.Println("eap failure")
			default:
				fmt.Println("unknown epa code:", eap.Code)
			}
		}
	}
}

func broadcast(handle *pcap.Handle, localMac net.HardwareAddr, stop chan int) error {
	eth := layers.Ethernet{
		SrcMAC:       localMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: 0x888e,
	}
	eaPol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
		Length:  0x00,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eaPol)
	fmt.Println("broadcast %x", buf.Bytes)
	for {
		time.Sleep(time.Duration(3 * time.Second))
		select {
		case _ = <-stop:
			fmt.Println("success! stop boardcast")
			return nil
		default:
			if err := handle.WritePacketData(buf.Bytes()); err != nil {
				fmt.Println("send boardcast failed.", err)
			}
		}
	}
	return nil
}

func sendUserName(handle *pcap.Handle, srcMac net.HardwareAddr, destAddr net.HardwareAddr, id uint8, username string) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       destAddr,
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

func sendPassword(handle *pcap.Handle, srcMac net.HardwareAddr, destAddr net.HardwareAddr, id uint8, password []byte) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       destAddr,
		EthernetType: 0x888e,
	}

	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
		Length:   uint16(len(password)),
		Type:     layers.EAPTypeIdentity,
		TypeData: password,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eap)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
