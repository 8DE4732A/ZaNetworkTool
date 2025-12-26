package mirror

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// EAPPacket contains parsed EAP packet information
type EAPPacket struct {
	SrcMAC   net.HardwareAddr
	DstMAC   net.HardwareAddr
	Code     layers.EAPCode
	Id       uint8
	Type     layers.EAPType
	TypeData []byte
	RawData  []byte // Original packet data for forwarding
}

// OpenInterface opens a network interface for packet capture
func OpenInterface(ifaceName string) (*pcap.Handle, error) {
	return pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
}

// SetEAPFilter sets BPF filter for EAP packets
func SetEAPFilter(handle *pcap.Handle, macFilter string) error {
	filterStr := "(ether proto 0x888e)"
	if macFilter != "" {
		filterStr = "(ether proto 0x888e) and (ether dst host " + macFilter + ")"
	}
	return handle.SetBPFFilter(filterStr)
}

// ParseEAPPacket parses an Ethernet frame containing EAP
func ParseEAPPacket(data []byte) *EAPPacket {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth := ethLayer.(*layers.Ethernet)

	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		return nil
	}
	eap := eapLayer.(*layers.EAP)

	return &EAPPacket{
		SrcMAC:   eth.SrcMAC,
		DstMAC:   eth.DstMAC,
		Code:     eap.Code,
		Id:       eap.Id,
		Type:     eap.Type,
		TypeData: eap.TypeData,
		RawData:  data,
	}
}

// BuildEAPRequest builds an EAP Request packet (for server to trigger supplicant)
func BuildEAPRequest(srcMAC, dstMAC net.HardwareAddr, id uint8, eapType layers.EAPType, typeData []byte) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: 0x888e,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeRequest,
		Id:       id,
		Type:     eapType,
		TypeData: typeData,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eapol, &eap)
	return buf.Bytes()
}

// BuildEAPResponse builds an EAP Response packet
func BuildEAPResponse(srcMAC, dstMAC net.HardwareAddr, id uint8, eapType layers.EAPType, typeData []byte) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: 0x888e,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
		Type:     eapType,
		TypeData: typeData,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eapol, &eap)
	return buf.Bytes()
}

// BuildEAPOLStart builds an EAPOL-Start packet
func BuildEAPOLStart(srcMAC net.HardwareAddr) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}, // PAE multicast
		EthernetType: 0x888e,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
		Length:  0,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, &eth, &eapol)
	return buf.Bytes()
}

// SerializeEAPPacket serializes EAP packet info back to raw bytes
func SerializeEAPPacket(pkt *EAPPacket) []byte {
	eth := layers.Ethernet{
		SrcMAC:       pkt.SrcMAC,
		DstMAC:       pkt.DstMAC,
		EthernetType: 0x888e,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
	}
	eap := layers.EAP{
		Code:     pkt.Code,
		Id:       pkt.Id,
		Type:     pkt.Type,
		TypeData: pkt.TypeData,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &eapol, &eap)
	return buf.Bytes()
}
