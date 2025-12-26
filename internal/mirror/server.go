package mirror

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Server runs on machine A (with EAP supplicant)
type Server struct {
	listenAddr    string
	ifaceName     string
	supplicantMAC net.HardwareAddr // MAC of the local supplicant
	handle        *pcap.Handle
	mu            sync.Mutex
}

// NewServer creates a new mirror server
func NewServer(listenAddr, ifaceName, supplicantMAC string) (*Server, error) {
	mac, err := net.ParseMAC(supplicantMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid supplicant MAC: %v", err)
	}

	return &Server{
		listenAddr:    listenAddr,
		ifaceName:     ifaceName,
		supplicantMAC: mac,
	}, nil
}

// Run starts the server
func (s *Server) Run() error {
	// Open interface for packet capture
	handle, err := OpenInterface(s.ifaceName)
	if err != nil {
		return fmt.Errorf("failed to open interface: %v", err)
	}
	s.handle = handle
	defer handle.Close()

	// Set filter to capture EAP responses from supplicant
	if err := SetEAPFilter(handle, ""); err != nil {
		return fmt.Errorf("failed to set filter: %v", err)
	}

	// Start TCP listener
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("[Server] Listening on %s, interface: %s, supplicant MAC: %s",
		s.listenAddr, s.ifaceName, s.supplicantMAC)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[Server] Accept error: %v", err)
			continue
		}
		log.Printf("[Server] Client connected: %s", conn.RemoteAddr())
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	// Channel for EAP responses from local supplicant
	responseChan := make(chan *EAPPacket, 10)
	done := make(chan struct{})
	defer close(done)

	// Start goroutine to capture EAP responses from supplicant
	go s.captureResponses(responseChan, done)

	for {
		// Read EAP request from client (B)
		msg, err := ReadMessage(conn)
		if err != nil {
			log.Printf("[Server] Read error: %v", err)
			return
		}

		if msg.Type != MsgTypeEAPRequest {
			log.Printf("[Server] Unexpected message type: %d", msg.Type)
			continue
		}

		// Parse the EAP request
		var eapInfo struct {
			Id       uint8  `json:"id"`
			Type     uint8  `json:"type"`
			TypeData []byte `json:"type_data"`
		}
		if err := json.Unmarshal(msg.Payload, &eapInfo); err != nil {
			log.Printf("[Server] Failed to parse EAP info: %v", err)
			continue
		}

		log.Printf("[Server] Received EAP request: id=%d, type=%d", eapInfo.Id, eapInfo.Type)

		// Build and send EAP request to local supplicant
		// Use broadcast MAC as source (simulating authenticator)
		srcMAC := net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
		pktData := BuildEAPRequest(srcMAC, s.supplicantMAC, eapInfo.Id, layers.EAPType(eapInfo.Type), eapInfo.TypeData)

		s.mu.Lock()
		if err := s.handle.WritePacketData(pktData); err != nil {
			s.mu.Unlock()
			log.Printf("[Server] Failed to send EAP request: %v", err)
			continue
		}
		s.mu.Unlock()

		log.Printf("[Server] Sent EAP request to supplicant")

		// Wait for response from supplicant with timeout
		select {
		case resp := <-responseChan:
			// Forward response to client
			respInfo, _ := json.Marshal(struct {
				Code     uint8  `json:"code"`
				Id       uint8  `json:"id"`
				Type     uint8  `json:"type"`
				TypeData []byte `json:"type_data"`
			}{
				Code:     uint8(resp.Code),
				Id:       resp.Id,
				Type:     uint8(resp.Type),
				TypeData: resp.TypeData,
			})

			var msgType byte
			switch resp.Code {
			case layers.EAPCodeResponse:
				msgType = MsgTypeEAPResponse
			case layers.EAPCodeSuccess:
				msgType = MsgTypeEAPSuccess
			case layers.EAPCodeFailure:
				msgType = MsgTypeEAPFailure
			default:
				msgType = MsgTypeEAPResponse
			}

			if err := WriteMessage(conn, &Message{Type: msgType, Payload: respInfo}); err != nil {
				log.Printf("[Server] Failed to send response: %v", err)
				return
			}
			log.Printf("[Server] Forwarded EAP response to client: code=%d, id=%d, type=%d",
				resp.Code, resp.Id, resp.Type)

		case <-time.After(10 * time.Second):
			log.Printf("[Server] Timeout waiting for supplicant response")
		}
	}
}

func (s *Server) captureResponses(responseChan chan<- *EAPPacket, done <-chan struct{}) {
	src := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packets := src.Packets()

	for {
		select {
		case <-done:
			return
		case packet := <-packets:
			if packet == nil {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)

			// Only capture packets from supplicant
			if eth.SrcMAC.String() != s.supplicantMAC.String() {
				continue
			}

			eapLayer := packet.Layer(layers.LayerTypeEAP)
			if eapLayer == nil {
				continue
			}
			eap := eapLayer.(*layers.EAP)

			// Only capture responses
			if eap.Code == layers.EAPCodeResponse {
				pkt := &EAPPacket{
					SrcMAC:   eth.SrcMAC,
					DstMAC:   eth.DstMAC,
					Code:     eap.Code,
					Id:       eap.Id,
					Type:     eap.Type,
					TypeData: eap.TypeData,
				}

				select {
				case responseChan <- pkt:
				default:
					// Channel full, drop packet
				}
			}
		}
	}
}
