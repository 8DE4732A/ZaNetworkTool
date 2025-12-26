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

// Client runs on machine B (without EAP supplicant)
type Client struct {
	serverAddr string
	ifaceName  string
	localMAC   net.HardwareAddr
	handle     *pcap.Handle
	conn       net.Conn
	mu         sync.Mutex
}

// NewClient creates a new mirror client
func NewClient(serverAddr, ifaceName, localMAC string) (*Client, error) {
	mac, err := net.ParseMAC(localMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid local MAC: %v", err)
	}

	return &Client{
		serverAddr: serverAddr,
		ifaceName:  ifaceName,
		localMAC:   mac,
	}, nil
}

// Run starts the client
func (c *Client) Run() error {
	// Open interface for packet capture
	handle, err := OpenInterface(c.ifaceName)
	if err != nil {
		return fmt.Errorf("failed to open interface: %v", err)
	}
	c.handle = handle
	defer handle.Close()

	// Set filter to capture EAP requests destined to us
	if err := SetEAPFilter(handle, c.localMAC.String()); err != nil {
		return fmt.Errorf("failed to set filter: %v", err)
	}

	log.Printf("[Client] Starting, interface: %s, MAC: %s, server: %s",
		c.ifaceName, c.localMAC, c.serverAddr)

	// Connect to server with retry
	for {
		if err := c.connectAndRun(); err != nil {
			log.Printf("[Client] Connection error: %v, retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}
	}
}

func (c *Client) connectAndRun() error {
	conn, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	defer conn.Close()

	log.Printf("[Client] Connected to server")

	// Send EAPOL-Start to initiate authentication
	startPkt := BuildEAPOLStart(c.localMAC)
	if err := c.handle.WritePacketData(startPkt); err != nil {
		log.Printf("[Client] Failed to send EAPOL-Start: %v", err)
	} else {
		log.Printf("[Client] Sent EAPOL-Start")
	}

	// Channel for responses from server
	responseChan := make(chan *Message, 10)
	done := make(chan struct{})
	defer close(done)

	// Start goroutine to read responses from server
	go c.readServerResponses(responseChan, done)

	// Capture and forward EAP requests
	src := gopacket.NewPacketSource(c.handle, layers.LayerTypeEthernet)
	packets := src.Packets()

	for {
		select {
		case packet := <-packets:
			if packet == nil {
				continue
			}
			c.handlePacket(packet, responseChan)

		case resp := <-responseChan:
			if err := c.handleServerResponse(resp); err != nil {
				return err
			}
		}
	}
}

func (c *Client) handlePacket(packet gopacket.Packet, responseChan <-chan *Message) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)
	serverMAC := eth.SrcMAC

	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		return
	}
	eap := eapLayer.(*layers.EAP)

	switch eap.Code {
	case layers.EAPCodeRequest:
		log.Printf("[Client] Received EAP request from server: id=%d, type=%d", eap.Id, eap.Type)

		// Forward to mirror server
		eapInfo, _ := json.Marshal(struct {
			Id       uint8  `json:"id"`
			Type     uint8  `json:"type"`
			TypeData []byte `json:"type_data"`
			ServerMAC string `json:"server_mac"`
		}{
			Id:        eap.Id,
			Type:      uint8(eap.Type),
			TypeData:  eap.TypeData,
			ServerMAC: serverMAC.String(),
		})

		c.mu.Lock()
		err := WriteMessage(c.conn, &Message{Type: MsgTypeEAPRequest, Payload: eapInfo})
		c.mu.Unlock()

		if err != nil {
			log.Printf("[Client] Failed to forward request: %v", err)
			return
		}
		log.Printf("[Client] Forwarded EAP request to mirror server")

		// Wait for response and send it
		select {
		case resp := <-responseChan:
			c.sendEAPResponse(resp, serverMAC)
		case <-time.After(15 * time.Second):
			log.Printf("[Client] Timeout waiting for mirror response")
		}

	case layers.EAPCodeSuccess:
		log.Printf("[Client] Authentication SUCCESS!")

	case layers.EAPCodeFailure:
		log.Printf("[Client] Authentication FAILED!")
	}
}

func (c *Client) readServerResponses(responseChan chan<- *Message, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			msg, err := ReadMessage(c.conn)
			if err != nil {
				log.Printf("[Client] Read from server error: %v", err)
				return
			}

			select {
			case responseChan <- msg:
			case <-done:
				return
			}
		}
	}
}

func (c *Client) handleServerResponse(msg *Message) error {
	// This is called from the main loop when we receive responses asynchronously
	// For now, responses are handled in handlePacket
	return nil
}

func (c *Client) sendEAPResponse(msg *Message, serverMAC net.HardwareAddr) {
	var respInfo struct {
		Code     uint8  `json:"code"`
		Id       uint8  `json:"id"`
		Type     uint8  `json:"type"`
		TypeData []byte `json:"type_data"`
	}

	if err := json.Unmarshal(msg.Payload, &respInfo); err != nil {
		log.Printf("[Client] Failed to parse response: %v", err)
		return
	}

	// Build EAP response with our MAC
	pktData := BuildEAPResponse(c.localMAC, serverMAC, respInfo.Id, layers.EAPType(respInfo.Type), respInfo.TypeData)

	if err := c.handle.WritePacketData(pktData); err != nil {
		log.Printf("[Client] Failed to send EAP response: %v", err)
		return
	}

	log.Printf("[Client] Sent EAP response: id=%d, type=%d", respInfo.Id, respInfo.Type)
}
