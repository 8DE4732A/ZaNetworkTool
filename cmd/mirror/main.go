package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/8DE4732A/ZaNetworkTool/internal/mirror"
)

var (
	mode      string
	ifaceName string
	mac       string
	listen    string
	server    string
)

func init() {
	flag.StringVar(&mode, "mode", "", "Mode: server or client")
	flag.StringVar(&ifaceName, "interface", "", "Network interface name")
	flag.StringVar(&mac, "mac", "", "MAC address (server: supplicant MAC, client: local MAC)")
	flag.StringVar(&listen, "listen", ":8021", "Listen address for server mode")
	flag.StringVar(&server, "server", "", "Server address for client mode (e.g., 192.168.1.100:8021)")
}

func main() {
	flag.Parse()

	if mode == "" || ifaceName == "" || mac == "" {
		printUsage()
		os.Exit(1)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	switch mode {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Printf("Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}
}

func runServer() {
	srv, err := mirror.NewServer(listen, ifaceName, mac)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Printf("Starting EAP Mirror Server...")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func runClient() {
	if server == "" {
		fmt.Println("Error: -server is required in client mode")
		printUsage()
		os.Exit(1)
	}

	cli, err := mirror.NewClient(server, ifaceName, mac)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	log.Printf("Starting EAP Mirror Client...")
	if err := cli.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}

func printUsage() {
	fmt.Println("EAP Mirror Tool - Relay EAP authentication between two machines")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Server mode (on machine A with EAP supplicant):")
	fmt.Println("    go run ./cmd/mirror -mode server -interface <iface> -mac <supplicant-mac> [-listen :8021]")
	fmt.Println()
	fmt.Println("  Client mode (on machine B without EAP supplicant):")
	fmt.Println("    go run ./cmd/mirror -mode client -interface <iface> -mac <local-mac> -server <server-ip:port>")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Machine A (has EAP client, IP: 192.168.1.100)")
	fmt.Println("  go run ./cmd/mirror -mode server -interface en0 -mac 00:11:22:33:44:55 -listen :8021")
	fmt.Println()
	fmt.Println("  # Machine B (needs authentication)")
	fmt.Println("  go run ./cmd/mirror -mode client -interface en0 -mac aa:bb:cc:dd:ee:ff -server 192.168.1.100:8021")
	fmt.Println()
	flag.PrintDefaults()
}
