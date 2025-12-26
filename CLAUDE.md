# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZaNetworkTool is a Go-based 802.1X EAP (Extensible Authentication Protocol) network authentication tool. It uses the gopacket library for raw packet capture and manipulation.

## Build Commands

```bash
# Build all commands
go build ./...

# List network interfaces
go run ./cmd/device

# Capture EAP credentials (requires interface name, e.g., en0 on macOS)
go run ./cmd/hack -i <interface>

# Run authentication with captured credentials
go run ./cmd/auth -interface <interface> -mac <mac-address>

# EAP Mirror - Server mode (on machine with EAP supplicant)
go run ./cmd/mirror -mode server -interface <iface> -mac <supplicant-mac> -listen :8021

# EAP Mirror - Client mode (on machine needing authentication)
go run ./cmd/mirror -mode client -interface <iface> -mac <local-mac> -server <server-ip:port>
```

Requires libpcap (macOS/Linux) or WinPcap/Npcap (Windows) for packet capture.

## Architecture

The project has four commands in `cmd/`:

- **cmd/device** - Network interface enumeration utility. Lists available interfaces using both `net.Interfaces()` and `pcap.FindAllDevs()`.

- **cmd/hack** - EAP credential capture. Listens on an interface for 802.1X packets (BPF filter `ether proto 0x888e`), extracts identity (EAPTypeIdentity) and password (EAP type 0x66) from EAP Response packets, and saves them to `password.bin` in format `username[0xFF]password`.

- **cmd/auth** - Authentication replay. Reads credentials from `password.bin`, broadcasts EAPOL Start frames to initiate authentication, then responds to EAP requests with the captured identity and password.

- **cmd/mirror** - EAP relay between two machines. Machine A (server mode) has an EAP supplicant, machine B (client mode) needs authentication. B forwards EAP requests to A via TCP, A triggers its local supplicant, captures the response, and returns it to B.

Shared EAP handling code is in `internal/mirror/`.

## Key Protocol Details

- EtherType 0x888e = EAPOL (EAP over LAN)
- EAP type 0x66 = Password packet (proprietary)
- Credentials file format: `username` + `0xFF` byte separator + `password` (binary)

## Dependencies

- `github.com/google/gopacket` - Packet parsing and serialization
- `github.com/google/gopacket/layers` - Protocol layer definitions
- `github.com/google/gopacket/pcap` - libpcap bindings
