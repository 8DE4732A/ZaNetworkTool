package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:\n -conn <interface> <username> <password> \n -dev")
	} else {
		if os.Args[1] == "-conn" && len(os.Args) < 4 {
			fmt.Println("Usage:\n -conn <interface> <username> <password>")
			return
		} else if os.Args[1] == "-dev" {
			fmt.Println(dev())
			return
		}
	}

}

func dev() []string {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}
	result := make([]string, 0, 0)
	for _, intf := range ifs {
		result = append(result, intf.Name)
	}
	return result
}
