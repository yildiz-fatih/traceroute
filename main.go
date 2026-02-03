package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")

	for TTL := 1; ; TTL++ {
		t := time.Now().Add(time.Second * 5)
		err = conn.SetReadDeadline(t)
		if err != nil {
			continue
		}

		msg := icmp.Message{
			Type:     ipv4.ICMPTypeEcho,
			Code:     0, // Description: No Code
			Checksum: 0, // has not been calculated yet, put 0 for now
			Body: &icmp.Echo{
				ID:   os.Getpid(),     // uniquely identifies this traceroute program
				Seq:  1,               // start at 1 for now, increment later
				Data: []byte("hello"), // can be anything, put "hello" for now
			},
		}

		connIPV4 := conn.IPv4PacketConn()
		connIPV4.SetTTL(TTL)

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			log.Fatalf("Error marshalling ICMP message to bytes: %v", err)
		}

		ipAddr, err := net.ResolveIPAddr("ip4", "google.com.tr")
		if err != nil {
			log.Fatalf("Error resolving IP address: %v", err)
		}

		conn.WriteTo(msgBytes, ipAddr)

		responseBytes := make([]byte, 1500)

		_, _, err = conn.ReadFrom(responseBytes)
		if err != nil { // timeout or other error
			fmt.Println("*")
			continue
		}

		responseMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), responseBytes)
		if err != nil {
			log.Fatalf("Error parsing ICMP message: %v", err)
		}

		fmt.Println(responseMsg)

		if responseMsg.Type == ipv4.ICMPTypeEchoReply {
			return
		}
	}
}
