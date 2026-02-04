package main

import (
	"encoding/binary"
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

		// --- wait for response ---
		found := false
		for {
			responseBytes := make([]byte, 1500)

			responseLen, responderAddr, err := conn.ReadFrom(responseBytes)
			if err != nil { // timeout or other error
				fmt.Printf("%d\t*\n", TTL)
				break
			}

			responseMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), responseBytes[:responseLen])
			if err != nil {
				continue
			}

			// --- check incoming packets ---
			switch responseMsg.Type {
			case ipv4.ICMPTypeEchoReply:
				// check if the packet belong to this program
				if responseMsg.Body.(*icmp.Echo).ID == os.Getpid() {
					fmt.Printf("%d\t%s\n", TTL, responderAddr.String())
					return // echo reply received, end the program
				}
			case ipv4.ICMPTypeTimeExceeded:
				// check if the packet belong to this program

				/*
				   ICMP Time Exceeded packet layout:
				   	Outer IPv4 Header  								- bytes 0–19 	- 20 bytes (Gets this packet back to you)
				   	Outer ICMP Header (Time Exceeded)				- bytes 20–27	- 8 bytes:
				   	Inner Payload (Original packet that expired):
				   		Inner IPv4 Header 							- bytes 28–47	- 20 bytes
				   		Inner ICMP Header (first 8 bytes only) 		- bytes 48-55	- 8 bytes
				   			- Bytes 48: Type (Echo = 8)
				   			- Bytes 49: Code (0)
				   			- Bytes 50-51: Checksum
				   			- Bytes 52-53: ID 						<--- TARGET
				   			- Bytes 54-55: Sequence Number
				*/
				// In Go:
				//   responseMsg.Body.(*icmp.TimeExceeded).Data[0]		== byte 28
				//   responseMsg.Body.(*icmp.TimeExceeded).Data[24] 	== byte 52
				//   responseMsg.Body.(*icmp.TimeExceeded).Data[24:26]	== original ICMP ID

				const (
					innerIPv4HeaderLen = 20
					icmpEchoIDOffset   = 4
					icmpEchoIDLen      = 2
				)

				echoIDOffset := innerIPv4HeaderLen + icmpEchoIDOffset

				if int(binary.BigEndian.Uint16(responseMsg.Body.(*icmp.TimeExceeded).Data[echoIDOffset:echoIDOffset+icmpEchoIDLen])) == os.Getpid() {
					fmt.Printf("%d\t%s\n", TTL, responderAddr.String())
					found = true
				}
			}

			if found {
				break
			}
		}
	}
}
