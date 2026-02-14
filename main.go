package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var processID int = os.Getpid()

func main() {
	var queries int
	var wait int
	var maxTTL int
	var numeric bool
	flag.IntVar(&queries, "q", 3, "Number of probes per hop")
	flag.IntVar(&wait, "w", 5, "Time (in seconds) to wait for a response to a probe")
	flag.IntVar(&maxTTL, "m", 64, "Max time-to-live (max number of hops)") // The current recommended default TTL for IP is 64 [RFC791] [RFC1122]
	flag.BoolVar(&numeric, "n", false, "Print hop addresses numerically (skip address-to-name lookup)")

	flag.Parse()

	remainingArgs := flag.Args()

	if len(remainingArgs) < 1 {
		fmt.Println("Usage: go run main.go <destination>")
		os.Exit(1)
	}
	destination := remainingArgs[0]

	dstAddr, err := net.ResolveIPAddr("ip4", destination)
	if err != nil {
		log.Fatalf("Error resolving IP address: %v", err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Error listening for ICMP packets: %v", err)
	}
	defer conn.Close()

	// IANA (https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml)
	// currently recommends default TTL of 64
	probeCounter := 1

	for TTL := 1; TTL <= maxTTL; TTL++ {
		reachedDestination := false
		fmt.Printf("Hop %d:\n", TTL)
		for range queries {
			responderAddr, elapsedTime, msgType, err := probe(conn, dstAddr, TTL, probeCounter, wait)
			probeCounter += 1
			if err != nil {
				fmt.Printf("  *\n")
				continue
			}

			displayName := responderAddr.String()

			if !numeric {
				// Reverse DNS Lookup
				names, _ := net.LookupAddr(responderAddr.String()) // Look up the hostname for the IP address, ignore errors
				if len(names) > 0 {                                // Hostname found
					displayName = fmt.Sprintf("%s (%s)", names[0], responderAddr.String()) // Format: "hostname (IP address)"
				}
			}

			switch msgType {
			case ipv4.ICMPTypeEchoReply:
				fmt.Printf("  %-32s %s\n", displayName, elapsedTime)
				reachedDestination = true
			case ipv4.ICMPTypeTimeExceeded:
				fmt.Printf("  %-32s %s\n", displayName, elapsedTime)
			}
		}

		if reachedDestination {
			os.Exit(0)
		}
	}
}

func probe(conn *icmp.PacketConn, dstAddr *net.IPAddr, TTL int, seqNum int, waitTime int) (net.Addr, time.Duration, ipv4.ICMPType, error) {
	startTime := time.Now()

	t := time.Now().Add(time.Second * time.Duration(waitTime))
	err := conn.SetReadDeadline(t)
	if err != nil {
		return nil, 0, 0, err
	}

	icmpEchoIDMask := 0xffff                      // ICMP Echo Identifier fields are exactly 16 bits wide, 0xffff is 16 1's in binary
	processIDKeep16 := processID & icmpEchoIDMask // Mask the PID with 0xffff to fit it into 16 bits

	msg := icmp.Message{
		Type:     ipv4.ICMPTypeEcho,
		Code:     0, // Description: No Code
		Checksum: 0, // has not been calculated yet, put 0 for now
		Body: &icmp.Echo{
			ID:   processIDKeep16, // uniquely identifies this traceroute program
			Seq:  seqNum,          // start at 1 for now, increment later
			Data: []byte("hello"), // can be anything, put "hello" for now
		},
	}

	connIPV4 := conn.IPv4PacketConn()
	connIPV4.SetTTL(TTL)

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return nil, 0, 0, err
	}

	conn.WriteTo(msgBytes, dstAddr)

	// --- wait for response ---
	for {
		responseBytes := make([]byte, 1500)

		responseLen, responderAddr, err := conn.ReadFrom(responseBytes)
		if err != nil { // timeout or other error
			return nil, 0, 0, err
		}

		elapsedTime := time.Since(startTime)

		responseMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), responseBytes[:responseLen])
		if err != nil {
			continue // ignore packet, keep listening
		}

		// --- check incoming packets ---
		switch responseMsg.Type {
		case ipv4.ICMPTypeEchoReply:
			// check if the packet belong to this program
			if responseMsg.Body.(*icmp.Echo).ID == processIDKeep16 && responseMsg.Body.(*icmp.Echo).Seq == seqNum {
				return responderAddr, elapsedTime, ipv4.ICMPTypeEchoReply, nil
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
				icmpEchoIDOffset   = innerIPv4HeaderLen + 4
				icmpEchoIDLen      = 2
				icmpEchoSeqOffset  = icmpEchoIDOffset + icmpEchoIDLen
				icmpEchoSeqLen     = 2
			)

			if int(binary.BigEndian.Uint16(responseMsg.Body.(*icmp.TimeExceeded).Data[icmpEchoIDOffset:icmpEchoIDOffset+icmpEchoIDLen])) == processIDKeep16 && int(binary.BigEndian.Uint16(responseMsg.Body.(*icmp.TimeExceeded).Data[icmpEchoSeqOffset:icmpEchoSeqOffset+icmpEchoSeqLen])) == seqNum {
				return responderAddr, elapsedTime, ipv4.ICMPTypeTimeExceeded, nil
			}
		}
	}
}
