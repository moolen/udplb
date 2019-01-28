package main

import (
	"flag"
	"log"
	"net"
)

var (
	sPort   int
	dPort   int
	dAddr   string
	payload string
)

func main() {
	flag.IntVar(&sPort, "sport", 9999, "udp source port to send traffic from")
	flag.IntVar(&dPort, "dport", 8125, "udp dest port to send traffic to")
	flag.StringVar(&dAddr, "daddr", "10.123.0.10", "udp dest addr to send traffic to")
	flag.StringVar(&payload, "payload", "foo.bar.baz", "udp payload")
	flag.Parse()

	send(sPort, dPort, net.ParseIP(dAddr), payload)
}

func send(sPort, dPort int, dIP net.IP, payload string) error {
	log.Printf("sending :%d -> %s:%d [%s]", sPort, dIP, dPort, payload)
	conn, err := net.DialUDP("udp", &net.UDPAddr{Port: sPort}, &net.UDPAddr{IP: dIP, Port: dPort})
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return err
	}
	return nil
}
