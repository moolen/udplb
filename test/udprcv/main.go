package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type packetResult struct {
	payload string
	err     error
}

var (
	port  int
	match string
	wait  string
)

func main() {
	flag.IntVar(&port, "port", 8125, "port to listen on")
	flag.StringVar(&match, "match", "foo.bar.baz", "match packet content")
	flag.StringVar(&wait, "wait", "2s", "wait time")
	flag.Parse()

	log.Printf("port= %d match= %s wait= %s", port, match, wait)

	dur, err := time.ParseDuration(wait)
	if err != nil {
		panic(err)
	}
	ok, err := matchPacket(dur, port, match)
	if err != nil {
		panic(err)
	}
	if ok {
		log.Printf("OK")
		os.Exit(0)
	}
	log.Printf("FAIL")
	os.Exit(1)
}

func matchPacket(dur time.Duration, port int, match string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	packet, err := waitForPacket(ctx, conn)
	if err != nil {
		return false, err
	}
	if strings.Compare(packet.payload, match) != 0 {
		log.Printf("packet did not match %s", match)
		return false, nil
	}
	return true, nil
}

func waitForPacket(ctx context.Context, conn net.PacketConn) (packetResult, error) {
	c := make(chan packetResult, 1)
	go func() {
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		c <- packetResult{
			payload: string(buf[:n]),
			err:     err,
		}
	}()
	select {
	case <-ctx.Done():
		return packetResult{}, fmt.Errorf("error waiting for packet: %s", ctx.Err())
	case res := <-c:
		return res, nil
	}
}
