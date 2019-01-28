package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	c := make(chan string, 1)
	payload := "foo.bar.baz.bang"
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":8193"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		c <- string(buf[:n])
	}()

	err = send(10000, 8193, net.ParseIP("127.0.0.1"), payload)
	if err != nil {
		t.Fatal(err)
	}
	rcv := <-c
	if strings.Compare(rcv, payload) != 0 {
		t.Fatalf("payload did not match %s", payload)
	}
}
