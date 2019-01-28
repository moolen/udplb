package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWaitPacketSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":8193"))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer conn.Close()
	go func() {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{Port: 8193})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Write([]byte("foo"))
		if err != nil {
			t.Fatal(err)
		}
	}()
	packet, err := waitForPacket(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(packet.payload, "foo") != 0 {
		t.Fatalf("packet did not match. expected foo, got %s\n", packet.payload)
	}
}

func TestWaitPacketTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":8193"))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer conn.Close()
	go func() {
		<-time.After(100 * time.Millisecond)
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{Port: 8193})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Write([]byte("foo"))
		if err != nil {
			t.Fatal(err)
		}
	}()
	_, err = waitForPacket(ctx, conn)
	if err == nil {
		t.Fatal(fmt.Printf("error should be context deadline exceeded"))
	}
}

func TestMatchPacketTimeout(t *testing.T) {
	_, err := matchPacket(50*time.Millisecond, 9381, "foo")
	if err == nil {
		t.Fatal("expected error")
	}
}
func TestMatchPacket(t *testing.T) {
	go func() {
		<-time.After(10 * time.Millisecond)
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{Port: 9381})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Write([]byte("bar"))
		if err != nil {
			t.Fatal(err)
		}
	}()
	ok, err := matchPacket(50*time.Millisecond, 9381, "bar")
	if err != nil {
		t.Fatal(err)
	}
	if ok == false {
		t.Fatalf("expected packet to match bar")
	}
}

func TestMatchPacketMismatch(t *testing.T) {
	go func() {
		<-time.After(10 * time.Millisecond)
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{Port: 9381})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Write([]byte("foo"))
		if err != nil {
			t.Fatal(err)
		}
	}()
	ok, err := matchPacket(50*time.Millisecond, 9381, "bar")
	if err != nil {
		t.Fatal(err)
	}
	if ok == true {
		t.Fatalf("expected mismatch")
	}
}
