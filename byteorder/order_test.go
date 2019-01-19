package byteorder

import (
	"bytes"
	"net"
	"testing"
)

func TestHtonIP(t *testing.T) {

	tbl := []struct {
		addr  net.IP
		bytes [4]byte
	}{
		{
			addr:  net.ParseIP("0.0.0.0"),
			bytes: [4]byte{0, 0, 0, 0},
		},
		{
			addr:  net.ParseIP("1.2.3.4"),
			bytes: [4]byte{1, 2, 3, 4},
		},
		{
			addr:  net.ParseIP("127.0.0.1"),
			bytes: [4]byte{0x7f, 0x0, 0x0, 0x1},
		},
		{
			addr:  net.ParseIP("255.255.255.255"),
			bytes: [4]byte{0xff, 0xff, 0xff, 0xff},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := HtonIP(row.addr)
		if bytes.Compare(row.bytes[:], val[:]) != 0 {
			t.Fatalf("[%d] bytes do not match, expected %#v, but got %#v", i, row.bytes, val)
		}
	}
}

func TestHtons(t *testing.T) {

	tbl := []struct {
		short uint16
		bytes [2]byte
	}{
		{
			short: 1,
			bytes: [2]byte{0x0, 0x1},
		},
		{
			short: 1025,
			bytes: [2]byte{0x4, 0x1},
		},
		{
			short: 65535,
			bytes: [2]byte{0xff, 0xff},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := Htons(row.short)
		if bytes.Compare(row.bytes[:], val[:]) != 0 {
			t.Fatalf("[%d] bytes do not match, expected %#v, but got %#v", i, row.bytes, val)
		}
	}
}

func TestHtonl(t *testing.T) {

	tbl := []struct {
		long  uint32
		bytes [4]byte
	}{
		{
			long:  1,
			bytes: [4]byte{0x0, 0x0, 0x0, 0x1},
		},
		{
			long:  1025,
			bytes: [4]byte{0x0, 0x0, 0x4, 0x1},
		},
		{
			long:  65535,
			bytes: [4]byte{0x0, 0x0, 0xff, 0xff},
		},
		{
			long:  65536,
			bytes: [4]byte{0x0, 0x1, 0x0, 0x0},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := Htonl(row.long)
		if bytes.Compare(row.bytes[:], val[:]) != 0 {
			t.Fatalf("[%d] bytes do not match, expected %#v, but got %#v", i, row.bytes, val)
		}
	}
}

func TestNtohl(t *testing.T) {

	tbl := []struct {
		long  uint32
		bytes []byte
	}{
		{
			long:  1,
			bytes: []byte{0x0, 0x0, 0x0, 0x1},
		},
		{
			long:  1025,
			bytes: []byte{0x0, 0x0, 0x4, 0x1},
		},
		{
			long:  65535,
			bytes: []byte{0x0, 0x0, 0xff, 0xff},
		},
		{
			long:  65536,
			bytes: []byte{0x0, 0x1, 0x0, 0x0},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := Ntohl(row.bytes)
		if val != row.long {
			t.Fatalf("[%d] bytes do not match, expected %#v, but got %#v", i, row.bytes, val)
		}
	}
}

func TestNtohs(t *testing.T) {

	tbl := []struct {
		long  uint16
		bytes []byte
	}{
		{
			long:  1,
			bytes: []byte{0x0, 0x1},
		},
		{
			long:  1025,
			bytes: []byte{0x4, 0x1},
		},
		{
			long:  65535,
			bytes: []byte{0xff, 0xff},
		},
		// slice too long, only first two bytes will be red
		{
			long:  0,
			bytes: []byte{0x0, 0x0, 0xff, 0xff},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := Ntohs(row.bytes)
		if val != row.long {
			t.Fatalf("[%d] bytes do not match, expected %d, but got %d", i, row.long, val)
		}
	}
}

func TestNtohIP(t *testing.T) {

	tbl := []struct {
		addr  net.IP
		bytes []byte
	}{
		{
			addr:  net.ParseIP("0.0.0.0"),
			bytes: []byte{0, 0, 0, 0},
		},
		{
			addr:  net.ParseIP("1.2.3.4"),
			bytes: []byte{1, 2, 3, 4},
		},
		{
			addr:  net.ParseIP("127.0.0.1"),
			bytes: []byte{0x7f, 0x0, 0x0, 0x1},
		},
		{
			addr:  net.ParseIP("255.255.255.255"),
			bytes: []byte{0xff, 0xff, 0xff, 0xff},
		},
	}

	for i, row := range tbl {
		t.Logf("[%d] %#v", i, row)
		val := NtohIP(row.bytes)
		if bytes.Compare(row.bytes, val) != 0 {
			t.Fatalf("[%d] bytes do not match, expected %#v, but got %#v", i, row.bytes, val)
		}
	}
}
