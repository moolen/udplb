package byteorder

import (
	"encoding/binary"
	"net"
)

// HtonIP transforms an net.IP to network-byte-order-byte-array
func HtonIP(ip net.IP) [4]byte {
	in := binary.BigEndian.Uint32(ip[12:16])
	bytes := [4]byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(bytes[:], in)
	return bytes
}

// Htons trasforms a uint16 to a network-byte-order-2-byte-array
func Htons(val uint16) [2]byte {
	bytes := [2]byte{0, 0}
	binary.BigEndian.PutUint16(bytes[:], val)
	return bytes
}

// Htonl trasforms a uint32 to a network-byte-order-4-byte-array
func Htonl(val uint32) [4]byte {
	bytes := [4]byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(bytes[:], val)
	return bytes
}

// Ntohl trasforms a network-byte-order-byteslice to a host-byte-order-uint32
// this function is susceptible to out-of-bounds reads
func Ntohl(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

// Ntohs trasforms a network-byte-order-byteslice to a host-byte-order-uint16
// this function is susceptible to out-of-bounds reads
func Ntohs(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

// NtohIP trasforms a network-byte-order-byteslice to a host-byte-order net.IP
// this function is susceptible to out-of-bounds reads
func NtohIP(buf []byte) net.IP {
	num := Ntohl(buf)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, num)
	return ip
}
