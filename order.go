package main

import (
	"encoding/binary"
	"net"
)

func htonsint(port uint16) uint16 {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, port)
	return binary.BigEndian.Uint16(bs)
}

func intle(i uint16) uint16 {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, i)
	return binary.LittleEndian.Uint16(bs)
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func htonl(val uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	return bytes
}

func htonIP(ip net.IP) [4]byte {
	in := binary.BigEndian.Uint32(ip[12:16])
	bytes := [4]byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(bytes[:], in)
	return bytes
}

func htons(val uint16) [2]byte {
	bytes := [2]byte{0, 0}
	binary.BigEndian.PutUint16(bytes[:], val)
	return bytes
}

func ntohl(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

func ntohs(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

func ntohIP(buf []byte) net.IP {
	num := ntohl(buf)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, num)
	return ip
}
