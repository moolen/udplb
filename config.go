package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"

	"gopkg.in/yaml.v2"
)

// LBKey must match C struct lb_key
type LBKey struct {
	Address uint32
	Port    uint16
	Slave   uint8
}

// LBUpstream must match C struct lb_upstream
type LBUpstream struct {
	Address uint32
	Port    uint16
	Count   uint8
}

type ConfigKey struct {
	Address string
	Port    int
}
type ConfigUpstream struct {
	// Address of upstream server
	Address string `yaml:"address"`
	// Port of upstream server
	Port int `yaml:"port"`
}

type ConfigRecord struct {
	Key      ConfigKey
	Upstream []ConfigUpstream
}

type Config []ConfigRecord

func NewConfigYaml(r io.Reader) (cfg *Config, err error) {
	d := yaml.NewDecoder(r)
	err = d.Decode(&cfg)
	return
}

func (c Config) Apply(tbl *bpf.Table) error {
	for _, record := range c {
		// prepare master record
		k := record.Key.LBKey()
		k.Slave = 0
		v := &LBUpstream{Count: uint8(len(record.Upstream))}
		err := tbl.SetP(unsafe.Pointer(k), unsafe.Pointer(v))
		if err != nil {
			return err
		}
		log.Printf("master: %#v | %#v\n", k, v)
		for n, upstream := range record.Upstream {
			v := upstream.LBUpstream()
			k.Slave = uint8(n + 1)
			err := tbl.SetP(unsafe.Pointer(k), unsafe.Pointer(v))
			if err != nil {
				return err
			}
		}
	}
	for it := tbl.Iter(); it.Next(); {
		var upstream LBUpstream
		var key LBKey
		err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key)
		if err != nil {
			return err
		}
		err = binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &upstream)
		if err != nil {
			return err
		}
		fmt.Printf("---\nKEY: %#v\nVAL: %#v\n", key, upstream)
	}
	return nil
}

func (k ConfigKey) LBKey() *LBKey {
	return NewLBKey(k.Address, k.Port)
}

func (k ConfigKey) String() string {
	return fmt.Sprintf("%s:%d/%d", k.Address, k.Port)
}

func (u ConfigUpstream) LBUpstream() *LBUpstream {
	return NewLBUpstream(u.Address, u.Port)
}

func (u ConfigUpstream) IP() net.IP {
	return net.ParseIP(u.Address)
}

func (u ConfigUpstream) String() string {
	return fmt.Sprintf("%s:%d", u.Address, u.Port)
}

func NewLBKey(addr string, port int) *LBKey {
	return &LBKey{
		Address: ip2int(net.ParseIP(addr)),
		Port:    uint16be(uint16(port)),
	}
}

func NewLBUpstream(addr string, port int) *LBUpstream {
	return &LBUpstream{
		Address: ip2int(net.ParseIP(addr)),
		Port:    uint16be(uint16(port)),
		Count:   0,
	}
}

func uint16be(port uint16) uint16 {
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
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
