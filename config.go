package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/moolen/udplb/byteorder"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Key must match C struct lb_key
type Key struct {
	// Address contains the IPv4 address in network byte order
	Address [4]byte
	// Port contains the UDP Port in network byte order
	Port [2]byte
	// Slave field contains the number of the upstream. 0 is considered a master
	// see bpf/ingress.c for a detailed explanation of the lookup procedure
	Slave uint8
}

// Upstream must match C struct lb_upstream
type Upstream struct {
	// Address contains the IPv4 address in network byte order
	Address [4]byte
	// Port contains the UDP port of the upstream in network byte order
	Port [2]byte
	// Count is set only for the master (Key.Slave=0) and contains the number of upstreams
	Count uint8
	// TCAction contains a valid TC_ACT_* return code for eBPF programs
	// TCAction=0 will forward the packet to userspace
	// TCAction=2 will drop the packet
	// see linux/pkt_cls.h
	TCAction uint8
}

type config []struct {
	Key      Key
	Upstream []Upstream
}

func newConfigYaml(r io.Reader) (cfg *config, err error) {
	d := yaml.NewDecoder(r)
	err = d.Decode(&cfg)
	return
}

// Apply sets the key/upstream configuration in the provided bpf.Table
func (c config) Apply(tbl *bpf.Table) error {
	for _, record := range c {
		k := record.Key
		k.Slave = 0 // the master
		masterUpstream := Upstream{Count: uint8(len(record.Upstream))}
		err := tbl.SetP(unsafe.Pointer(&k), unsafe.Pointer(&masterUpstream))
		if err != nil {
			return err
		}
		for n, upstream := range record.Upstream {
			k.Slave = uint8(n + 1)
			err := tbl.SetP(unsafe.Pointer(&k), unsafe.Pointer(&upstream))
			if err != nil {
				return err
			}
		}
	}
	for it := tbl.Iter(); it.Next(); {
		var upstream Upstream
		var key Key
		err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key)
		if err != nil {
			return err
		}
		err = binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &upstream)
		if err != nil {
			return err
		}
		log.Infof("%s | %s", key.String(), upstream.String())
	}
	return nil
}

// UnmarshalYAML translates the yaml types to match the internal C types
func (k *Key) UnmarshalYAML(unmarshal func(interface{}) error) error {
	cfg := &struct {
		Address string
		Port    int
	}{}
	err := unmarshal(&cfg)
	if err != nil {
		return err
	}
	newKey := Key{
		Address: byteorder.HtonIP(net.ParseIP(cfg.Address)),
		Port:    byteorder.Htons(uint16(cfg.Port)),
	}
	*k = newKey
	return nil
}

// IP returns the net.IP address of the key
func (k *Key) IP() net.IP {
	return byteorder.NtohIP(k.Address[:])
}

// implement Stringer interface
func (k *Key) String() string {
	return fmt.Sprintf("Key{ Address: %s, Port: %d, Slave: %d } ", k.IP(), byteorder.Ntohs(k.Port[:]), k.Slave)
}

// UnmarshalYAML translates the yaml types to match the internal C types
func (u *Upstream) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tcAction uint8
	cfg := &struct {
		Address  string `yaml:"address"`
		Port     uint16 `yaml:"port"`
		TCAction string `yaml:"tc_action"`
	}{}
	err := unmarshal(&cfg)
	if err != nil {
		return err
	}

	if cfg.TCAction == "pass" || cfg.TCAction == "" {
		tcAction = 0
	} else if cfg.TCAction == "block" {
		tcAction = 2
	} else {
		return fmt.Errorf("invalid tc_action value: %s", cfg.TCAction)
	}
	newUpstream := Upstream{
		Address:  byteorder.HtonIP(net.ParseIP(cfg.Address)),
		Port:     byteorder.Htons(cfg.Port),
		Count:    0,
		TCAction: tcAction,
	}
	*u = newUpstream
	return nil
}

// IP returns the net.IP address of the upstream
func (u *Upstream) IP() net.IP {
	return byteorder.NtohIP(u.Address[:])
}

// implement Stringer interface
func (u *Upstream) String() string {
	return fmt.Sprintf("Upstream{ Address: %s, Port: %d, Count: %d, Action: %d } ", u.IP(), byteorder.Ntohs(u.Port[:]), u.Count, u.TCAction)
}
