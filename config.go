package main

import (
	"fmt"
	"io"
	"net"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/moolen/udplb/byteorder"

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
	// 0=src-port based
	// 1=src-ip based
	// 2=udp-payload based (TODO)
	Strategy uint8
}

// LBOption is a configuration-only data structure
// it is merged into the Upstream value
type LBOption struct {
	TCAction uint8
	Strategy uint8
}

type config []struct {
	Key      Key
	Options  LBOption
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
		// only the master contains the Strategy & TCAction
		k.Slave = 0
		masterUpstream := Upstream{
			Count:    uint8(len(record.Upstream)),
			Strategy: record.Options.Strategy,
			TCAction: record.Options.TCAction,
		}
		err := tbl.SetP(unsafe.Pointer(&k), unsafe.Pointer(&masterUpstream))
		if err != nil {
			return fmt.Errorf("err SetP master: %s", err)
		}
		for n, upstream := range record.Upstream {
			k.Slave = uint8(n + 1)
			err := tbl.SetP(unsafe.Pointer(&k), unsafe.Pointer(&upstream))
			if err != nil {
				return fmt.Errorf("err SetP upstream: %s", err)
			}
		}
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
	cfg := &struct {
		Address string `yaml:"address"`
		Port    uint16 `yaml:"port"`
	}{}
	err := unmarshal(&cfg)
	if err != nil {
		return err
	}

	addr, err := net.ResolveIPAddr("ip", cfg.Address)
	if err != nil {
		return fmt.Errorf("could not resolve addr %s: %s", cfg.Address, err)
	}
	newUpstream := Upstream{
		Address: byteorder.HtonIP(addr.IP),
		Port:    byteorder.Htons(cfg.Port),
		Count:   0,
	}
	*u = newUpstream
	return nil
}

// UnmarshalYAML translates the yaml types to internal C types
func (o *LBOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tcAction, strategy uint8
	cfg := &struct {
		TCAction string `yaml:"tc_action"`
		Strategy string `yaml:"strategy"`
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
	if cfg.Strategy == "src-port" || cfg.Strategy == "" {
		strategy = 0
	} else if cfg.Strategy == "src-ip" {
		strategy = 1
	} else if cfg.Strategy == "udp:" {

	} else {
		return fmt.Errorf("invalid strategy value: %s", cfg.Strategy)
	}
	opt := LBOption{
		TCAction: tcAction,
		Strategy: strategy,
	}
	*o = opt
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
