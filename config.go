package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Key must match C struct lb_key
type Key struct {
	Address [4]byte
	Port    [2]byte
	Slave   uint8
}

// Upstream must match C struct lb_upstream
type Upstream struct {
	Address  [4]byte
	Port     [2]byte
	Count    uint8
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
		Address: htonIP(net.ParseIP(cfg.Address)),
		Port:    htons(uint16(cfg.Port)),
	}
	*k = newKey
	return nil
}

// IP returns the net.IP address of the key
func (k *Key) IP() net.IP {
	return ntohIP(k.Address[:])
}

func (k *Key) String() string {
	return fmt.Sprintf("Key{ Address: %s, Port: %d, Slave: %d } ", k.IP(), ntohs(k.Port[:]), k.Slave)
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
		Address:  htonIP(net.ParseIP(cfg.Address)),
		Port:     htons(cfg.Port),
		Count:    0,
		TCAction: tcAction,
	}
	*u = newUpstream
	return nil
}

// IP returns the net.IP address of the upstream
func (u *Upstream) IP() net.IP {
	return ntohIP(u.Address[:])
}

func (u *Upstream) String() string {
	return fmt.Sprintf("Upstream{ Address: %s, Port: %d, Count: %d, Action: %d } ", u.IP(), ntohs(u.Port[:]), u.Count, u.TCAction)
}
