package main

import (
	"bytes"
	"strings"
	"testing"
)

const testConfigYaml = `
- key:
    address: 127.0.0.1
    port: 8125
  upstream:
    - address: 172.17.0.2
      port: 8125
      tc_action: pass
    - address: 172.17.0.3
      port: 8125
      tc_action: block
`

func TestConfig(t *testing.T) {
	rd := bytes.NewBufferString(testConfigYaml)
	cfg, err := newConfigYaml(rd)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", cfg)

	// assert
	for _, entry := range *cfg {

		// key
		if bytes.Compare(entry.Key.Address[:], []byte{0x7f, 0x0, 0x0, 0x1}) != 0 {
			t.Fatalf("Key.Address does not match. found: %#v", entry.Key.Address)
		}
		if bytes.Compare(entry.Key.Port[:], []byte{0x1f, 0xbd}) != 0 {
			t.Fatalf("Key.Port does not match. found: %#v", entry.Key.Port)
		}
		if entry.Key.Slave != 0 {
			t.Fatalf("Key.Slave is not 0")
		}
		if strings.Compare(entry.Key.IP().String(), "127.0.0.1") != 0 {
			t.Fatalf("Key.IP() does not return correct address, found: %s", entry.Key.IP().String())
		}

		// upstream
		us1 := entry.Upstream[0]
		us2 := entry.Upstream[1]
		if strings.Compare(us1.IP().String(), "172.17.0.2") != 0 {
			t.Fatalf("us1.IP() does not return correct address, found: %s", us1.IP().String())
		}
		if strings.Compare(us2.IP().String(), "172.17.0.3") != 0 {
			t.Fatalf("us2.IP() does not return correct address, found: %s", us2.IP().String())
		}
		if bytes.Compare(us1.Port[:], []byte{0x1f, 0xbd}) != 0 {
			t.Fatalf("us1.Port does not match. found: %#v", us1.Port)
		}
		if bytes.Compare(us2.Port[:], []byte{0x1f, 0xbd}) != 0 {
			t.Fatalf("us2.Port does not match. found: %#v", us2.Port)
		}
		if us1.TCAction != 0x0 {
			t.Fatalf("us1.TCAction is wrong. found: %#v", us1)
		}
		if us2.TCAction != 0x2 {
			t.Fatalf("us2.TCAction is wrong. found: %#v", us2)
		}
	}

}
