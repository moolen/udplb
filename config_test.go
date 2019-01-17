package main

import (
	"bytes"
	"testing"
)

const config = `
- key:
    address: 127.0.0.1
    port: 8125
    proto: 17
  upstream:
    - address: 172.17.0.2
      port: 8125
    - address: 172.17.0.3
      port: 8125
`

func TestConfig(t *testing.T) {
	rd := bytes.NewBufferString(config)
	cfg, err := NewConfigYaml(rd)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", cfg)
}
