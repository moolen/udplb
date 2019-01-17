package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/vishvananda/netlink"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func main() {
	var device string

	if len(os.Args) != 2 {
		usage()
	}

	device = os.Args[1]
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	cfgFile, err := os.Open(path.Join(dir, "config.yaml"))
	if err != nil {
		panic(err)
	}
	cfg, err := NewConfigYaml(cfgFile)
	if err != nil {
		panic(err)
	}
	source, err := ioutil.ReadFile(path.Join(dir, "bpf", "ingress.c"))
	if err != nil {
		panic(err)
	}
	module := bpf.NewModule(string(source), []string{
		"-w",
	})
	defer module.Close()
	fd, err := module.LoadNet("ingress")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load sched prog: %v\n", err)
		os.Exit(1)
	}

	link, err := netlink.LinkByName(device)
	if err != nil {
		panic(err)
	}

	err = createQdisc(link)
	if err != nil {
		panic(err)
	}
	defer deleteQdisc(link)

	err = createFilter(fd, "ingress", link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		panic(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	upstreams := bpf.NewTable(module.TableId("upstreams"), module)
	err = cfg.Apply(upstreams)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.TODO())

	go pollUpstream(ctx, *cfg)

	<-sig
	ctx.Done()
	cancel()
}

func pollUpstream(ctx context.Context, cfg Config) {
	for {
		select {
		case <-ctx.Done():
			log.Printf("poll ctx done")
			return
		default:
			for _, entry := range cfg {
				for _, u := range entry.Upstream {
					c, err := net.DialUDP("udp", nil, &net.UDPAddr{
						IP:   u.IP(),
						Port: u.Port,
					})
					if err != nil {
						log.Printf("error opening connection: %v", err)
						continue
					}
					_, err = c.Write([]byte{0})
					if err != nil {
						log.Printf("error writing to connection: %v", err)
						continue
					}
					err = c.Close()
					if err != nil {
						log.Printf("error closing connection: %v", err)
						continue
					}
				}
			}
			<-time.After(10 * time.Second)
		}
	}
}
