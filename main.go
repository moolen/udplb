package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/j-keck/arping"

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

func main() {
	var device string
	var debug bool

	flag.StringVar(&device, "i", "lo", "network interface")
	flag.BoolVar(&debug, "d", false, "enable debug mode")
	flag.Parse()

	log.Infof("cli config: interface=%s, debug=%b", device, debug)
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	cfgFile, err := os.Open(path.Join(dir, "config.yaml"))
	if err != nil {
		panic(err)
	}
	cfg, err := newConfigYaml(cfgFile)
	if err != nil {
		panic(err)
	}
	source, err := ioutil.ReadFile(path.Join(dir, "bpf", "ingress.c"))
	if err != nil {
		panic(err)
	}
	llvmArgs := []string{"-w"}
	if debug == true {
		llvmArgs = append(llvmArgs, "-DDEBUG=1")
	}
	module := bpf.NewModule(string(source), llvmArgs)
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

	go pollUpstream(ctx, *cfg, link)
	<-sig
	ctx.Done()
	cancel()
}

// we need to keep the fib table up to date
// otherwise eBPF fib_lookup will fail and packets will not be forwarded
func pollUpstream(ctx context.Context, cfg config, link netlink.Link) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			neighList, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			if err != nil {
				log.Warnf("err fetching neighbors: %s", err)
			}
			for _, entry := range cfg {
				for _, u := range entry.Upstream {
					updateUpstream(u, link, neighList)
				}
			}

			<-time.After(10 * time.Second)
		}
	}
}

// updateUpstream issues an arp request to find out the
// hw address of the destination ip
// the kernel does not touch the fib tables automatically
// we have to tell him the new address
func updateUpstream(u Upstream, link netlink.Link, neighList []netlink.Neigh) {
	log.Debugf("fetching upstream's hw address %s", u.IP())
	hw, _, err := arping.Ping(u.IP())
	if err != nil {
		log.Warnf("arp err: %s", err)
		return
	}
	log.Debugf("found hw addr: %s", hw)
	for _, neigh := range neighList {
		if neigh.IP.Equal(u.IP()) {
			log.Debugf("found match: %s", neigh)
			if bytes.Equal(neigh.HardwareAddr, hw) {
				log.Debugf("hw addr is up to date")
				return
			}
			neigh.HardwareAddr = hw
			err = netlink.NeighSet(&neigh)
			if err != nil {
				log.Warnf("err: %s", err)
				return
			}
			log.Debugf("updated hw: %s", neigh)
			return
		}
	}
	err = netlink.NeighAdd(&netlink.Neigh{
		Family:       netlink.FAMILY_V4,
		HardwareAddr: hw,
		IP:           u.IP(),
		LinkIndex:    link.Attrs().Index,
	})
	if err != nil {
		log.Warnf("err: %s", err)
	}
	log.Debugf("added hw: %s", hw)
}
