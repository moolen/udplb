package main

import (
	"flag"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
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

var (
	device   string
	debug    bool
	confPath string
)

func main() {
	flag.StringVar(&device, "i", "lo", "network interface")
	flag.BoolVar(&debug, "d", false, "enable debug mode")
	flag.StringVar(&confPath, "c", "", "path to the configuration file")
	flag.Parse()

	log.Infof("cli config: interface=%s, debug=%t", device, debug)
	cfgFile, err := os.Open(confPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := newConfigYaml(cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	source, err := Asset("bpf/ingress.c")
	if err != nil {
		log.Fatal(err)
	}
	llvmArgs := []string{"-w"}
	if debug == true {
		llvmArgs = append(llvmArgs, "-DDEBUG=1")
		log.SetLevel(log.DebugLevel)
	}
	module := bpf.NewModule(string(source), llvmArgs)
	defer module.Close()
	fd, err := module.LoadNet("ingress")
	if err != nil {
		log.Fatal(err)
	}
	link, err := netlink.LinkByName(device)
	if err != nil {
		log.Fatal(err)
	}
	err = createQdisc(link)
	if err != nil {
		log.Fatal(err)
	}
	defer deleteQdisc(link)
	err = createFilter(fd, "ingress", link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	upstreams := bpf.NewTable(module.TableId("upstreams"), module)
	err = cfg.Apply(upstreams)
	if err != nil {
		log.Fatal(err)
	}

	go updateFIB(*cfg, link)
	<-sig
}
