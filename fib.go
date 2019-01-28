package main

import (
	"bytes"
	"time"

	"github.com/j-keck/arping"
	"github.com/prometheus/common/log"
	"github.com/vishvananda/netlink"
)

// we need to keep the fib table up to date
// otherwise eBPF fib_lookup will fail and packets will not be forwarded
func updateFIB(cfg config, link netlink.Link) {
	for {
		select {
		default:
			neighList, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			if err != nil {
				log.Warnf("err fetching neighbors: %s", err)
			}
			for _, entry := range cfg {
				for _, u := range entry.Upstream {
					updateNeigh(u, link, neighList)
				}
			}
			<-time.After(2 * time.Second)
		}
	}
}

// updateNeigh issues an arp request to find out the hw address of the destination ip
// the kernel does not touch the fib tables automatically, we have to tell him the new address
func updateNeigh(u Upstream, link netlink.Link, neighList []netlink.Neigh) {
	log.Debugf("fetching upstream's hw address %s", u.IP())
	hw, _, err := arping.Ping(u.IP())
	if err != nil {
		log.Warnf("error ping %s: %s", u.IP(), err)
		return
	}
	log.Debugf("found hw addr: %s", hw)
	for _, neigh := range neighList {
		if neigh.IP.Equal(u.IP()) {
			log.Debugf("found match: %v", neigh)
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
			log.Debugf("updated hw: %v", neigh)
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
