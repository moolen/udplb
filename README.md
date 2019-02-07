# udplb

udplb is a udp load balancer / packer forwarder using eBPF/BCC in the traffic control layer.

## Motivation

There are no implementations or examples available on how to use eBPF/BCC in the traffic control layer with [goBPF](https://github.com/iovisor/gobpf/). Also, i want to provide a starting point to do networking with BCC/goBPF.

## Use-case: UDP Relay
You can use this as a low-level, transparent UDP relay: Incoming UDP packets (matched by destination addr/port) are cloned and sent directly to a different host. The initial packet **goes up the stack** and may be processed from userspace.

## Use-case: UDP Forwarder
You may use this as a UDP packet forwarder: Incoming packets (matching a destination address/port) are being forwarded to a different destination host. the packet will **NOT** be further processed by the kernel.


## Prerequisites

* see [BCC Installation](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* golang

## Usage

use-case: clone incoming traffic

create a `config.yaml` like the following. The configuration describes the following:

* look for packets matching `1.2.3.4:1111`
* send them over to `10.100.53.27:2222`
* let the packet go up the stack (`tc_action: pass`, use `block` to drop the packet)

```yaml
- key:
    address: 1.2.3.4
    port: 1111
  options:
    tc_action: pass # `pass` or `block`
    strategy: src-ip # `src-ip` or `src-port`
  upstream:
    - address: 10.100.53.27
      port: 2222
```

Run udplb, you'll need `NET_ADMIN` and `SYS_ADMIN` privileges:
```
$ sudo ./udplb -d -i ens3
INFO[0000] cli config: interface=ens3, debug=true
INFO[0001] netlink: replacing qdisc for ens3 succeeded
INFO[0001] netlink: successfully added filter for ingress
INFO[0001] Key{ Address: 1.2.3.4, Port: 1111, Slave: 0 }  | Upstream{ Address: 0.0.0.0, Port: 0, Count: 1, Action: 0 }
INFO[0001] Key{ Address: 1.2.3.4, Port: 1111, Slave: 1 }  | Upstream{ Address: 10.100.53.27, Port: 2222, Count: 0, Action: 0 }
[...]
DEBU[0001] fetching upstream's hw address 10.100.53.27
DEBU[0001] found hw addr: 52:54:00:23:a4:5c
DEBU[0001] found match: {2 2 4 1 0 192.168.122.23 52:54:00:23:a4:5c <nil> 0 0}
DEBU[0001] hw addr is up to date
```

What happens here?
* the `config.yaml` will be parsed
* `ingress.c` will be compiled to BPF bytecode and sent to the kernel which validates it
* `tc qdisc` will be created
* `tc filter` will be created
* the associated bpf map will be populated from the `config.yml`
* we'll continuously issue ARP requests and inform the kernel about changes for our upstreams

When we mutate the packet in the tc layer, we can lookup records from the fib (forwarding information base, `IP <-> MAC` lookup) table but we can not issue arp requests from there (and block further processing of the packet). That's why we populate the fib table from userspace.

## Debugging

run udplb with `-d` to enable debug mode. That will compile the eBPF program with debugging `bpf_trace_printk` calls. You can access the logs via the kernel trace pipe.

```
$ sudo tc exec bpf dbg
<idle>-0     [000] ..s1 123062.418577: 0: lookup master at 779790528 48415
<idle>-0     [000] .Ns1 123062.418613: 0: found master at 779790528 48415
<idle>-0     [000] .Ns1 123062.418614: 0: master count: 1
<idle>-0     [000] .Ns1 123062.418618: 0: found upstream, forwarding packet
<idle>-0     [000] .Ns1 123062.418627: 0: csum rewrite dst_ip= 779790528 target_addr= 393914560
<idle>-0     [000] .Ns1 123062.418629: 0: csum rewrite src_ip= 24815808 dst_ip= 779790528
<idle>-0     [000] .Ns1 123062.418631: 0: csum rewrite dst_port= 48415 target_port= 48415
<idle>-0     [000] .Ns1 123062.418771: 0: preparing packet for userspace
<idle>-0     [000] .Ns1 123062.418774: 0: csum rewrite dst_ip= 393914560 target_addr= 779790528
<idle>-0     [000] .Ns1 123062.418776: 0: csum rewrite src_ip= 779790528 dst_ip= 393914560
<idle>-0     [000] .Ns1 123062.418778: 0: csum rewrite dst_port= 48415 target_port= 48415
<idle>-0     [000] .Ns1 123062.418779: 0: packet successfully prepared for userspace
```

What does that mean?
* `48415` is `8125` in network byte order
* `779790528` is `192.168.122.46` in network byte order
* `393914560` is `192.168.122.23` in network byte order
