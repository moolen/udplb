#define KBUILD_MODNAME "udplb"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define PROTO_UDP 17
#define LB_MAP_MAX_ENTRIES 256

// # Example to find a upstream
//
// incoming packet:
//
//   saddr: 1.1.1.1
//   sport: 81732
//   daddr: 2.2.2.2
//   dport: 8125
//
//  available upstreams:
//    7.7.7.7:8125
//    8.8.8.8:8125
//
// lookup-mechanics:
//
//  lb_key struct: <src-ip>/<dest-port>/<slave>
//  lb_upstream struct: <dest-ip>/<dest-port>/<count>
//
//   first: lookup: "master". slave=0 is a master by definition.
//   KEY: [2.2.2.2/8125/0]
//   VAL: [0/0/2] <-- 2 is the count. this means we have 2 upstreams available.
//
//   second: hash incoming packet w/ slave count
//   slave_nr = ( udp->source % count) + 1
//
//   3rd: lookup upstream
//   let's assume slave_nr = 2
//   KEY: [2.2.2.2:8125/2]
//   VAL: [8.8.8.8:8125]
//
struct lb_key {
    __be32 address;
    __be16 port;
    __u8 slave
} __attribute__((packed));

struct lb_upstream {
    __be32 target;
    __be16 port;
    __u8 count; // 0 is the master "service". the actual upstreams are stored in count=N (1-indexed)
    __u8 tc_action;
} __attribute__((packed));

BPF_HASH(upstreams, struct lb_key, struct lb_upstream, LB_MAP_MAX_ENTRIES);

// L3/L4 offsets
#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest ))
#define L4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

// tries to find an upstream for the given packet
// returns an upstream pointer or NULL
static inline struct lb_upstream *lookup_upstream(struct __sk_buff *skb)
{
    struct lb_key key = {};
    struct lb_upstream *master;
    struct lb_upstream *slave;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return NULL;
    }

    // only IP packets are allowed
    if (eth->h_proto != htons(ETH_P_IP)){
        return NULL;
    }

    // only UDP
    if (ip->protocol != PROTO_UDP){
        return NULL;
    }

    key.address = ip->daddr;
    key.port = udp->dest;
    key.slave = 0;
    #ifdef DEBUG
    bpf_trace_printk("lookup master at %lu %lu\n", key.address, key.port);
    #endif
    master = upstreams.lookup(&key);

    if (master) {
        #ifdef DEBUG
        bpf_trace_printk("found master at %lu %lu\n", key.address, key.port);
        bpf_trace_printk("master count: %lu\n", master->count);
        #endif
        // we do not need a 4-tuple hash, since udp is not connection-oriented
        // for now, we'll just use the soure-port
        __u16 slave_idx = (udp->source % master->count) + 1;
        key.slave = slave_idx;
        slave = upstreams.lookup(&key);
        if (slave == 0){
            #ifdef DEBUG
            bpf_trace_printk("slave lookup failed\n");
            bpf_trace_printk("slave key: addr= %lu %lu port= %lu\n", key.address, key.port);
            bpf_trace_printk("slave count: %lu\n", key.slave);
            #endif
            return NULL;
        }
        return slave;
    }
    return NULL;
}

// mutates the given packet buffer: set L2-L4 fields, recalculate checksums
// if fwd_packet is true, we'll clone and forward the packet
// returns 0 on success, negative on failure
static inline int mutate_packet(struct __sk_buff *skb, __be32 target_addr, __be16 target_port, bool fwd_packet)
{
    int ret;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    struct bpf_fib_lookup fib_params;

    // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return -1;
    }

    // only IP packets are allowed
    if (eth->h_proto != htons(ETH_P_IP)){
        return -1;
    }

    // grab original destination addr
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __be16 dst_port = udp->dest;

    if (fwd_packet) {
        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.family       = AF_INET;
        fib_params.tos          = ip->tos;
        fib_params.l4_protocol  = ip->protocol;
        fib_params.sport        = 0;
        fib_params.dport        = 0;
        fib_params.tot_len      = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src     = src_ip;
        fib_params.ipv4_dst     = target_addr;
        fib_params.ifindex      = skb->ingress_ifindex;

        ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);

        if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
            #ifdef DEBUG
            bpf_trace_printk("fib lookup result: %lu\n", ret);
            bpf_trace_printk("fib lookup src_ip= %lu dst_ip= %lu\n", src_ip, target_addr);
            #endif
            return -1;
        }

        // set smac/dmac addr
        bpf_skb_store_bytes(skb, 0, &fib_params.dmac, sizeof(fib_params.dmac), 0);
        bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, sizeof(fib_params.smac), 0);
    }
    #ifdef DEBUG
    bpf_trace_printk("csum rewrite dst_ip= %lu target_addr= %lu\n", dst_ip, target_addr);
    bpf_trace_printk("csum rewrite src_ip= %lu dst_ip= %lu\n", src_ip, dst_ip);
    bpf_trace_printk("csum rewrite dst_port= %lu target_port= %lu\n", dst_port, target_port);
    #endif

    // recalc checksum
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_ip, target_addr, sizeof(target_addr));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_port, target_port, sizeof(target_port));
	bpf_l3_csum_replace(skb, L3_CSUM_OFF, dst_ip, target_addr, sizeof(target_addr));
	bpf_l3_csum_replace(skb, L3_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));

    // set src/dst addr
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &target_addr, sizeof(target_addr), 0);
    bpf_skb_store_bytes(skb, L4_PORT_OFF, &target_port, sizeof(target_port), 0);

    if (fwd_packet){
        // clone packet, put it on interface found in fib
        return bpf_clone_redirect(skb, fib_params.ifindex, 0);
    }
    return 0;
}

// forwards a packet to the given upstream
// returns an TC_ACT_*
static inline int fwd_upstream(struct __sk_buff *skb, struct lb_upstream *upstream)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    struct bpf_fib_lookup fib_params;

    // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return -1;
    }

    // only IP packets are allowed
    if (eth->h_proto != htons(ETH_P_IP)){
        return -1;
    }

    // grab original destination addr
    __u32 dest_ip = ip->daddr;
    __u16 dest_port = udp->dest;

    // change packet destination, and forward it
    int ret = mutate_packet(skb, upstream->target, upstream->port, true);
    if (ret < 0) {
        #ifdef DEBUG
        bpf_trace_printk("fwd packet error: %lu\n", ret);
        #endif
        return -1;
    }

    // if we want to pass the packet to userspace
    // we got to re-set the daddr and port but we do not need to forward it to a interface
    // we just return TC_ACT_OK and hand it over to the kernel
    if (upstream->tc_action == TC_ACT_OK){
        #ifdef DEBUG
        bpf_trace_printk("preparing packet for userspace\n");
        #endif
        ret = mutate_packet(skb, dest_ip, dest_port, false);
        #ifdef DEBUG
        if (ret < 0){
            bpf_trace_printk("userspace fwd packet error: %lu\n", ret);
            return -1;
        }
        bpf_trace_printk("packet successfully prepared for userspace\n");
        #endif
    }
    return upstream->tc_action;
}

// main entrypoint
// returns TC_ACT_*
int ingress(struct __sk_buff *skb) {
    struct lb_upstream *upstream;
    upstream = lookup_upstream(skb);
    if (upstream == NULL){
        return TC_ACT_OK;
    }
    if (upstream){
        #ifdef DEBUG
        bpf_trace_printk("found upstream, forwarding packet\n");
        #endif
        return fwd_upstream(skb, upstream);
    }
    bpf_trace_printk("no upstream: %lu\n", upstream);
    return TC_ACT_OK;
}
