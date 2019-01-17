#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define PROTO_UDP 17
#define LB_MAP_MAX_ENTRIES 256

// provided by us at compile-time
//#define TC_PKG_ACTION;

// # Example to find an upstream
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
//   first: lookup: "master" service. We only care about the count!
//   KEY: [2.2.2.2:8125/0]
//   VAL: [0/0/2] <-- N is the count.
//
//   2nd: hash incoming packet w/ count
//   slave_nr: (hash(skb) % count) + 1
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
} __attribute__((packed));

BPF_HASH(upstreams, struct lb_key, struct lb_upstream, LB_MAP_MAX_ENTRIES);

#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest ))
#define L4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

#define SKIP_PACKET -1

//
//
//
static inline struct lb_upstream *lookup_upstream(struct __sk_buff *skb)
{
    struct lb_key key = {};
    struct lb_upstream *master; // "master" is used for only count lookup
    struct lb_upstream *slave;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
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

    master = upstreams.lookup(&key);

    if (master) {
#ifdef DEBUG
        bpf_trace_printk("found master at %lu %lu\n", key.address, key.port);
        bpf_trace_printk("master count: %lu\n", master->count);
#endif
        uint32_t hash = bpf_get_hash_recalc(skb);
        __u16 slave_idx = (hash % master->count) + 1;
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

//
//
//
static inline int fwd_upstream(struct __sk_buff *skb, struct lb_upstream *upstream)
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

    bpf_trace_printk("src addr: %lu\n", ip->saddr);
    bpf_trace_printk("target: %lu %lu\n", upstream->target, dst_port);

    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family       = AF_INET;
    fib_params.tos          = ip->tos;
    fib_params.l4_protocol  = ip->protocol;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = bpf_ntohs(ip->tot_len);
    fib_params.ipv4_src     = src_ip;
    fib_params.ipv4_dst     = upstream->target;
    fib_params.ifindex      = skb->ingress_ifindex;

    ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);

    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
#ifdef DEBUG
        bpf_trace_printk("fib lookup result: %lu\n", ret);
#endif
        return -1;
    }

    // set smac/dmac addr
    bpf_skb_store_bytes(skb, 0, &fib_params.dmac, sizeof(fib_params.dmac), 0);
    bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, sizeof(fib_params.smac), 0);

    // recalc checksum
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_ip, upstream->target, sizeof(upstream->target));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_port, upstream->port, sizeof(upstream->port));
	bpf_l3_csum_replace(skb, L3_CSUM_OFF, dst_ip, upstream->target, sizeof(upstream->target));
	bpf_l3_csum_replace(skb, L3_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));

    // set src/dst addr
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &upstream->target, sizeof(upstream->target), 0);
    bpf_skb_store_bytes(skb, L4_PORT_OFF, &upstream->port, sizeof(upstream->port), 0);

    // clone packet, put it on interface found in fib
    ret = bpf_clone_redirect(skb, fib_params.ifindex, 0);
#ifdef DEBUG
    bpf_trace_printk("clone redirect: %lu\n", ret);
#endif
    return 0;
}

//
//
//
int ingress(struct __sk_buff *skb) {
    struct lb_upstream *upstream;
    upstream = lookup_upstream(skb);
    if (upstream == NULL){
        return TC_ACT_OK;
    }
    if (upstream){
#ifdef DEBUG
        bpf_trace_printk("found upstream\n");
#endif
        int ret = fwd_upstream(skb, upstream);
        if (ret == 0) {
#ifdef DEBUG
            bpf_trace_printk("fwd succeesful\n");
#endif
            return TC_ACT_OK;
        }
#ifdef DEBUG
        bpf_trace_printk("fwd failed\n");
#endif
        return TC_ACT_OK;
    }
    bpf_trace_printk("no upstream: %lu\n", upstream);
    return TC_ACT_OK;
}
