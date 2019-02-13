//#include <linux/types.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define u16 __u16
#define u32 __u32
#define u64 __u64

/* Interface direction WARNING - sync with _user.c */
#define INTERFACE_WAN      (1 << 0)
#define INTERFACE_LAN      (1 << 1)

#define DEBUG

#define MAX_CPUS 64 /* WARNING - sync with _user.c */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map = {
	.type		= BPF_MAP_TYPE_CPUMAP,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(u32),
	.max_entries	= MAX_CPUS,
};
struct bpf_map_def SEC("maps") ip_hash = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 50000,
};
struct bpf_map_def SEC("maps") cpus_available = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .key_size       = sizeof(u32),
        .value_size     = sizeof(u32),
        .max_entries    = MAX_CPUS,
};
struct bpf_map_def SEC("maps") cpus_count = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(u32),
	.max_entries	= 1,
};
struct bpf_map_def SEC("maps") cpu_direction = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 100,
};

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;
	bpf_debug("Debug: eth_type:0x%x\n", bpf_ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if (bpf_ntohs(eth_type) < ETH_P_802_3_MIN)
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = bpf_ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

static __always_inline
u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset, u32 ifindex)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	u32 *direction_lookup;
	u32 direction;
	u32 ip; /* type need to match map */
	u32 *cpu_idx_lookup;
	u32 cpu_idx;
	u32 *cpu_lookup;
	u32 cpu_dest;
	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_PASS;
	}
	/* Wan of lan interface? */
	direction_lookup = bpf_map_lookup_elem(&cpu_direction, &ifindex);
	if (!direction_lookup)
		return XDP_PASS;
	direction = *direction_lookup;
	/* Extract key */
	if (direction == INTERFACE_WAN) {
		ip = iph->daddr;
	} else if (direction == INTERFACE_LAN) {
		ip = iph->saddr;
	} else {
		return XDP_PASS;
	}

	bpf_debug("Valid IPv4 packet: raw saddr:0x%x\n", ip);

	cpu_idx_lookup = bpf_map_lookup_elem(&ip_hash, &ip);
	if (!cpu_idx_lookup) {
		bpf_debug("cant find cpu_idx_lookup\n");
		// 0.0.0.0 is for default traffic
		ip = bpf_ntohl(0);
		cpu_idx_lookup = bpf_map_lookup_elem(&ip_hash, &ip);
		if (!cpu_idx_lookup) {
			bpf_debug("cant find default cpu_idx_lookup\n");
			return XDP_PASS;
		}
	}
	cpu_idx = *cpu_idx_lookup;
	bpf_debug("cpu_idx %i\n", cpu_idx);
	cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_lookup) {
		bpf_debug("cant find cpu_lookup\n");
		return XDP_PASS;
	}
	cpu_dest = *cpu_lookup;
	if (cpu_dest >= MAX_CPUS) {
		bpf_debug("cpu_dest to high %i\n",cpu_dest);
		return XDP_PASS;
	}

	bpf_debug("Before redirect\n");
	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
	bpf_debug("After redirect\n");
	//return parse_port(ctx, iph->protocol, iph + 1);
}

static __always_inline
u32 handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset, u32 ifindex)
{
	int test;
	switch (eth_proto) {
	case ETH_P_IP:
		//return parse_ipv4(ctx, l3_offset, ifindex);
		test = parse_ipv4(ctx, l3_offset, ifindex);
		bpf_debug("return from redirect %i\n",test);
		return test;
		break;
	case ETH_P_IPV6: /* Not handler for IPv6 yet*/
	case ETH_P_ARP:  /* Let OS handle ARP */
		/* Fall-through */
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp_prog")
int  xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	__u32 ifindex  = ctx->ingress_ifindex;
	struct ethhdr *eth = data;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 action;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		return XDP_PASS; /* Skip */
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

	action = handle_eth_protocol(ctx, eth_proto, l3_offset, ifindex);
	
        //stats_action_verdict(action);
	return action;
}

char _license[] SEC("license") = "GPL";

