//#include <linux/types.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "common_kern_user.h"

#define DEBUG

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Pinned shared map: see  mapfile_ip_hash */
struct bpf_map_def SEC("maps") map_ip_hash = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct in6_addr),
	.value_size  = sizeof(struct ip_hash_info),
	.max_entries = IP_HASH_ENTRIES_MAX,
};

/* Pinned shared map: see  mapfile_txq_config */
struct bpf_map_def SEC("maps") map_txq_config = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct txq_config),
	.max_entries = MAX_CPUS,
};

/* Pinned shared map: see  mapfile_ifindex_type */
struct bpf_map_def SEC("maps") map_ifindex_type = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = MAX_IFINDEX,
};

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map = {
	.type		= BPF_MAP_TYPE_CPUMAP,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_available = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .key_size       = sizeof(__u32),
        .value_size     = sizeof(__u32),
        .max_entries    = MAX_CPUS,
};

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = "(xdp) " fmt;			\
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
	       __u16 *eth_proto, __u32 *l3_offset)
{
	__u16 eth_type;
	__u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

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

static __always_inline struct ip_hash_info *get_ip_info(struct in6_addr *ip)
{
	struct ip_hash_info *ip_info;

	ip_info = bpf_map_lookup_elem(&map_ip_hash, ip);
	if (!ip_info) {
		struct in6_addr nulladdr = {};
		/* On LAN side (XDP-ingress) some uncategorized traffic are
		 * expected, e.g. services like DHCP are running and IPs
		 * contacting captive portal (which are not yet configured)
		 */
		// bpf_debug("cant find ip_info->cpu id for ip:%u\n", ip);
		// the all-zeroes address is for default traffic
		ip_info = bpf_map_lookup_elem(&map_ip_hash, &nulladdr);
	}
	return ip_info;
}

static __always_inline
__u32 parse_ip(struct xdp_md *ctx, __u32 l3_offset, __u32 ifindex, __u16 eth_proto)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	/* aliases pointers used for v4/v6 based on version */
	struct iphdr *iph = data + l3_offset;
	struct ipv6hdr *ip6h = data + l3_offset;
	__u32 *direction_lookup;
	__u32 direction;
	struct ip_hash_info *ip_info;
	//u32 *cpu_id_lookup;
	__u32 cpu_id;
	__u32 *cpu_lookup;
	__u32 cpu_dest;

	struct in6_addr ip = {};

	/* WAN or LAN interface? */
	direction_lookup = bpf_map_lookup_elem(&map_ifindex_type, &ifindex);
	if (!direction_lookup)
		return XDP_PASS;
	direction = *direction_lookup;
	if (direction != INTERFACE_WAN && direction != INTERFACE_LAN) {
		bpf_debug("Cant determin ifindex(%u) direction\n", ifindex);
		return XDP_PASS;
	}

	/* we know it's v4 or v6, so just check the version field of the IP
	 * header itself
	 */
	if (eth_proto == ETH_P_IP) {
		/* Hint: +1 is sizeof(struct iphdr) */
		if (iph + 1 > data_end) {
			bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
			return XDP_PASS;
		}

		/* init to a v4-mapped IPv6 address - the last four octets will
		 * be replaced by the v4 address in the IP header below
		 */
		ip.s6_addr16[5] = 0xffff;

		/* Extract key, XDP operate at "ingress" */
		if (direction == INTERFACE_WAN) {
			ip.s6_addr32[3] = iph->daddr;
		} else if (direction == INTERFACE_LAN) {
			ip.s6_addr32[3] = iph->saddr;
		}
	} else {
		if (ip6h + 1 > data_end) {
			bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
			return XDP_PASS;
		}
		if (direction == INTERFACE_WAN)
			ip = ip6h->daddr;
		else if (direction == INTERFACE_LAN)
			ip = ip6h->saddr;
	}

	ip_info = get_ip_info(&ip);
	if (!ip_info) {
		bpf_debug("cant find default cpu_idx_lookup\n");
		return XDP_PASS;
	}
	cpu_id = ip_info->cpu;

	/* The CPUMAP type doesn't allow to bpf_map_lookup_elem (see
	 * verifier.c check_map_func_compatibility()). Thus, maintain
	 * another map that says if a CPU is avail for redirect.
	 */
        cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_id);
	if (!cpu_lookup) {
		bpf_debug("cant find cpu_lookup\n");
		return XDP_PASS;
	}
	cpu_dest = *cpu_lookup;
	if (cpu_dest >= MAX_CPUS) {
		/* _user side set/marked non-configured CPUs with MAX_CPUS */
		bpf_debug("cpu_dest too high %i\n",cpu_dest);
		return XDP_PASS;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

static __always_inline
__u32 handle_eth_protocol(struct xdp_md *ctx, __u16 eth_proto, __u32 l3_offset,
			  __u32 ifindex)
{
	__u32 action;

	switch (eth_proto) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		action = parse_ip(ctx, l3_offset, ifindex, eth_proto);
		//bpf_debug("return from redirect %i\n",test);
		return action;
		break;
	case ETH_P_ARP:  /* Let OS handle ARP */
		/* Fall-through */
	default:
		// ARP traffic is handled locally on RX CPU
		// bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
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
	__u16 eth_proto = 0;
	__u32 l3_offset = 0;
	__u32 action;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		return XDP_PASS; /* Skip */
	}

	action = handle_eth_protocol(ctx, eth_proto, l3_offset, ifindex);

        //stats_action_verdict(action);
	return action;
}

char _license[] SEC("license") = "GPL";
