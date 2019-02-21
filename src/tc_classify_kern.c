/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <stdbool.h>

#include "bpf_endian.h"
#include "common_kern_user.h"

#include "bpf_helpers.h"

/* Manuel setup:

 tc qdisc  del dev ixgbe2 clsact # clears all
 tc qdisc  add dev ixgbe2 clsact
 tc filter add dev ixgbe2 egress bpf da obj tc_classify_kern.o sec tc_classify
 tc filter list dev ixgbe2 egress

*/

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* iproute2 use another ELF map layout than libbpf.  The PIN_GLOBAL_NS
 * will cause map to be exported to /sys/fs/bpf/tc/globals/
 */
#define PIN_GLOBAL_NS	2
struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

/* Map shared with XDP programs */
struct bpf_elf_map SEC("maps") map_ip_hash = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(__u32),
	.size_value = sizeof(struct ip_hash_info),
	.max_elem   = IP_HASH_ENTRIES_MAX,
        .pinning    = PIN_GLOBAL_NS, /* /sys/fs/bpf/tc/globals/map_ip_hash */
};

/* More dynamic: let create a map that contains the mapping table, to
 * allow more dynamic configuration. (See common.h for struct txq_config)
 */
struct bpf_elf_map SEC("maps") map_txq_config = {
        .type	    = BPF_MAP_TYPE_ARRAY,
        .size_key   = sizeof(__u32),
        .size_value = sizeof(struct txq_config),
        .pinning    = PIN_GLOBAL_NS,/* /sys/fs/bpf/tc/globals/map_txq_config */
        .max_elem   = MAX_CPUS,
};

/* Map shared with XDP programs */
struct bpf_elf_map SEC("maps") map_ifindex_type = {
        .type	    = BPF_MAP_TYPE_ARRAY,
        .size_key   = sizeof(__u32),
        .size_value = sizeof(struct txq_config),
        .pinning    = PIN_GLOBAL_NS,/* /sys/fs/bpf/tc/globals/map_ifindex_type*/
        .max_elem   = MAX_IFINDEX,
};

/*
  CPU config map table (struct txq_config):

  |----------+---------------+-----------+-----------------|
  | Key: CPU | queue_mapping | htb_major | maps-to-MQ-leaf |
  |----------+---------------+-----------+-----------------|
  |        0 |             1 |      100: | 7FFF:1          |
  |        1 |             2 |      101: | 7FFF:2          |
  |        2 |             3 |      102: | 7FFF:3          |
  |        3 |             4 |      103: | 7FFF:4          |
  |----------+---------------+-----------+-----------------|

  Last column "maps-to-MQ-leaf" is not part of config, but illustrates
  that queue_mapping corresponds to MQ-leaf "minor" numbers, assuming
  MQ is created with handle 7FFF, like:

   # tc qdisc replace dev ixgbe2 root handle 7FFF: mq

  The HTB-qdisc major number "handle" is choosen by the user, when
  attaching the HTB qdisc to the MQ-leaf "parent", like:

   # tc qdisc add dev ixgbe2 parent 7FFF:1 handle 100: htb default 2
   # tc qdisc add dev ixgbe2 parent 7FFF:2 handle 101: htb default 2

 */

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = "(tc) " fmt;			\
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Wrap the macros from <linux/pkt_sched.h> */
#define TC_H_MAJOR(x) TC_H_MAJ(x)
#define TC_H_MINOR(x) TC_H_MIN(x)

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

static __always_inline
__u32 get_ipv4_addr(struct __sk_buff *skb, __u32 l3_offset, __u32 ifindex_type)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct iphdr *iph = data + l3_offset;
	__u32 ipv4 = 0;

	if (iph + 1 > data_end) {
		//bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return 0;
	}

	/* The IP-addr to match against depend on the "direction" of
	 * the packet.  This TC hook runs at egress.
	 */
	switch (ifindex_type) {
	case INTERFACE_WAN: /* Egress on WAN interface: match on src IP */
		ipv4 = iph->saddr;
		break;
	case INTERFACE_LAN: /* Egress on LAN interface: match on dst IP */
		ipv4 = iph->daddr;
		break;
	default:
		ipv4 = 0;
	}

	return ipv4;
}

/* Quick manual reload command:
 tc filter replace dev ixgbe2 prio 0xC000 handle 1 egress bpf da obj tc_classify_kern.o sec tc_classify
 */
SEC("tc_classify")
int  tc_cls_prog(struct __sk_buff *skb)
{
	__u32 cpu = bpf_get_smp_processor_id();
	struct ip_hash_info *ip_info;
	struct txq_config *cfg;
	__u32 *ifindex_type;
	__u32 ifindex;
	__u32 action = TC_ACT_OK;

	/* For packet parsing */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	__u16 eth_proto = 0;
	__u32 l3_offset = 0;
	__u32 ipv4 = bpf_ntohl(0xFFFFFFFF); /* default not found */

	cfg = bpf_map_lookup_elem(&map_txq_config, &cpu);
        if (!cfg)
                return TC_ACT_SHOT;

	if (cfg->queue_mapping != 0) {
		skb->queue_mapping = cfg->queue_mapping;
	} else {
		bpf_debug("Misconf: CPU:%u no conf (curr qm:%d)\n",
			  cpu, skb->queue_mapping);
	}

	/* Ethernet header parsing: The protocol is already known via
	 * skb->protocol (host-byte-order). But due to double VLAN
	 * tagging, we still need to parse eth-headers.  The
	 * skb->{vlan_present,vlan_tci} can only show outer VLAN.
	 */
	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		return TC_ACT_OK; /* Skip */
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x skb_proto:0x%x\n",
		  l3_offset, eth_proto, skb->protocol);

	/* Get interface "direction" via map_ifindex_type */
	ifindex = skb->ifindex;
	ifindex_type = bpf_map_lookup_elem(&map_ifindex_type, &ifindex);
	if (!ifindex_type)
		return TC_ACT_OK;

	/* Get IP addr to match against */
	switch (eth_proto) {
	case ETH_P_IP:
		ipv4 = get_ipv4_addr(skb, l3_offset, *ifindex_type);
		if (!ipv4)
			return TC_ACT_OK;
		break;
	case ETH_P_IPV6: /* No handler for IPv6 yet */
	case ETH_P_ARP:  /* Let OS handle ARP */
		// TODO: Should we choose a special classid for these?
		/* Fall-through */
	default:
		// bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return TC_ACT_OK;
	}

	// Just use map_ip_hash for something
	ip_info = bpf_map_lookup_elem(&map_ip_hash, &ipv4);
	if (!ip_info) {
		bpf_debug("Misconf: FAILED lookup IP:%x\n", ipv4);
		// TODO: Assign to some default classid?
		return TC_ACT_OK;
	}

	if (ip_info->cpu != cpu)
		bpf_debug("Mismatch: Curr-CPU:%u but IP:%x wants CPU:%u\n",
			  cpu, ipv4, ip_info->cpu);

	// TODO: Verify that the TC handle major number in
	// skb->priority field is correct.

	// TODO: Control skb->priority (TC-handle)
	if (ip_info->tc_handle != 0)
		skb->priority = ip_info->tc_handle;

	bpf_debug("Lookup IP:%x prio:0x%x tc_handle:0x%x\n",
		  ipv4, skb->priority, ip_info->tc_handle);

	//return TC_ACT_OK;
	return action;
}

char _license[] SEC("license") = "GPL";
