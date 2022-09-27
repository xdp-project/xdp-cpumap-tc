#define DEBUG 1
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/in6.h>

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"
#include "shared_maps.h"

/* More dynamic: let create a map that contains the mapping table, to
 * allow more dynamic configuration. (See common.h for struct txq_config)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct txq_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} map_txq_config SEC(".maps");

/* Manuel setup:

 tc qdisc  del dev ixgbe2 clsact # clears all
 tc qdisc  add dev ixgbe2 clsact
 tc filter add dev ixgbe2 egress bpf da obj tc_classify_kern.o sec tc
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
void get_ipv4_addr(struct __sk_buff *skb, __u32 l3_offset, __u32 ifindex_type,
		struct ip_hash_key *key)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct iphdr *iph = data + l3_offset;
	__u32 ipv4 = 0;

	if (iph + 1 > data_end) {
		//bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return;
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
	key->address.in6_u.u6_addr32[3] = ipv4;
}


static __always_inline
void get_ipv6_addr(struct __sk_buff *skb, __u32 l3_offset, __u32 ifindex_type,
		struct ip_hash_key *key)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ipv6hdr *ip6h = data + l3_offset;

	if (ip6h + 1 > data_end) {
		//bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
		return;
	}

	/* The IP-addr to match against depend on the "direction" of
	 * the packet.  This TC hook runs at egress.
	 */
	switch (ifindex_type) {
	case INTERFACE_WAN: /* Egress on WAN interface: match on src IP */
		key->address = ip6h->saddr;
		break;
	case INTERFACE_LAN: /* Egress on LAN interface: match on dst IP */
		key->address = ip6h->daddr;
		break;
	}
}

/* Locahost generated traffic gets assigned a classid MINOR number */
#define DEFAULT_LOCALHOST_MINOR 0x0003
/*
 * Localhost generated traffic, goes into another default qdisc, but
 * need fixup of class MAJOR number to match CPU.
 */
static __always_inline
__u32 localhost_default_classid(struct __sk_buff *skb,
				struct txq_config *txq_cfg)
{
	__u32 cpu_major;

	if (!txq_cfg)
		return TC_ACT_SHOT;

	cpu_major = txq_cfg->htb_major << 16;

	if (skb->priority == 0) {
		skb->priority = cpu_major | DEFAULT_LOCALHOST_MINOR;
	} else {
		/* The classid (via skb->priority) is already set, we
		 * allow this, but update major number (assigned to CPU)
		 */
		__u32 curr_minor = TC_H_MINOR(skb->priority);

		skb->priority = cpu_major | curr_minor;
	}
	return TC_ACT_OK;
}

/* Special types of traffic exists.
 *
 * Like LAN-to-LAN or WAN-to-WAN traffic.  The LAN-to-LAN traffic can
 * also be between different VLANS, thus it is not possible to
 * identify this via comparing skb->ifindex and skb->ingress_ifindex.
 *
 * Instead allow other filters (e.g. iptables -t mangle -j CLASSIFY)
 * to set the TC-handle/classid (in skb->priority) and match the
 * special TC-minor classid here.
 */
#define SPECIAL_MINOR_CLASSID_LOW  3
#define SPECIAL_MINOR_CLASSID_HIGH 9
static __always_inline
bool special_minor_classid(struct __sk_buff *skb,
			   struct txq_config *txq_cfg)
{
	__u32 curr_minor;

	if (!txq_cfg)
		return false;

	if (skb->priority == 0)
		return false; /* no special pre-set classid */

	curr_minor = TC_H_MINOR(skb->priority);

	if (curr_minor >= SPECIAL_MINOR_CLASSID_LOW &&
	    curr_minor <= SPECIAL_MINOR_CLASSID_HIGH) {
		/* The classid (via skb->priority) was already set
		 * with a special minor-classid, but update major
		 * number assigned to this CPU
		 */
		__u32 cpu_major  = txq_cfg->htb_major << 16;

		skb->priority = cpu_major | curr_minor;
		return true;
	}
	return false;
}

/* Quick manual reload command:
 tc filter replace dev ixgbe2 prio 0xC000 handle 1 egress bpf da obj tc_classify_kern.o sec tc
 */
SEC("tc")
int tc_iphash_to_cpu(struct __sk_buff *skb)
{
	__u32 cpu = bpf_get_smp_processor_id();
	struct ip_hash_info *ip_info;
	struct txq_config *txq_cfg;
	__u32 *ifindex_type;
	__u32 ifindex;
	__u32 action = TC_ACT_OK;

	/* For packet parsing */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	__u16 eth_proto = 0;
	__u32 l3_offset = 0;
	//__u32 ipv4 = bpf_ntohl(0xFFFFFFFF); // default not found
	struct ip_hash_key hash_key;

	txq_cfg = bpf_map_lookup_elem(&map_txq_config, &cpu);
        if (!txq_cfg)
                return TC_ACT_SHOT;

	if (txq_cfg->queue_mapping != 0) {
		skb->queue_mapping = txq_cfg->queue_mapping;
	} else {
		bpf_debug("Misconf: CPU:%u no conf (curr qm:%d)\n",
			  cpu, skb->queue_mapping);
	}

	/* Localhost generated traffic, goes into another default qdisc */
	if (skb->ingress_ifindex == 0) {
		return localhost_default_classid(skb, txq_cfg);
	}

	if (special_minor_classid(skb, txq_cfg)) {
		/* SKB was pre-marked with special class id */
		return TC_ACT_OK;
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

	/* Get interface "direction" via map_ifindex_type */
	ifindex = skb->ifindex;
	ifindex_type = bpf_map_lookup_elem(&map_ifindex_type, &ifindex);
	if (!ifindex_type)
		return TC_ACT_OK;

	/* Get IP addr to match against */
        hash_key.prefixlen = 128;
        hash_key.address.in6_u.u6_addr32[0] = 0xFFFFFFFF;
        hash_key.address.in6_u.u6_addr32[1] = 0xFFFFFFFF;
        hash_key.address.in6_u.u6_addr32[2] = 0xFFFFFFFF;
        hash_key.address.in6_u.u6_addr32[3] = 0xFFFFFFFF;
	switch (eth_proto) {
	case ETH_P_IP:
		get_ipv4_addr(skb, l3_offset, *ifindex_type, &hash_key);
		break;
	case ETH_P_IPV6: 
		get_ipv6_addr(skb, l3_offset, *ifindex_type, &hash_key);
		break;
	case ETH_P_ARP:  /* Let OS handle ARP */
		// TODO: Should we choose a special classid for these?
		/* Fall-through */
	default:
		// bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return TC_ACT_OK;
	}

	ip_info = bpf_map_lookup_elem(&map_ip_hash, &hash_key);
	if (!ip_info) {
		/* Check for 255.255.255.255/32 as a default if no 0.0.0.0/0 is provided */
		hash_key.prefixlen = 128;
		hash_key.address.in6_u.u6_addr32[3] = 0xFFFFFFFF;
		ip_info = bpf_map_lookup_elem(&map_ip_hash, &hash_key);
		if (!ip_info) {
			bpf_debug("Misconf: FAILED lookup IP:0x%x ifindex_ingress:%d prio:%x\n",
				  hash_key.address.in6_u.u6_addr32[3], skb->ingress_ifindex, skb->priority);
			// TODO: Assign to some default classid?
			return TC_ACT_OK;
		}
	}

	if (ip_info->cpu != cpu) {
		bpf_debug("Mismatch: Curr-CPU:%u but IP:%x wants CPU:%u\n",
			  cpu, hash_key.address.in6_u.u6_addr32[3], ip_info->cpu);
		bpf_debug("Mismatch: more-info ifindex:%d ingress:%d skb->prio:%x\n",
			  skb->ifindex, skb->ingress_ifindex, skb->priority);
	}

	/* Catch if TC handle major number mismatch, between CPU
	 * config and ip_info config.
	 * TODO: Can this be done setup time?
	 */
	__u16 ip_info_major = (TC_H_MAJOR(ip_info->tc_handle) >> 16);
	if (txq_cfg->htb_major != ip_info_major)
	{
		// TODO: Could fixup MAJOR number
		bpf_debug("Misconf: TC major(%d) mismatch %x\n",
			  txq_cfg->htb_major, ip_info->tc_handle);
	}

	/* Setup skb->priority (TC-handle) based on ip_info */
	if (ip_info->tc_handle != 0)
		skb->priority = ip_info->tc_handle;

	//bpf_debug("Lookup IP:%x prio:0x%x tc_handle:0x%x\n",
	//	  ipv4, skb->priority, ip_info->tc_handle);

	//return TC_ACT_OK;
	return action;
}

char _license[] SEC("license") = "GPL";
