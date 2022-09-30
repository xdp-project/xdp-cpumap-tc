/* This common_kern_user.h is used by BPF-progs (both XDP and TC) and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/in6.h>

/* Interface (ifindex) direction type */
#define INTERFACE_NONE	0	/* Not configured */
#define INTERFACE_WAN	(1 << 0)
#define INTERFACE_LAN	(1 << 1)

#define MAX_CPUS 64

/* This ifindex limit is an artifical limit that can easily be bumped.
 * The reason for this is allowing to use a faster BPF_MAP_TYPE_ARRAY
 * in fast-path lookups.
 */
#define MAX_IFINDEX 256

/* Data structure used for map_txq_config */
struct txq_config {
	/* lookup key: __u32 cpu; */
	__u16 queue_mapping;
	__u16 htb_major;
};

#define IP_HASH_ENTRIES_MAX	32767
/* Data structure used for map_ip_hash */
struct ip_hash_info {
	/* lookup key: __u32 IPv4-address */
	__u32 cpu;
	__u32 tc_handle; /* TC handle MAJOR:MINOR combined in __u32 */
};

/* Key type used for map_ip_hash trie */
struct ip_hash_key {
	__u32 prefixlen; /* Length of the prefix to match */
	struct in6_addr address; /* An IPv6 address. IPv4 uses the last 32 bits. */
};

#endif /* __COMMON_KERN_USER_H */
