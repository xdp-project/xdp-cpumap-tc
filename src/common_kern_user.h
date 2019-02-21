/* This common_kern_user.h is used by BPF-progs (both XDP and TC) and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

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

#endif /* __COMMON_KERN_USER_H */
