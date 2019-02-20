/* This common.h is used by both XDP and TC programs */
#ifndef __PROJ_COMMON_H
#define __PROJ_COMMON_H

/* Exit return codes */
#define	EXIT_OK			0 /* == EXIT_SUCCESS */
#define EXIT_FAIL		1 /* == EXIT_FAILURE */
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_MAP		20
#define EXIT_FAIL_MAP_KEY	21
#define EXIT_FAIL_MAP_FILE	22
#define EXIT_FAIL_MAP_FS	23
#define EXIT_FAIL_IP		30
#define EXIT_FAIL_CPU		31
#define EXIT_FAIL_BPF		40
#define EXIT_FAIL_BPF_ELF	41
#define EXIT_FAIL_BPF_RELOCATE	42

/*
 * Map files shared between TC and XDP program, are due to iproute2
 * limitations, located under /sys/fs/bpf/tc/globals/
 */
#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

static const char *mapfile_txq_config = BASEDIR_MAPS "/map_txq_config";
static const char *mapfile_ip_hash    = BASEDIR_MAPS "/map_ip_hash";

/*
 * Gotcha need to mount:
 *   mount -t bpf bpf /sys/fs/bpf/
 */

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

#endif /* __PROJ_COMMON_H */
