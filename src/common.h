/* This common.h is used by both XDP and TC programs */
#ifndef __PROJ_COMMON_H
#define __PROJ_COMMON_H

/*
 * Map files shared between TC and XDP program, are due to iproute2
 * limitations, located under /sys/fs/bpf/tc/globals/
 */
#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

static const char *file_txq_config = BASEDIR_MAPS "/map_txq_config";
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

#endif /* __PROJ_COMMON_H */
