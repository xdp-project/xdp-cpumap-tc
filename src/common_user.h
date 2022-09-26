/* This common_user.h is used by userspace programs.
 */
#ifndef __COMMON_USER_H
#define __COMMON_USER_H

extern int verbose; /* common_user.c */

/* Also see: #include "common_kern_user.h" */

/* Exit return codes */
#define	EXIT_OK			0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
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
/* Basedir due to iproute2 use this path */
#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

extern const char *mapfile_txq_config; /* located in common_user.c */
extern const char *mapfile_ip_hash;
extern const char *mapfile_ifindex_type;
extern const char *mapfile_cpu_map;
/*
 * Gotcha need to mount:
 *   mount -t bpf bpf /sys/fs/bpf/
 */

/* iphash_modify operations */
#define ACTION_ADD	(1 << 0)
#define ACTION_DEL	(1 << 1)

int iphash_modify(int fd, char *ip_string, unsigned int action,
		  __u32 cpu_idx, __u32 tc_handle, int txq_map_fd);

bool locate_kern_object(char *execname, char *filename, size_t size);

#define BPF_DIR_MNT	"/sys/fs/bpf"
int bpf_fs_check();
int bpf_fs_check_and_fix();

bool map_txq_config_list_setup(int map_fd);
bool map_txq_config_base_setup (int map_fd);

struct ip_hash_info; /* to use #include "common_kern_user.h" */
bool map_txq_config_check_ip_info(int map_fd, struct ip_hash_info *ip_info);

int tc_egress_attach_bpf(const char* dev, const char* bpf_obj,
			 const char* sec_name);
int tc_list_egress_filter(const char* dev);
int tc_remove_egress_filter(const char* dev);;

#endif /* __COMMON_USER_H */
