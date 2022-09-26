#include <linux/types.h> /* __u32 */
#include <stdio.h>       /* fprintf */
#include <string.h>      /* strerror */
#include <unistd.h>      /* access */
#include <stdbool.h>     /* bool */
#include <libgen.h>      /* dirname */
#include <arpa/inet.h>   /* inet_pton */
#include <sys/statfs.h>  /* statfs */
#include <sys/stat.h>    /* stat(2) + S_IRWXU */
#include <sys/mount.h>   /* mount(2) */
#include <netdb.h>

#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */

#include "common_user.h"
#include "common_kern_user.h"

#include "bpf_util.h"

#include <bpf/bpf.h>     /* LIBBPF_API: bpf_map_update_elem */
//#include <linux/bpf.h> /* System kernel-headers, BPF_ANY, but inc by bpf/bpf.h */

int verbose = 1; /* extern in common_user.h */

const char *mapfile_txq_config = BASEDIR_MAPS "/map_txq_config";
const char *mapfile_ip_hash    = BASEDIR_MAPS "/map_ip_hash";
const char *mapfile_ifindex_type = BASEDIR_MAPS "/map_ifindex_type";
const char *mapfile_cpu_map      = BASEDIR_MAPS "/cpu_map";

/* Check consistency between map_txq_config and ip_hash_info that is
 * going to be inserted into ip_hash
 */
bool map_txq_config_check_ip_info(int map_fd, struct ip_hash_info *ip_info) {
	struct txq_config txq_cfg;
	__u16 ip_htb_major;
	__u32 cpu;
	int err;

	if (map_fd < 0) {
		fprintf(stderr, "ERR: (bad map_fd:%d) "
			"cannot proceed without access to txq_config map\n",
			map_fd);
		return false;
	}

	cpu = ip_info->cpu;
	err = bpf_map_lookup_elem(map_fd, &cpu, &txq_cfg);
	if (err) {
		fprintf(stderr,
			"ERR: %s() lookup cpu-key:%d err(%d):%s\n",
			__func__, cpu, errno, strerror(errno));
		return false;
	}

	if (txq_cfg.queue_mapping == 0) {
		fprintf(stderr, "WARN: "
			"Looks like map_txq_config --base-setup is missing\n");
		fprintf(stderr, "WARN: "
			"Fixing, doing map_txq_config --base-setup\n");
		if (!map_txq_config_base_setup(map_fd))
			return false;
		return true; // FIXME, redo check
	}

	ip_htb_major = TC_H_MAJ(ip_info->tc_handle) >> 16;
	if (txq_cfg.htb_major != ip_htb_major) {
		if (verbose)
			fprintf(stderr,
				"WARN: Bad config mismatch "
				"ip handle:0x%X (major:0x%X) "
				"not matching TXQ-config:0x%X\n",
				ip_info->tc_handle, ip_htb_major,
				txq_cfg.htb_major);
		return false;
	}
	return true;
}

struct ip_hash_key ip_string_to_key(char *ip_string) {
	struct ip_hash_key key;
	int res;
	char addr[42]; /* Temporary buffer if parsing IP */

	key.address.__in6_u.__u6_addr32[0] = 0;
        key.address.__in6_u.__u6_addr32[1] = 0;
        key.address.__in6_u.__u6_addr32[2] = 0;
	key.address.__in6_u.__u6_addr32[3] = 0;
	key.prefixlen = 0;

	/* Does the IP string contain a prefix? */
	char * slash_loc = strchr(ip_string, '/');
	if (slash_loc != NULL) {
		char cidr[4];
		memset(&addr, 0, sizeof(addr));
		memset(&cidr, 0, sizeof(cidr));
		strncpy(addr, ip_string, slash_loc - ip_string);
		strncpy(cidr, slash_loc+1, 4);
		key.prefixlen = atoi(cidr);
		ip_string = (char *)&addr;
	}

	struct addrinfo hints = {}, *result;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;
	res = getaddrinfo(ip_string, NULL, &hints, &result);
	if (res < 0) {
		perror("getaddrinfo");
		key.prefixlen = 0; /* Indicates fail */
		return key;
	}

	switch (result->ai_family) {
		case AF_INET:
			key.address.__in6_u.__u6_addr32[3] = ((struct sockaddr_in *) result->ai_addr)->sin_addr.s_addr;
			if (key.prefixlen == 0) {
				key.prefixlen = 128;
			} else {
				key.prefixlen = key.prefixlen + 96;
			}
			break;
		case AF_INET6:
			printf("IPv6\n");
			key.address = ((struct sockaddr_in6 *) result->ai_addr)->sin6_addr;
			if (key.prefixlen == 0) {
				key.prefixlen = 128;
			}
			break;
	}


	freeaddrinfo(result);
	return key;
}

void print_key_binary(struct ip_hash_key *key) {
	if (key->address.__in6_u.__u6_addr32[0] == 0 && key->address.__in6_u.__u6_addr32[1] == 0 && key->address.__in6_u.__u6_addr32[2] == 0) {
		/* It's IPv4 */
		printf("IPv4: 0x%X/%d", key->address.__in6_u.__u6_addr32[3], key->prefixlen);
	} else {
		/* It's an IPv6 address */
		printf("IPv6: 0x%X/0x%X/0x%X/0x%X/%d",  key->address.__in6_u.__u6_addr32[0],
				 key->address.__in6_u.__u6_addr32[1],  key->address.__in6_u.__u6_addr32[2],
				  key->address.__in6_u.__u6_addr32[3], key->prefixlen);
	}
}

int iphash_modify(int fd, char *ip_string, unsigned int action,
		  __u32 cpu_idx, __u32 tc_handle, int txq_map_fd)
{
	//printf ("In iphash_modify %u\n",cpu_idx);
	struct ip_hash_key key;
	int res;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_hash_info ip_info;

	if (cpu_idx+1 > nr_cpus || cpu_idx+1 < 0)
		return EXIT_FAIL_CPU;

	/* Value for the map */
	ip_info.cpu       = cpu_idx;
	ip_info.tc_handle = tc_handle;

	/* Convert IP-string into network byte-order value */
	key = ip_string_to_key(ip_string);
	if (key.prefixlen == 0) {
		return EXIT_FAIL_IP;
	}
	print_key_binary(&key);
	if (action == ACTION_ADD) {
		//res = bpf_map_update_elem(fd, &key, &ip_info, BPF_NOEXIST);
		if (!map_txq_config_check_ip_info(txq_map_fd, &ip_info))
			fprintf(stderr, "Misconf: But allowing to continue\n");
		res = bpf_map_update_elem(fd, &key, &ip_info, BPF_ANY);
	} else if (action == ACTION_DEL) {
		res = bpf_map_delete_elem(fd, &key);
	} else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			"%s() IP:%s errno(%d/%s)",
			__func__, ip_string, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in Iphash\n");
			return EXIT_OK;
		}
		fprintf(stderr, "\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose)
		fprintf(stderr,
			"%s() IP:%s TC-handle:0x%X\n",
			__func__, ip_string, tc_handle);
	return EXIT_OK;
}

bool locate_kern_object(char *execname, char *filename, size_t size)
{
	char *basec, *bname;

	snprintf(filename, size, "%s_kern.o", execname);

	if (access(filename, F_OK) != -1 )
		return true;

	/* Cannot find the _kern.o ELF object file directly.
	 * Lets start searching for it in different paths.
	 */
	basec = strdup(execname);
	if (basec == NULL)
		return false;
	bname = basename(basec);

	/* Maybe enough to add a "./" */
	snprintf(filename, size, "./%s_kern.o", bname);
	if (access( filename, F_OK ) != -1 ) {
		free(basec);
		return true;
	}

	/* Maybe /usr/local/lib/ */
	snprintf(filename, size, "/usr/local/lib/%s_kern.o", bname);
	if (access( filename, F_OK ) != -1 ) {
		free(basec);
		return true;
	}

	/* Maybe /usr/local/bin/ */
	snprintf(filename, size, "/usr/local/bin/%s_kern.o", bname);
	if (access(filename, F_OK) != -1 ) {
		free(basec);
		return true;
	}

	free(basec);
	return false;
}

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

#define FILEMODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

/* Verify BPF-filesystem is mounted on given file path */
int __bpf_fs_check_path(const char *path)
{
	struct statfs st_fs;
	char *dname, *dir;
	int err = 0;

	if (path == NULL)
		return -EINVAL;

	dname = strdup(path);
	if (dname == NULL)
		return -ENOMEM;

	dir = dirname(dname);
	if (statfs(dir, &st_fs)) {
		fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n",
			dir, errno, strerror(errno));
		err = -errno;
	}
	free(dname);

	if (!err && st_fs.f_type != BPF_FS_MAGIC) {
		err = -EMEDIUMTYPE;
	}

	return err;
}

int bpf_fs_check()
{
	const char *path = BPF_DIR_MNT "/some_file";
	int err;

	err = __bpf_fs_check_path(path);

	if (err == -EMEDIUMTYPE) {
		fprintf(stderr,
			"ERR: specified path %s is not on BPF FS\n\n"
			" You need to mount the BPF filesystem type like:\n"
			"  mount -t bpf bpf /sys/fs/bpf/\n\n",
			path);
	}
	return err;
}


int __bpf_fs_subdir_check_and_fix(const char *dir)
{
	int err;

	err = access(dir, F_OK);
	if (err) {
		if (errno == EACCES) {
			fprintf(stderr,"ERR: "
				"Got root? dir access %s fail: %s\n",
				dir, strerror(errno));
			return -1;
		}
		err = mkdir(dir, FILEMODE);
		if (err) {
			fprintf(stderr, "ERR: mkdir %s failed: %s\n",
				dir, strerror(errno));
				return -1;
		}
		// printf("DEBUG: mkdir %s\n", dir);
	}

	return err;
}

int bpf_fs_check_and_fix()
{
	const char *some_base_path = BPF_DIR_MNT "/some_file";
	const char *dir_tc_globals = BPF_DIR_MNT "/tc/globals";
	const char *dir_tc = BPF_DIR_MNT "/tc";
	const char *target = BPF_DIR_MNT;
	bool did_mkdir = false;
	int err;

	err = __bpf_fs_check_path(some_base_path);

	if (err) {
		/* First fix step: mkdir /sys/fs/bpf if dir not exist */
		struct stat sb = {0};
		int ret;

		ret = stat(target, &sb);
		if (ret) {
			ret = mkdir(target, FILEMODE);
			if (ret) {
				fprintf(stderr, "mkdir %s failed: %s\n", target,
					strerror(errno));
				return ret;
			}
			did_mkdir = true;
		}
	}

	if (err == -EMEDIUMTYPE || did_mkdir) {
		/* Fix step 2: Mount bpf filesystem */
		if (mount("bpf", target, "bpf", 0, "mode=0755")) {
			fprintf(stderr, "ERR: mount -t bpf bpf %s failed: %s\n",
				target,	strerror(errno));
			return -1;
		}
	}

	/* Fix step 3: Check sub-directories exists */
	err = __bpf_fs_subdir_check_and_fix(dir_tc);
	if (err)
		return err;

	err = __bpf_fs_subdir_check_and_fix(dir_tc_globals);
	if (err)
		return err;

	return 0;
}


bool map_txq_config_list_setup(int map_fd) {
	unsigned int possible_cpus = bpf_num_possible_cpus();
	struct txq_config txq_cfg;
	int cpu, err;

	printf("Current configuration:\n");
	printf("|-----------+---------------+-----------|\n"
	       "| key (cpu) | queue_mapping | htb_major |\n"
	       "|-----------+---------------+-----------|\n");

	for (cpu = 0; cpu < possible_cpus; cpu++) {

		err = bpf_map_lookup_elem(map_fd, &cpu, &txq_cfg);
		if (err) {
			fprintf(stderr,
				"ERR: %s() lookup cpu-key:%d err(%d):%s\n",
				__func__, cpu, errno, strerror(errno));
			return false;
		}

		printf("|    %-6u |        %-6u |  0x%-6X |\n",
		       cpu, txq_cfg.queue_mapping, txq_cfg.htb_major);
	}

	printf("|-----------+---------------+-----------|\n");
	return true;
}

/*
Create a simple default base setup for the "map_txq_config", where the
queue_mapping is CPU + 1, and HTB qdisc have handles equal to
queue_mapping.

  |-----------+---------------+-----------|
  | key (cpu) | queue_mapping | htb_major |
  |-----------+---------------+-----------|
  |         0 |             1 |         1 |
  |         1 |             2 |         2 |
  |         2 |             3 |         3 |
  |         3 |             4 |         4 |
  |-----------+---------------+-----------|

 */
bool map_txq_config_base_setup(int map_fd) {
	unsigned int possible_cpus = bpf_num_possible_cpus();
	struct txq_config txq_cfg;
	__u32 cpu;
	int err;

	if (map_fd < 0) {
		fprintf(stderr, "ERR: (bad map_fd:%d) "
			"cannot proceed without access to txq_config map\n",
			map_fd);
		return false;
	}

	for (cpu = 0; cpu < possible_cpus; cpu++) {
		txq_cfg.queue_mapping = cpu + 1;
		txq_cfg.htb_major     = cpu + 1;

		err = bpf_map_update_elem(map_fd, &cpu, &txq_cfg, 0);
		if (err) {
			fprintf(stderr,
				"ERR: %s() updating cpu-key:%d err(%d):%s\n",
				__func__, cpu, errno, strerror(errno));
			return false;
		}
	}

	return true;
}

#define CMD_MAX 	2048
#define CMD_MAX_TC	256
static char tc_cmd[CMD_MAX_TC] = "tc";

/*
 * TC require attaching the bpf-object via the TC cmdline tool.
 *
 * Manually like:
 *  $TC qdisc   del dev $DEV clsact
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV egress bpf da obj $BPF_OBJ sec $SEC_NAME
 *  $TC filter show dev $DEV egress
 *  $TC filter  del dev $DEV egress
 *
 * (The tc "replace" command does not seem to work as expected)
 */
int tc_egress_attach_bpf(const char* dev, const char* bpf_obj,
			 const char* sec_name)
{
	char cmd[CMD_MAX];
	int ret = 0;

	/* Step-1: Delete clsact, which also remove filters */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s qdisc del dev %s clsact 2> /dev/null",
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (!WIFEXITED(ret)) {
		fprintf(stderr,
			"ERR(%d): Cannot exec tc cmd\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	} else if (WEXITSTATUS(ret) == 2) {
		/* Unfortunately TC use same return code for many errors */
		if (verbose) printf(" - (First time loading clsact?)\n");
	}

	/* Step-2: Attach a new clsact qdisc */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s qdisc add dev %s clsact",
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot attach qdisc hook\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	/* Step-3: Attach BPF program/object as ingress filter */
	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s filter add dev %s "
		 "egress prio 1 handle 1 bpf da obj %s sec %s",
		 tc_cmd, dev, bpf_obj, sec_name);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot attach filter\n Cmdline:%s\n",
			WEXITSTATUS(ret), cmd);
		exit(EXIT_FAILURE);
	}

	return ret;
}

int tc_list_egress_filter(const char* dev)
{
	char cmd[CMD_MAX];
	int ret = 0;

	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 "%s filter show dev %s egress",
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot list filters\n Cmdline:%s\n",
			ret, cmd);
		exit(EXIT_FAILURE);
	}
	return ret;
}

int tc_remove_egress_filter(const char* dev)
{
	char cmd[CMD_MAX];
	int ret = 0;

	memset(&cmd, 0, CMD_MAX);
	snprintf(cmd, CMD_MAX,
		 /* Remove all egress filters on dev */
		 "%s filter delete dev %s egress",
		 /* Alternatively could remove specific filter handle:
		 "%s filter delete dev %s egress prio 1 handle 1 bpf",
		 */
		 tc_cmd, dev);
	if (verbose) printf(" - Run: %s\n", cmd);
	ret = system(cmd);
	if (ret) {
		fprintf(stderr,
			"ERR(%d): tc cannot remove filters\n Cmdline:%s\n",
			ret, cmd);
		exit(EXIT_FAILURE);
	}
	return ret;
}
