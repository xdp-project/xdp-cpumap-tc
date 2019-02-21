#include <linux/types.h> /* __u32 */
#include <stdio.h>       /* fprintf */
#include <string.h>      /* strerror */
#include <arpa/inet.h>   /* inet_pton */

#include "common_user.h"
#include "common_kern_user.h"

#include "bpf_util.h"

#include <bpf/bpf.h>     /* LIBBPF_API: bpf_map_update_elem */
//#include <linux/bpf.h> /* System kernel-headers, BPF_ANY, but inc by bpf/bpf.h */

int verbose = 1; /* extern in common_user.h */

/* Basedir due to iproute2 use this path */
#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

const char *mapfile_txq_config = BASEDIR_MAPS "/map_txq_config";
const char *mapfile_ip_hash    = BASEDIR_MAPS "/map_ip_hash";
const char *mapfile_ifindex_type = BASEDIR_MAPS "/map_ifindex_type";

int iphash_modify(int fd, char *ip_string, unsigned int action,
		  __u32 cpu_idx, __u32 tc_handle)
{
	//printf ("In iphash_modify %u\n",cpu_idx);
	__u32 key;
	int res;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_hash_info ip_info;

	if (cpu_idx+1 > nr_cpus || cpu_idx+1 < 0)
		return EXIT_FAIL_CPU;

	/* Value for the map */
	ip_info.cpu       = cpu_idx;
	ip_info.tc_handle = tc_handle;

	/* Convert IP-string into 32-bit network byte-order value */
	res = inet_pton(AF_INET, ip_string, &key);
	if (res <= 0) {
		if (res == 0)
			fprintf(stderr,
				"ERR: IPv4 \"%s\" not in presentation format\n",
				ip_string);
		else
			perror("inet_pton");
		return EXIT_FAIL_IP;
	}
	printf ("key: 0x%X\n", key);
	if (action == ACTION_ADD) {
		//res = bpf_map_update_elem(fd, &key, &ip_info, BPF_NOEXIST);
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
			"%s() IP:%s key:0x%X errno(%d/%s)",
			__func__, ip_string, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in Iphash\n");
			return EXIT_OK;
		}
		fprintf(stderr, "\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose)
		fprintf(stderr,
			"%s() IP:%s key:0x%X TC-handle:0x%X\n",
			__func__, ip_string, key, tc_handle);
	return EXIT_OK;
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
