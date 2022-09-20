static const char *__doc__=
 "TC: Control program for tc_classify_kern.o\n"
 " - When using --dev, loads TC-egress filter calling BPF program\n"
 " - Config of map_txq_config, that control CPU to queue_mapping\n"
 " - List current queue_mapping (txq) config via --list\n"
 "\n"
 ;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf_util.h>

#include "common_user.h"
#include "common_kern_user.h"

static int map_txq_config_fd = -1;

const char *bpf_obj  = "tc_classify_kern.o";
const char *sec_name = "tc_classify";

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"base-setup",	no_argument,		NULL, 'b' },
	{"list",	no_argument,		NULL, 'l' },
	{"quiet",	no_argument,		NULL, 'q' },
	{"cpu",		required_argument,	NULL, 'c' },
	{"queue-mapping",required_argument,	NULL, 'm' },
	{"htb-major-hex",required_argument,	NULL, 'j' }, /* Hex base 16 */
	{"dev-egress"	,required_argument,	NULL, 'd' },
	{0, 0, NULL,  0 }
};

static void usage(const char *prog_name_argv0, const char *doctxt)
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", doctxt);
	printf(" Usage: %s (options-see-below)\n", prog_name_argv0);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

int open_bpf_map_file(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			file, errno, strerror(errno));
		return fd;
	}
	return fd;
}

bool single_cpu_setup(int map_fd, __s64 set_cpu, struct txq_config txq_cfg,
		      bool set_queue_mapping, bool set_htb_major)
{
	__u32 cpu;
	int err;

	if (!set_queue_mapping) {
		fprintf(stderr, "ERR: missing option --queue-mapping\n");
		return false;
	}
	if (!set_htb_major) {
		fprintf(stderr, "ERR: missing option --htb-major\n");
		return false;
	}
	if (set_cpu < 0) {
		fprintf(stderr, "ERR: missing option --cpu\n");
		return false;
	}
	cpu = (__u32) set_cpu;

	err = bpf_map_update_elem(map_fd, &cpu, &txq_cfg, 0);
	if (err) {
		fprintf(stderr,
			"ERR: %s() updating cpu-key:%d err(%d):%s\n",
			__func__, cpu, errno, strerror(errno));
		return false;
	}
	if (verbose) {
		printf("Set CPU=%u to use queue_mapping=%u + htb_major=0x%X:\n",
		       cpu, txq_cfg.queue_mapping, txq_cfg.htb_major);
		map_txq_config_list_setup(map_fd);
	}
	return true;
}

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

int main(int argc, char **argv)
{
	int opt, longindex = 0;
	struct txq_config txq_cfg;
	bool set_queue_mapping = false;
	bool set_htb_major = false;
	bool do_map_init = false;
	bool do_list = false;
	__s64 set_cpu = -1;
	char filename[512];

	/* Depend on sharing pinned maps */
	if (bpf_fs_check_and_fix()) {
		fprintf(stderr, "ERR: "
			"Need access to bpf-fs(%s) for pinned maps "
			"(%d): %s\n", BPF_DIR_MNT, errno, strerror(errno));
		return EXIT_FAIL_MAP_FS;
	}

	/* Try opening txq_config map for CPU to queue_mapping */
	map_txq_config_fd = open_bpf_map_file(mapfile_txq_config);

	if (!locate_kern_object(argv[0], filename, sizeof(filename))) {
		fprintf(stderr, "ERR: "
			"cannot locate BPF _kern.o ELF file:%s errno(%d):%s\n",
			filename, errno, strerror(errno));
		return EXIT_FAIL_BPF_ELF;
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hqblc:m:j:d:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'q':
			verbose = 0;
			break;
		case 'b':
			do_map_init = true;
			break;
		case 'l':
			do_list = true;
			break;
		case 'c':
			set_cpu = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			set_queue_mapping = true;
			txq_cfg.queue_mapping = strtoul(optarg, NULL, 0);
			break;
		case 'j':
			set_htb_major = true;
			txq_cfg.htb_major = strtoul(optarg, NULL, 16); /* Hex */
			break;
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			if (ifindex >= MAX_IFINDEX) {
				fprintf(stderr,
					"ERR: Fix MAX_IFINDEX err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'h':
		error:
		default:
			usage(argv[0], __doc__);
			return EXIT_FAIL_OPTION;
		}
	}

	if (verbose)
		printf("%s Map filename: %s\n", __doc__, mapfile_txq_config);

	if (ifindex > 0 && !do_list) {
		int err;

		if (verbose)
			printf("Dev:%s -- Loading: TC-clsact egress\n", ifname);

		err = tc_egress_attach_bpf(ifname, filename, sec_name);
		if (err) {
			fprintf(stderr, "ERR: dev:%s"
				" Fail TC-clsact loading %s sec:%s\n",
				ifname, filename, sec_name);
			return err;
		}

		if (map_txq_config_fd < 0) {
			/* Just loaded TC prog should have pinned it */
			map_txq_config_fd =
				open_bpf_map_file(mapfile_txq_config);
			do_map_init = true;
		}
	}

	if (do_map_init) {
		if (!map_txq_config_base_setup(map_txq_config_fd))
			return EXIT_FAIL_MAP;
		if (verbose)
			map_txq_config_list_setup(map_txq_config_fd);
	}

	if (set_cpu >= 0 || set_queue_mapping || set_htb_major) {

		if (map_txq_config_fd < 0) {
			fprintf(stderr,
			"ERR: cannot proceed without access to config map\n");
			return EXIT_FAIL_MAP;
		}

		if (!single_cpu_setup(map_txq_config_fd, set_cpu, txq_cfg,
				      set_queue_mapping, set_htb_major))
			return EXIT_FAIL_OPTION;
	}

	if (do_list) {
		if (!map_txq_config_list_setup(map_txq_config_fd))
			return EXIT_FAIL_MAP;

		if (ifindex > 0)
			tc_list_egress_filter(ifname);
	}


	return EXIT_OK;
}
