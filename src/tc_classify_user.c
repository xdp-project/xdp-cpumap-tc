static const char *__doc__=
 "TC: Control program for tc_classid_kern.o\n"
 " (For now this just configure the BPF map: /sys/fs/bpf/tc/globals/map_txq_config)\n"
 ;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf_util.h>

#include "common_user.h"
#include "common_kern_user.h"

static int map_txq_config_fd = -1;

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"base-setup",	no_argument,		NULL, 'b' },
	{"list",	no_argument,		NULL, 'l' },
	{"quiet",	no_argument,		NULL, 'q' },
	{"cpu",		required_argument,	NULL, 'c' },
	{"queue-mapping",required_argument,	NULL, 'm' },
	{"htb-major-hex",required_argument,	NULL, 'j' }, /* notice Hex base 16 */
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

bool list_setup(int map_fd) {
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
bool base_setup(int map_fd) {
	unsigned int possible_cpus = bpf_num_possible_cpus();
	struct txq_config txq_cfg;
	__u32 cpu;
	int err;

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
	if (verbose)
		list_setup(map_fd);

	return true;
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
		list_setup(map_fd);
	}
	return true;
}

int main(int argc, char **argv)
{
	int opt, longindex = 0;
	struct txq_config txq_cfg;
	bool set_queue_mapping = false;
	bool set_htb_major = false;
	__s64 set_cpu = -1;

	if ((map_txq_config_fd = open_bpf_map_file(mapfile_txq_config)) < 0) {
		fprintf(stderr,
			"ERR: cannot proceed without access to config map\n");
		return EXIT_FAIL;
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hq",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'q':
			verbose = 0;
			break;
		case 'b':
			if (!base_setup(map_txq_config_fd))
				return EXIT_FAIL_MAP;
			break;
		case 'l':
			if (!list_setup(map_txq_config_fd))
				return EXIT_FAIL_MAP;
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
		case 'h':
		default:
			usage(argv[0], __doc__);
			return EXIT_FAIL_OPTION;
		}
	}

	if (verbose)
		printf("%s Map name: %s\n", __doc__, mapfile_txq_config);

	if (set_cpu >= 0 || set_queue_mapping || set_htb_major) {
		if (!single_cpu_setup(map_txq_config_fd, set_cpu, txq_cfg,
				      set_queue_mapping, set_htb_major))
			return EXIT_FAIL_OPTION;
	}

	return EXIT_OK;
}
