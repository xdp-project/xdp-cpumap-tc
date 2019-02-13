static const char *__doc__=
 " XDP: Simple IPv4 to cpu hash\n"
 "\n"
 "This program loads the XDP eBPF program into the kernel.\n"
 "Use the cmdline tool for add/removing dest IPs to the has\n"
 ;

#include <linux/bpf.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pwd.h>

#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>

#include <sys/statfs.h>
#include <libgen.h>  /* dirname */

#include <arpa/inet.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf_util.h>
#include "xdp_iphash_to_cpu_common.h"

/* Interface direction WARNING - sync with _user.c */
#define INTERFACE_WAN      (1 << 0)
#define INTERFACE_LAN      (1 << 1)

#define MAX_CPUS 64 /* WARNING - sync with _kern.c */

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

static int cpu_map_fd = -1;
static int ip_hash_map_fd = -1;
static int cpus_available_map_fd  = -1;
static int cpus_count_map_fd = -1;
static int cpu_direction_map_fd  = -1;

static int init_map_fds(struct bpf_object *obj)
{
	cpu_map_fd            = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	ip_hash_map_fd        = bpf_object__find_map_fd_by_name(obj, "rx_cnt");
	cpus_available_map_fd = bpf_object__find_map_fd_by_name(obj, "cpus_available");
	cpus_count_map_fd     = bpf_object__find_map_fd_by_name(obj, "cpus_count");
	cpu_direction_map_fd  = bpf_object__find_map_fd_by_name(obj, "cpu_direction");

	if (cpu_map_fd < 0 || ip_hash_map_fd < 0 ||
	    cpus_available_map_fd < 0 ||
	    cpus_count_map_fd < 0 || cpu_direction_map_fd < 0)
		return -ENOENT;

	return 0;
}

#define NR_MAPS 6
int maps_marked_for_export[NR_MAPS] = { 0 };

static const char* map_idx_to_export_filename(int idx)
{
	const char *file = NULL;

	/* Mapping map_fd[idx] to export filenames */
	switch (idx) {
	case 0: /* map_fd[0]: cpu_map */
		file =   file_cpu_map;
		break;
	case 1: /* map_fd[1]: ip_hash */
		file =   file_ip_hash;
		break;
	case 2: /* map_fd[2]: cpus_available */
		file =   file_cpus_available;
		break;
	case 3: /* map_fd[3]: cpus_count */
		file =   file_cpus_count;
		break;
	case 4: /* map_fd[4]: cpu_direction */
		file =   file_cpu_direction;
		break;
	default:
		break;
	}
	return file;
}

static int create_cpu_entry(__u32 cpu, __u32 queue_size,
			    __u32 avail_idx, bool new)
{
	printf ("cpu %d idx %d\n", cpu, avail_idx);
	__u32 curr_cpus_count = 0;
	__u32 key = 0;
	int ret;
	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	/* map_fd[0]: cpu_map */
	ret = bpf_map_update_elem(cpu_map_fd, &cpu, &queue_size, 0);
	if (ret) {
		fprintf(stderr, "Create CPU entry failed (err:%d)\n", ret);
		exit(EXIT_FAIL_BPF);
	}

	/* Inform bpf_prog's that a new CPU is available to select
	 * from via some control maps.
	 */
	/* map_fd[2] = cpus_available */
	ret = bpf_map_update_elem(cpus_available_map_fd, &avail_idx, &cpu, 0);
	if (ret) {
		fprintf(stderr, "Add to avail CPUs failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* When not replacing/updating existing entry, bump the count */
	/* map_fd[3] = cpus_count */
	ret = bpf_map_lookup_elem(cpus_count_map_fd, &key, &curr_cpus_count);
	if (ret) {
		fprintf(stderr, "Failed reading curr cpus_count\n");
		exit(EXIT_FAIL_BPF);
	}
	if (new) {
		curr_cpus_count++;
		ret = bpf_map_update_elem(cpus_count_map_fd,
					  &key, &curr_cpus_count, 0);
		if (ret) {
			fprintf(stderr, "Failed write curr cpus_count\n");
			exit(EXIT_FAIL_BPF);
		}
	}
	if (verbose) {
		printf("%s CPU:%u as idx:%u queue_size:%d (total cpus_count:%u)\n",
	       	new ? "Add-new":"Replace", cpu, avail_idx,
	       	queue_size, curr_cpus_count);
	}
	return 0;
}

/* CPUs are zero-indexed. Thus, add a special sentinel default value
 * in map cpus_available to mark CPU index'es not configured
 */
static void mark_cpus_unavailable(void)
{
	__u32 invalid_cpu = MAX_CPUS;
	int ret, i;

	for (i = 0; i < MAX_CPUS; i++) {
		/* map_fd[2] = cpus_available */
		ret = bpf_map_update_elem(cpus_available_map_fd,
					  &i, &invalid_cpu, 0);
		if (ret) {
			fprintf(stderr, "Failed marking CPU unavailable\n");
			exit(EXIT_FAIL_BPF);
		}
	}
}

static void remove_xdp_program(int ifindex, const char *ifname, __u32 xdp_flags)
{
	const char *file = file_ip_hash;
	int i;

	if (verbose) {
		fprintf(stderr, "Removing XDP program on ifindex:%d device:%s\n",
			ifindex, ifname);
	}
	if (ifindex > -1)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

	/* Remove exported map files */
	if (unlink(file) < 0) {
		printf("WARN: cannot rm map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
	}
}

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"remove",	no_argument,		NULL, 'r' },
	{"dev",		required_argument,	NULL, 'd' },
	{"wan",		no_argument,		NULL, 'w' },
	{"lan",		no_argument,		NULL, 'l' },
	{"cpu",		required_argument,	NULL, 'c' },
	{"quiet",	no_argument,		NULL, 'q' },
	{"owner",	required_argument,	NULL, 'o' },
	{"skb-mode",	no_argument,		NULL, 'S' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
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

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

/* Verify BPF-filesystem is mounted on given file path */
static int bpf_fs_check_path(const char *path)
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
		fprintf(stderr,
			"ERR: specified path %s is not on BPF FS\n\n"
			" You need to mount the BPF filesystem type like:\n"
			"  mount -t bpf bpf /sys/fs/bpf/\n\n",
			path);
		err = -EINVAL;
	}

	return err;
}

void chown_maps(uid_t owner, gid_t group, const char *file)
{
	int i;

	/* Change permissions and user for the map file, as this allow
	 * an unpriviliged user to operate the cmdline tool.
	 */
	if (chown(file, owner, group) < 0)
		fprintf(stderr,
			"WARN: Cannot chown file:%s err(%d):%s\n",
			file, errno, strerror(errno));
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool rm_xdp_prog = false;
	struct passwd *pwd = NULL;
	__u32 xdp_flags = 0;
	char filename[256];
	__u32 qsize;
	int longindex = 0;
	uid_t owner = -1; /* -1 result in no-change of owner */
	gid_t group = -1;
	int dir = 0;
	int added_cpus = 0;
	int add_cpu = -1;
	int cpus[MAX_CPUS];
	int err;
	int opt;
	int i;

	/* libbpf */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_object *obj;
	struct bpf_map *map;
	int prog_fd;

	/* Notice: choosing the queue size is very important with the
	 * ixgbe driver, because it's driver page recycling trick is
	 * dependend on pages being returned quickly.  The number of
	 * out-standing packets in the system must be less-than 2x
	 * RX-ring size.
	 */
	qsize = 128+64;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hSrqdwlc:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'q':
			verbose = 0;
			break;
		case 'r':
			rm_xdp_prog = true;
			break;
		case 'o': /* extract owner and group from username */
			if (!(pwd = getpwnam(optarg))) {
				fprintf(stderr,
					"ERR: unknown owner:%s err(%d):%s\n",
					optarg, errno, strerror(errno));
				goto error;
			}
			owner = pwd->pw_uid;
			group = pwd->pw_gid;
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
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'w':
			if (dir != 0) {
				fprintf(stderr,
					"ERR: set either --wan or --lan\n");
				goto error;
			}
			dir = INTERFACE_WAN;
			break;
		case 'l':
			if (dir != 0) {
				fprintf(stderr,
					"ERR: set either --wan or --lan\n");
				goto error;
			}
			dir = INTERFACE_LAN;
			break;
		case 'c':
			add_cpu = strtoul(optarg, NULL, 0);
			if (add_cpu >= MAX_CPUS) {
				fprintf(stderr,
				"--cpu nr too large for cpumap err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			cpus[added_cpus] = add_cpu;
			added_cpus++;
			break;
		case 'h':
		error:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	if (ifindex == -1) {
		printf("ERR: required option --dev missing");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}

	if (rm_xdp_prog) {
		remove_xdp_program(ifindex, ifname, xdp_flags);
		return EXIT_OK;
	}
	/* Required option */
	if (add_cpu == -1) {
		fprintf(stderr, "ERR: required option --cpu missing\n");
		fprintf(stderr, " Specify multiple --cpu option to add more\n");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}
	if (dir == 0) {
		fprintf(stderr,"ERR: set either --wan or --lan\n");
		goto error;
	}

	/* Increase resource limits */
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

	/* ISSUE: How can libbpf load the maps via filesystem, and
	 * replace those in the ELF object before giving BPF-prog to
	 * the kernel?!
	 *
	 * Like bpf_load.c did with:
	 *  load_bpf_file_fixup_map(filename, pre_load_maps_via_fs)
	 */
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return EXIT_FAIL;

	if (!prog_fd) {
		fprintf(stderr, "ERR: load_bpf_file: %s\n", strerror(errno));
		return EXIT_FAIL;
	}

	/* Export maps that were not loaded from filesystem */
	// TODO: Missing export_maps();
	// Look at libbpf API:
	//  bpf_map__pin(struct bpf_map *map, const char *path);
	//
	map = bpf_object__find_map_by_name(obj, "ip_hash");
	if (!map) {
		fprintf(stderr, "ERR: cannot find map\n");
		return EXIT_FAIL;
	}
	err = bpf_map__pin(map, file_ip_hash);
	if (err < 0)
		return EXIT_FAIL;

	if (owner >= 0)
		chown_maps(owner, group, file_ip_hash);

	if (init_map_fds(obj) < 0) {
		fprintf(stderr, "bpf_object__find_map_fd_by_name failed\n");
		return EXIT_FAIL;
	}
	mark_cpus_unavailable();

	printf("added_cpus %i\n",added_cpus);
	for (i = 0; i < added_cpus; i++) {
		create_cpu_entry(cpus[i], qsize, i, true);
	}
	// add all configured cpus
	//int i;
	//for (i = 0; i < get_nprocs_conf(); i++) {
	//	create_cpu_entry(i, qsize, i, true);
	//}
	/* Set lan or wan direction */
	/* map_fd[4]: cpu_direction */
	if (bpf_map_update_elem(cpu_direction_map_fd, &ifindex, &dir, 0) < 0) {
		printf("Create CPU direction failed \n");
		return (EXIT_FAIL_BPF);
	}
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		return EXIT_FAIL_XDP;
	}
	if (verbose) {
		printf("Documentation:\n%s\n", __doc__);
		printf(" - Attached to device:%s (ifindex:%d)\n",
		       ifname, ifindex);
	}

	return EXIT_OK;
}

