static const char *__doc__=
 " XDP: Lookup IPv4 and redirect to CPU hash\n"
 "\n"
 "This program loads the XDP eBPF program into the kernel.\n"
 "Use the cmdline tool for add/removing dest IPs to the hash\n"
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

#include "common.h"
#include "xdp_iphash_to_cpu_common.h"

/* Interface direction WARNING - sync with _user.c */
#define INTERFACE_WAN      (1 << 0)
#define INTERFACE_LAN      (1 << 1)

#define MAX_CPUS 64 /* WARNING - sync with _kern.c */

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

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
	{"all-cpus",	no_argument,		NULL, 'a' },
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

static int cpu_map_fd = -1;
static int ip_hash_map_fd = -1;
static int cpus_available_map_fd  = -1;
static int cpu_direction_map_fd  = -1;

static int init_map_fds(struct bpf_object *obj)
{
	cpu_map_fd            = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	ip_hash_map_fd        = bpf_object__find_map_fd_by_name(obj, "map_ip_hash");
	cpus_available_map_fd = bpf_object__find_map_fd_by_name(obj, "cpus_available");
	cpu_direction_map_fd  = bpf_object__find_map_fd_by_name(obj, "cpu_direction");

	if (cpu_map_fd < 0 || ip_hash_map_fd < 0 ||
	    cpus_available_map_fd < 0 || cpu_direction_map_fd < 0)
		return -ENOENT;

	return 0;
}

static int create_cpu_entry(__u32 cpu, __u32 queue_size)
{
	int ret;

	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	/* map: cpu_map */
	ret = bpf_map_update_elem(cpu_map_fd, &cpu, &queue_size, 0);
	if (ret) {
		fprintf(stderr, "Create CPU entry failed (err:%d)\n", ret);
		exit(EXIT_FAIL_BPF);
	}

	/* Inform bpf_prog's that a new CPU is available to select
	 * from via another maps, because eBPF prog side cannot lookup
	 * directly in cpu_map.
	 */
	/* map = cpus_available */
	ret = bpf_map_update_elem(cpus_available_map_fd, &cpu, &cpu, 0);
	if (ret) {
		fprintf(stderr, "Add to avail CPUs failed\n");
		exit(EXIT_FAIL_BPF);
	}

	if (verbose)
		printf("Added CPU:%u queue_size:%d\n", cpu, queue_size);

	return 0;
}

/* CPUs are zero-indexed. A special sentinel default value in map
 * cpus_available to mark CPU index'es not configured
 */
static void mark_cpus_available(bool cpus[MAX_CPUS], __u32 queue_size, bool add_all_cpu)
{
	unsigned int possible_cpus = bpf_num_possible_cpus();
	__u32 invalid_cpu = MAX_CPUS;
	__u32 cpu_value;
	int ret, i;

	/* add all available CPUs in system  */
	if (add_all_cpu == true)
		for (i = 0; i < possible_cpus; i++)
			cpus[i] = true;

	for (i = 0; i < MAX_CPUS; i++) {

		if (cpus[i] == true) {
			create_cpu_entry(i, queue_size);
		} else {
			cpu_value = invalid_cpu;

			/* map: cpus_available */
			ret = bpf_map_update_elem(cpus_available_map_fd,
						  &i, &invalid_cpu, 0);
			if (ret) {
				fprintf(stderr, "Failed marking CPU unavailable\n");
				exit(EXIT_FAIL_BPF);
			}
		}
	}
}

static void remove_xdp_program(int ifindex, const char *ifname, __u32 xdp_flags)
{
	const char *file = mapfile_ip_hash;
	int i;

	if (verbose) {
		fprintf(stderr, "Removing XDP program on ifindex:%d device:%s\n",
			ifindex, ifname);
	}
	if (ifindex > -1)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

	/* map file is possibly share, cannot remove it here */
	if (verbose)
		fprintf(stderr,
			"INFO: not cleanup pinned map file:%s (use 'rm')\n",
			file);
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

int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("WARN: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
	}
	return fd;
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

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool cpus[MAX_CPUS] = { false };
	bool add_all_cpus = true; /* Default add all CPU if no-others are provided */
	bool rm_xdp_prog = false;
	struct passwd *pwd = NULL;
	__u32 xdp_flags = 0;
	char filename[512];
	__u32 qsize;
	int longindex = 0;
	uid_t owner = -1; /* -1 result in no-change of owner */
	gid_t group = -1;
	int dir = 0;
	int added_cpus = 0;
	int add_cpu = -1;
	int err;
	int opt;
	int i;

	/* libbpf */
	struct bpf_object_open_attr prog_open_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};

	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_program * bpf_prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int pinned_file_fd;
	int prog_fd;

	/* Notice: choosing the queue size is very important with the
	 * ixgbe driver, because it's driver page recycling trick is
	 * dependend on pages being returned quickly.  The number of
	 * out-standing packets in the system must be less-than 2x
	 * RX-ring size.
	 */
	qsize = 128+64;

	if (!locate_kern_object(argv[0], filename, sizeof(filename))) {
		fprintf(stderr,
			"ERR: cannot locate BPF _kern.o ELF file:%s errno(%d):%s\n",
			filename, errno, strerror(errno));
		return EXIT_FAIL;
	}
	prog_open_attr.file = filename;

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
		case 'a':
			add_all_cpus = true;
		case 'c':
			add_all_cpus = false;
			add_cpu = strtoul(optarg, NULL, 0);
			if (add_cpu >= MAX_CPUS) {
				fprintf(stderr,
				"--cpu nr too large for cpumap err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			cpus[add_cpu] = true;
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
		fprintf(stderr, "ERR: required option --dev missing");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}

	if (rm_xdp_prog) {
		remove_xdp_program(ifindex, ifname, xdp_flags);
		return EXIT_OK;
	}
	/* Required option */
	if (dir == 0) {
		fprintf(stderr,"ERR: set either --wan or --lan\n");
		goto error;
	}

	/* Increase resource limits */
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

	/*
	 * Instead of using bpf_prog_load_xattr(), go through the
	 * steps bpf_object__open + bpf_object__load and in-between,
	 * load a pinned map file that the program should use
	 */
	obj = bpf_object__open_xattr(&prog_open_attr);
	if (!obj) {
		fprintf(stderr, "ERR: bpf_object__open_xattr: %s\n", strerror(errno));
		return EXIT_FAIL_MAP_FILE;
	}

	map = bpf_object__find_map_by_name(obj, "map_ip_hash");
	if (!map) {
		fprintf(stderr, "ERR: cannot find map\n");
		return EXIT_FAIL;
	}

	/* Reuse pinned map file, if available, else create pinned file */
	pinned_file_fd = open_bpf_map(mapfile_ip_hash);
	if (pinned_file_fd > 0) {
		/* Use pinned_file_fd instead */
		err = bpf_map__reuse_fd(map, pinned_file_fd);
		fprintf(stderr, "INFO: using pinned ip_hash map: %s\n",
			mapfile_ip_hash);
	}

	bpf_prog = bpf_program__next(NULL, obj);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: cannot find first prog: %s\n", strerror(errno));
		return EXIT_FAIL;
	}
	bpf_program__set_type(bpf_prog, prog_open_attr.prog_type);

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERR: bpf_object__load: %s\n", strerror(errno));
		bpf_object__close(obj);
		return -EINVAL;
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (!prog_fd) {
		fprintf(stderr, "ERR: load_bpf_file: %s\n", strerror(errno));
		return EXIT_FAIL;
	}

	if (pinned_file_fd < 0) {
		/* No pinned file, lets pin the file */
		fprintf(stderr, "INFO: pin ip_hash map: %s\n", mapfile_ip_hash);
		err = bpf_map__pin(map, mapfile_ip_hash);
		if (err) {
			fprintf(stderr, "ERR: cannot pin: %s\n", strerror(errno));
			return EXIT_FAIL;
		}
	}

	if (owner >= 0)
		chown_maps(owner, group, mapfile_ip_hash);

	if (init_map_fds(obj) < 0) {
		fprintf(stderr, "bpf_object__find_map_fd_by_name failed\n");
		return EXIT_FAIL;
	}

	/* The CPUMAP type doesn't allow to bpf_map_lookup_elem (from
	 * eBPF prog side _kern.c). Thus, maintain another map that
	 * says if a CPU is avail for redirect.
	 */
	mark_cpus_available(cpus, qsize, add_all_cpus);

	/* Set lan or wan direction */
	/* map: cpu_direction */
	if (bpf_map_update_elem(cpu_direction_map_fd, &ifindex, &dir, 0) < 0) {
		fprintf(stderr, "ERR: create CPU direction failed \n");
		return (EXIT_FAIL_BPF);
	}
	if ((err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp fd failed (err:%d)\n", err);
		return EXIT_FAIL_XDP;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	if (verbose) {
		printf("Documentation:\n%s\n", __doc__);
		printf(" - Attached to device:%s (ifindex:%d) prog_id:%d\n",
		       ifname, ifindex, info.id);
	}

	return EXIT_OK;
}
