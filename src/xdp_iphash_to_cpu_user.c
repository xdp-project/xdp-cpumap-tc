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

#include "common_user.h"
#include "common_kern_user.h"

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

/* TODO move to libbpf */
struct bpf_pinned_map {
	const char *name;
	const char *filename;
	int map_fd;
};

/*     bpf_prog_load_attr extended */
struct bpf_prog_load_attr_maps {
	const char *file;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	int ifindex;
	int nr_pinned_maps;
	struct bpf_pinned_map *pinned_maps;
};

static int cpu_map_fd = -1;
static int ip_hash_map_fd = -1;
static int cpus_available_map_fd  = -1;
static int ifindex_type_map_fd  = -1;

static int find_map_fd_by_name(struct bpf_object *obj,
			       const char *mapname,
			       struct bpf_prog_load_attr_maps *attr)
{
	int map_fd, i;

	/* Prefer using libbpf function to find_fd_by_name */
	map_fd = bpf_object__find_map_fd_by_name(obj, mapname);
	if (map_fd > 0)
		return map_fd;

	/* If an old TC tool created and pinned map then it have no "name".
	 * In that case use the FD that was returned when opening pinned file.
	 */
	for (i = 0; i < attr->nr_pinned_maps; i++) {
		struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];

		if (strcmp(mapname, pin_map->name) != 0)
				continue;

		/* Matched, use FD stored in bpf_pinned_map */
		map_fd = pin_map->map_fd;
		if (verbose)
			printf("TC workaround for mapname: %s map_fd:%d\n",
			       mapname, map_fd);
	}
	return map_fd;
}

static int init_map_fds(struct bpf_object *obj,
			struct bpf_prog_load_attr_maps *attr)
{
	cpu_map_fd           = find_map_fd_by_name(obj,"cpu_map", attr);
	cpus_available_map_fd= find_map_fd_by_name(obj,"cpus_available",attr);
	ifindex_type_map_fd  = find_map_fd_by_name(obj,"map_ifindex_type",attr);
	ip_hash_map_fd       = find_map_fd_by_name(obj,"map_ip_hash", attr);

	if (cpu_map_fd < 0 || ip_hash_map_fd < 0 ||
	    cpus_available_map_fd < 0 || ifindex_type_map_fd < 0) {
		fprintf(stderr,
			"FDs cpu_map:%d ip_hash:%d cpus_avail:%d ifindex:%d\n",
			cpu_map_fd, ip_hash_map_fd,
			cpus_available_map_fd, ifindex_type_map_fd);
		return -ENOENT;
	}

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
	int ret, i;

	/* add all available CPUs in system  */
	if (add_all_cpu == true)
		for (i = 0; i < possible_cpus; i++)
			cpus[i] = true;

	for (i = 0; i < MAX_CPUS; i++) {

		if (cpus[i] == true) {
			create_cpu_entry(i, queue_size);
		} else {
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
	__u32 dir = INTERFACE_NONE;

	if (verbose) {
		fprintf(stderr, "Removing XDP program on ifindex:%d device:%s\n",
			ifindex, ifname);
	}
	if (ifindex > -1) {
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (bpf_map_update_elem(ifindex_type_map_fd,
					&ifindex, &dir, 0) < 0) {
			fprintf(stderr, "ERR: Clear ifindex type failed \n");
		}
	}

	/* map file is possibly share, cannot remove it here */
	if (verbose)
		fprintf(stderr,
			"INFO: not cleanup pinned map file:%s (use 'rm')\n",
			file);
}

void chown_maps(uid_t owner, gid_t group, const char *file)
{
	/* Change permissions and user for the map file, as this allow
	 * an unpriviliged user to operate the cmdline tool.
	 */
	if (chown(file, owner, group) < 0)
		fprintf(stderr,
			"WARN: Cannot chown file:%s err(%d):%s\n",
			file, errno, strerror(errno));
}

/* From: include/linux/err.h */
#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline bool IS_ERR_OR_NULL(const void *ptr)
{
        return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

#define pr_warning printf

/* As close as possible to libbpf bpf_prog_load_xattr(), with the
 * difference of handling pinned maps.
 */
int bpf_prog_load_xattr_maps(const struct bpf_prog_load_attr_maps *attr,
			     struct bpf_object **pobj, int *prog_fd)
{
	struct bpf_object_open_attr open_attr = {
		.file		= attr->file,
		.prog_type	= attr->prog_type,
	};
	struct bpf_program *prog, *first_prog = NULL;
	enum bpf_attach_type expected_attach_type;
	enum bpf_prog_type prog_type;
	struct bpf_object *obj;
	struct bpf_map *map;
	int err;
	int i;

	if (!attr)
		return -EINVAL;
	if (!attr->file)
		return -EINVAL;


	obj = bpf_object__open_xattr(&open_attr);
	if (IS_ERR_OR_NULL(obj))
		return -ENOENT;

	bpf_object__for_each_program(prog, obj) {
		/*
		 * If type is not specified, try to guess it based on
		 * section name.
		 */
		prog_type = attr->prog_type;
#if 0 /* Use internal libbpf variables */
		prog->prog_ifindex = attr->ifindex;
#endif
		expected_attach_type = attr->expected_attach_type;
#if 0 /* Use internal libbpf variables */
		if (prog_type == BPF_PROG_TYPE_UNSPEC) {
			err = bpf_program__identify_section(prog, &prog_type,
							    &expected_attach_type);
			if (err < 0) {
				bpf_object__close(obj);
				return -EINVAL;
			}
		}
#endif

		bpf_program__set_type(prog, prog_type);
		bpf_program__set_expected_attach_type(prog,
						      expected_attach_type);

		if (!first_prog)
			first_prog = prog;
	}

	/* Reset attr->pinned_maps.map_fd to identify successful file load */
	for (i = 0; i < attr->nr_pinned_maps; i++)
		attr->pinned_maps[i].map_fd = -1;

	bpf_map__for_each(map, obj) {
		const char* mapname = bpf_map__name(map);

#if 0 /* Use internal libbpf variables */
		if (!bpf_map__is_offload_neutral(map))
			map->map_ifindex = attr->ifindex;
#endif
		for (i = 0; i < attr->nr_pinned_maps; i++) {
			struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];
			int fd;

			if (strcmp(mapname, pin_map->name) != 0)
				continue;

			/* Matched, try opening pinned file */
			fd = bpf_obj_get(pin_map->filename);
			if (fd > 0) {
				/* Use FD from pinned map as replacement */
				bpf_map__reuse_fd(map, fd);
				/* TODO: Might want to set internal map "name"
				 * if opened pinned map didn't, to allow
				 * bpf_object__find_map_fd_by_name() to work.
				 */
				pin_map->map_fd = fd;
				continue;
			}
			/* Could not open pinned filename map, then this prog
			 * should then pin the map, BUT this can only happen
			 * after bpf_object__load().
			 */
		}
	}

	if (!first_prog) {
		pr_warning("object file doesn't contain bpf program\n");
		bpf_object__close(obj);
		return -ENOENT;
	}

	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		return -EINVAL;
	}

	/* Pin the maps that were not loaded via pinned filename */
	bpf_map__for_each(map, obj) {
		const char* mapname = bpf_map__name(map);

		for (i = 0; i < attr->nr_pinned_maps; i++) {
			struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];
			int err;

			if (strcmp(mapname, pin_map->name) != 0)
				continue;

			/* Matched, check if map is already loaded */
			if (pin_map->map_fd != -1)
				continue;

			/* Needs to be pinned */
			err = bpf_map__pin(map, pin_map->filename);
			if (err)
				continue;
			pin_map->map_fd = bpf_map__fd(map);
		}
	}

	/* Help user if requested map name that doesn't exist */
	for (i = 0; i < attr->nr_pinned_maps; i++) {
		struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];

		if (pin_map->map_fd < 0)
			pr_warning("%s() requested mapname:%s not seen\n",
				   __func__, pin_map->name);
	}

	*pobj = obj;
	*prog_fd = bpf_program__fd(first_prog);
	return 0;
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

	/* libbpf */
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_object *obj;
	int prog_fd;

	struct bpf_pinned_map my_pinned_maps[2];
	struct bpf_prog_load_attr_maps prog_load_attr_maps = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.nr_pinned_maps	= 2,
	};
	my_pinned_maps[0].name     = "map_ip_hash";
	my_pinned_maps[0].filename = mapfile_ip_hash;
	my_pinned_maps[1].name     = "map_ifindex_type";
	my_pinned_maps[1].filename = mapfile_ifindex_type;

	prog_load_attr_maps.pinned_maps = my_pinned_maps;

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
	//prog_open_attr.file = filename;
	prog_load_attr_maps.file = filename;

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
			if (ifindex >= MAX_IFINDEX) {
				fprintf(stderr,
					"ERR: Fix MAX_IFINDEX err(%d):%s\n",
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

	if (bpf_prog_load_xattr_maps(&prog_load_attr_maps, &obj, &prog_fd)) {
		fprintf(stderr,"ERR: Failed loading BPF-prog\n");
		return EXIT_FAIL_BPF;
	}

	if (owner >= 0)
		chown_maps(owner, group, mapfile_ip_hash);

	if (init_map_fds(obj, &prog_load_attr_maps) < 0) {
		fprintf(stderr, "bpf_object__find_map_fd_by_name failed\n");
		return EXIT_FAIL;
	}

	/* The CPUMAP type doesn't allow to bpf_map_lookup_elem (from
	 * eBPF prog side _kern.c). Thus, maintain another map that
	 * says if a CPU is avail for redirect.
	 */
	mark_cpus_available(cpus, qsize, add_all_cpus);

	/* Set LAN or WAN type direction */
	if (bpf_map_update_elem(ifindex_type_map_fd, &ifindex, &dir, 0) < 0) {
		fprintf(stderr, "ERR: create ifindex direction type failed \n");
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
