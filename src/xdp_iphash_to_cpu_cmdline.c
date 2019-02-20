
static const char *__doc__=
 " XDP ip_hash: command line tool";

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include <sys/resource.h>
#include <getopt.h>
#include <time.h>

#include <arpa/inet.h>

/* libbpf.h defines bpf_* function helpers for syscalls,
 * indirectly via ./tools/lib/bpf/bpf.h */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf_util.h>

#include <linux/pkt_sched.h> /* TC macros */

#include "common.h"
#include "xdp_iphash_to_cpu_common.h"

static const struct option long_options[] = {
        {"help",        no_argument,            NULL, 'h' },
        {"add",         no_argument,            NULL, 'a' },
        {"del",         no_argument,            NULL, 'x' },
        {"ip",          required_argument,      NULL, 'i' },
        {"classid",     required_argument,      NULL, 't' },
        {"cpu",         required_argument,      NULL, 'c' },
        {"list",        no_argument,            NULL, 'l' },
        {"clear",       no_argument,            NULL, 'e' },
        {0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
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
static __u32 get_key32_value32(int fd, __u32 key)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	/* unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u64 sum = 0; */
	__u32 value;
	//res = inet_pton(AF_INET, ip_string, &key);
	if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
		fprintf(stderr,
			"ERR:%i, bpf_map_lookup_elem failed key:%i %i \n",errno, key, value);
		return 0;
	}
	return value;
	/* Sum values from each CPU */
	/*for (i = 0; i < nr_cpus; i++) {
		sum += values[i];
	} */
	//return sum;
}

static bool get_key32_value_ip_info(int fd, __u32 key, struct ip_hash_info *ip_info)
{
	if ((bpf_map_lookup_elem(fd, &key, ip_info)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:%u errno(%d):%s\n",
			key, errno, strerror(errno));
		return false;
	}
	return true;
}

static void iphash_print_ipv4(__u32 ip, struct ip_hash_info *ip_info)
{
	char ip_txt[INET_ADDRSTRLEN] = {0};

	if (!ip_info) {
		fprintf(stderr,	"ERR: %s() NULL pointer\n", __func__);
		exit(EXIT_FAIL);
	}

	/* Convert IPv4 addresses from binary to text form */
	if (!inet_ntop(AF_INET, &ip, ip_txt, sizeof(ip_txt))) {
		fprintf(stderr,
			"ERR: Cannot convert u32 IP:0x%X to IP-txt\n", ip);
		exit(EXIT_FAIL_IP);
	}
	printf("\"%s\" : %u, tc_handle : 0x%X\n",
	       ip_txt, ip_info->cpu, ip_info->tc_handle);
}
static void iphash_list_all_ipv4(int fd)
{
	__u32 key, *prev_key = NULL;
	struct ip_hash_info ip_info;
	int err;

	printf("{\n");
	while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
		if (!get_key32_value_ip_info(fd, key, &ip_info)) {
			err = -1;
			break;
		}
		iphash_print_ipv4(key, &ip_info);
		prev_key = &key;
	}
	printf("}\n");
	/* Make sure err was result of last key reached */
	if (err < 0 && errno != ENOENT)
		fprintf(stderr,
			"WARN: %s() didn't list all entries: err(%d/%d):%s\n",
			__func__, err, errno, strerror(errno));
}
static void iphash_clear_all_ipv4(int fd)
{
	__u32 key, *prev_key = NULL;
	__u32 value;
        int res;
	char ip_txt[INET_ADDRSTRLEN] = {0};
	while (bpf_map_get_next_key(fd, prev_key, &key) == 0) {
                inet_ntop(AF_INET, &key, ip_txt, sizeof(ip_txt));
		res = iphash_modify(fd, ip_txt, ACTION_DEL, 0, 0);
		prev_key = &key;
	}
}
int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
		exit(EXIT_FAIL_MAP_FILE);
	}
	return fd;
}

/* Handle classid parsing based on iproute source */
int get_tc_classid(__u32 *h, const char *str)
{
	__u32 major, minor;
	char *p;

//	major = TC_H_ROOT;
//	if (strcmp(str, "root") == 0)
//		goto ok;
//	major = TC_H_UNSPEC;
//	if (strcmp(str, "none") == 0)
//		goto ok;
	major = strtoul(str, &p, 16);
	if (p == str) {
		major = 0;
		if (*p != ':')
			return -1;
	}
	if (*p == ':') {
		if (major >= (1<<16))
			return -1;
		major <<= 16;
		str = p+1;
		minor = strtoul(str, &p, 16);
		if (*p != 0)
			return -1;
		if (minor >= (1<<16))
			return -1;
		major |= minor;
	} else if (*p != 0)
		return -1;

ok:
	*h = major;
	return 0;
}


int main(int argc, char **argv) {
	#	define STR_MAX 42 /* For trivial input validation */
	char _ip_string_buf[STR_MAX] = {};
	char *ip_string = NULL;
	unsigned int action = 0;
	int longindex = 0;
	bool do_list = false;
	bool do_clear = false;
	int opt;
	int fd;
	__u32 cpu = -1;
	__u32 tc_handle = 0;
	bool provided_classid = false;

	while ((opt = getopt_long(argc, argv, "haxil:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'a':
			action |= ACTION_ADD;
			break;
		case 'x':
			action |= ACTION_DEL;
			break;
		case 'c':
			cpu = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			if (!optarg || strlen(optarg) >= STR_MAX) {
				printf("ERR: src ip too long or NULL\n");
				goto fail_opt;
			}
			ip_string = (char *)&_ip_string_buf;
			strncpy(ip_string, optarg, STR_MAX);
			break;
		case 't': /* classid parse like iproute2 into __u32 tc_handle */
			if ( get_tc_classid(&tc_handle, optarg) < 0) {
				printf("ERR: classid tc syntax (HEX) major:minor\n");
				goto fail_opt;
			}
			// printf("Got --classid=%s handle:0x%X\n", optarg, tc_handle);
			provided_classid = true;
			break;
		case 'l':
			do_list = true;
			break;
		case 'e':
			do_clear = true;
			break;
		case 'h':
		fail_opt:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	if (do_list) {
		int i;

		fd = open_bpf_map(mapfile_ip_hash);
		iphash_list_all_ipv4(fd);
		close(fd);
		return EXIT_OK;
	}
	if (do_clear) {
		int i;

		fd = open_bpf_map(mapfile_ip_hash);
		iphash_clear_all_ipv4(fd);
		close(fd);
		return EXIT_OK;
	}
	if (action == 0) {
                printf("ERR: required option --add or --del missing");
		goto fail_opt;
        }
	if (!ip_string) {
                printf("ERR: required option --ip missing");
		goto fail_opt;
        }
	if (action == ACTION_ADD && cpu == -1) {
                printf("ERR: required option --cpu missing when using --add");
		goto fail_opt;
        }
	if (action == ACTION_ADD && !provided_classid) {
                printf("ERR: required option --classid missing when using --add");
		goto fail_opt;
        }
	if (action) {
		int res = 0;

		if (!ip_string) {
			fprintf(stderr,
			  "ERR: action require data, e.g option --ip\n");
			goto fail_opt;
		}

		if (ip_string) {
			fd = open_bpf_map(mapfile_ip_hash);
			res = iphash_modify(fd, ip_string, action, cpu, tc_handle);
			close(fd);
		}
		return res;
	}
}
