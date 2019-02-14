
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
#include "xdp_iphash_to_cpu_common.h"

static const struct option long_options[] = {
        {"help",        no_argument,            NULL, 'h' },
        {"add",         no_argument,            NULL, 'a' },
        {"del",         no_argument,            NULL, 'x' },
        {"ip",          required_argument,      NULL, 'i' },
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

static void iphash_print_ipv4(__u32 ip, __u32 cpu)
{
	char ip_txt[INET_ADDRSTRLEN] = {0};

	/* Convert IPv4 addresses from binary to text form */
	if (!inet_ntop(AF_INET, &ip, ip_txt, sizeof(ip_txt))) {
		fprintf(stderr,
			"ERR: Cannot convert u32 IP:0x%X to IP-txt\n", ip);
		exit(EXIT_FAIL_IP);
	}
	printf("\"%s\" : %i\n", ip_txt, cpu);
}
static void iphash_list_all_ipv4(int fd)
{
	__u32 key = 0, next_key;
	__u32 value;

	printf("{\n");
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		key = next_key;
		value = get_key32_value32(fd, key);
		iphash_print_ipv4(key, value);
	}
	printf("}\n");
}
static void iphash_clear_all_ipv4(int fd)
{
	__u32 key = 0, next_key;
	__u32 value;
        int res;
	char ip_txt[INET_ADDRSTRLEN] = {0};
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		key = next_key;
                inet_ntop(AF_INET, &key, ip_txt, sizeof(ip_txt));
		res = iphash_modify(fd, ip_txt, ACTION_DEL,0);
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
		int fd_iphash_count_array[IP_HASH_MAX];
		int i;

		fd = open_bpf_map(file_ip_hash);
		iphash_list_all_ipv4(fd);
		close(fd);
		return EXIT_OK;
	}
	if (do_clear) {
		int fd_iphash_count_array[IP_HASH_MAX];
		int i;

		fd = open_bpf_map(file_ip_hash);
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
	if (action) {
		int res = 0;

		if (!ip_string) {
			fprintf(stderr,
			  "ERR: action require data, e.g option --ip\n");
			goto fail_opt;
		}

		if (ip_string) {
			fd = open_bpf_map(file_ip_hash);
			res = iphash_modify(fd, ip_string, action,cpu);
			close(fd);
		}
		return res;
	}
}
