#ifndef __XDP_IPHASH_TO_CPU_USER_COMMON_H
#define __XDP_IPHASH_TO_CPU_USER_COMMON_H


static int verbose = 1;

/* Iphash operations */
#define ACTION_ADD	(1 << 0)
#define ACTION_DEL	(1 << 1)

static int iphash_modify(int fd, char *ip_string, unsigned int action,
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
#endif
