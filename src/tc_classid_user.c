static const char *__doc__=
 " TC: Control program for tc_classid_kern.o\n";

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

static int map_txq_config_fd = -1;

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

int main(int argc, char **argv)
{
	printf("Hello World, map name: %s\n", mapfile_txq_config);

	if ((map_txq_config_fd = open_bpf_map_file(mapfile_txq_config)) < 0) {
		fprintf(stderr,
			"ERR: cannot proceed without access to config map\n");
		return EXIT_FAIL;
	}

	return EXIT_OK;
}

