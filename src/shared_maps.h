#ifndef SHARED_MAPS_H
#define SHARED_MAPS_H

#include <bpf/bpf_helpers.h>

#include "common_kern_user.h"

/* Pinned shared map: see  mapfile_ip_hash */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, IP_HASH_ENTRIES_MAX);
	__type(key, struct ip_hash_key);
	__type(value, struct ip_hash_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} map_ip_hash SEC(".maps");

/* Map shared with XDP programs */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_IFINDEX);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} map_ifindex_type SEC(".maps");

#endif
