/* Basedir due to iproute2 use this path */
#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

const char *mapfile_txq_config = BASEDIR_MAPS "/map_txq_config";
const char *mapfile_ip_hash    = BASEDIR_MAPS "/map_ip_hash";
