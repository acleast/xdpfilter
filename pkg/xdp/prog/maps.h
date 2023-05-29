#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
static void *(*bpf_map_update_elem)(void *map, void *key, void *value, int flags) = (void *) BPF_FUNC_map_update_elem;

#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

enum bpf_pin_type {
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};

struct bpf_map_def SEC("maps/srcMap") srcMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/dstMap") dstMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/protoMap") protoMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/sportMap") sportMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/dportMap") dportMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/actionMap") actionMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};
