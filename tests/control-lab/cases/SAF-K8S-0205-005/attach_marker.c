/* One case-owned cgroup/sysctl allow program with a one-entry invocation counter. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

typedef unsigned int __u32;

struct {
    __uint(type, 2);          /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sysctl_hits SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

SEC("cgroup/sysctl")
int saf_sysctl(void *context)
{
    __u32 key = 0;
    __u32 *count;
    (void)context;
    count = bpf_map_lookup_elem(&sysctl_hits, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 1; /* Permit the read; this fixture does not alter the value. */
}

SEC("license")
char fixture_license[] = "GPL";
