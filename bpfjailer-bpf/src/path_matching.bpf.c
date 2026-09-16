#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_COMPONENTS 255
#define MAX_COMPONENT_LEN 255

struct path_component {
    char name[256];
    u16 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} path_decision_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} path_patterns SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(path_matching_file_open, struct file *file)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
