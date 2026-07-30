// Use kernel BTF types from vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Protocol and socket constants
#define PROTO_TCP 6
#define PROTO_UDP 17
#define AF_INET 2
#define AF_INET6 10

#define MAX_STACK_DEPTH 4
#define MAX_PATH_LEN 4096

struct process_info {
    u64 pod_id;
    u32 role_id;
    u8 stack_depth;
    u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct process_info));
    __uint(max_entries, 0);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct process_info);
} task_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} pod_to_role SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} role_flags SEC(".maps");

// Network rule key: role_id + port + protocol + direction
// direction: 0 = bind, 1 = connect
struct net_rule_key {
    u32 role_id;
    u16 port;
    u8 protocol;  // PROTO_TCP or PROTO_UDP
    u8 direction; // 0 = bind, 1 = connect
};

// Network rules map: key -> allowed (1) or blocked (0)
// If key not found, falls back to role_flags
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct net_rule_key);
    __type(value, u8);
} network_rules SEC(".maps");

// Pending enrollments: userspace writes here, BPF migrates to task_storage
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);    // PID
    __type(value, struct process_info);
} pending_enrollments SEC(".maps");

// =============================================================================
// Path Matching State Machine
// =============================================================================
// Based on LPC 2025 presentation approach:
// - Walk dentry tree from file to root
// - Use state machine for pattern matching
// - State transitions based on path component hash
// - Supports wildcards and hierarchical patterns

#define MAX_PATH_DEPTH 32       // Max directory depth to walk
#define PATH_STATE_ROOT 0       // Starting state
// Sentinels live in the same space as the 64-bit state hashes, so they sit at
// the top of the range where a real FNV-1a digest is vanishingly unlikely.
#define PATH_STATE_ACCEPT 0xFFFFFFFFFFFFFFFEULL  // Accept (allow)
#define PATH_STATE_REJECT 0xFFFFFFFFFFFFFFFFULL  // Reject (deny)

// State transition key: current_state + component_hash -> next_state
struct path_state_key {
    u32 role_id;
    u64 state;           // Current state
    u64 component_hash;  // Hash of path component (e.g., "var", "www")
};

// State transition value
struct path_state_value {
    u64 next_state;      // Next state after this component
    u8 is_terminal;      // 1 if this is a final decision
    u8 decision;         // If terminal: 1=allow, 0=deny
    u8 wildcard;         // 1 if this matches any component (like *)
    u8 _pad;
};

// Path state machine transitions
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct path_state_key);
    __type(value, struct path_state_value);
} path_states SEC(".maps");

// Inode cache: inode -> cached decision (for performance)
struct inode_cache_key {
    u32 role_id;
    u64 inode;
};

struct inode_cache_value {
    u8 decision;      // 1=allow, 0=deny
    u8 _pad[3];
    u32 generation;   // Cache generation for invalidation
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct inode_cache_key);
    __type(value, struct inode_cache_value);
} inode_cache SEC(".maps");

// Global cache generation counter (incremented on mount changes)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} cache_generation SEC(".maps");

// Legacy path_rules map (kept for compatibility)
#define PATH_RULE_MAX_LEN 256

struct path_rule_key {
    u32 role_id;
    u64 path_hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct path_rule_key);
    __type(value, u8);
} path_rules SEC(".maps");

// Auto-enrollment by executable inode
struct exec_enrollment_value {
    u64 pod_id;
    u32 role_id;
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // inode number of executable
    __type(value, struct exec_enrollment_value);
} exec_enrollment SEC(".maps");

// Auto-enrollment by cgroup (cgroup id -> enrollment)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);  // cgroup id
    __type(value, struct exec_enrollment_value);
} cgroup_enrollment SEC(".maps");

// =============================================================================
// IP/CIDR Egress Filtering
// =============================================================================
// Supports IPv4 address-based filtering with CIDR prefix matching

// IP rule key: role_id + IP address + prefix length
struct ip_rule_key {
    u32 role_id;
    u32 ip_addr;      // IPv4 in network byte order
    u8 prefix_len;    // CIDR prefix (e.g., 24 for /24)
    u8 direction;     // 0 = bind, 1 = connect
    u8 _pad[2];
};

// IP rules map: key -> allowed (1) or blocked (0)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip_rule_key);
    __type(value, u8);
} ip_rules SEC(".maps");

// Proxy configuration per role
struct proxy_config {
    u32 proxy_ip;     // Proxy IPv4 address
    u16 proxy_port;   // Proxy port
    u8 require_proxy; // 1 = force all traffic through proxy
    u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);  // role_id
    __type(value, struct proxy_config);
} proxy_config SEC(".maps");

// Domain rules map: hash of domain -> allowed (1) or blocked (0)
struct domain_rule_key {
    u32 role_id;
    u64 domain_hash;  // FNV-1a 64 hash of domain name
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct domain_rule_key);
    __type(value, u8);
} domain_rules SEC(".maps");

// Resolved-address table: maps a resolved IP -> the hash of the name it came
// from. Populated at policy load, not by DNS interception, so entries must
// survive for the lifetime of the policy: a plain HASH, never an LRU_HASH.
// An LRU here silently evicts policy state and the domain rule stops biting.
struct dns_cache_key {
    u32 role_id;
    u32 ip_addr;      // Resolved IP address
};

struct dns_cache_value {
    u64 domain_hash;  // Hash of the domain that resolved to this IP
    u64 timestamp;    // When this entry was added (for TTL)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct dns_cache_key);
    __type(value, struct dns_cache_value);
} dns_cache SEC(".maps");

// =============================================================================
// Audit Events (Perf Buffer for systemd-journald integration)
// =============================================================================
// Used in daemonless mode - events are picked up by journald or logging daemon

// Hook types for audit events
#define AUDIT_HOOK_FILE_OPEN      1
#define AUDIT_HOOK_SOCKET_BIND    2
#define AUDIT_HOOK_SOCKET_CONNECT 3
#define AUDIT_HOOK_BPRM_CHECK     4
#define AUDIT_HOOK_PATH_RENAME    5

// Decision types
#define AUDIT_DECISION_DENY  0
#define AUDIT_DECISION_ALLOW 1

struct audit_event {
    u64 timestamp;       // ktime_get_ns()
    u32 pid;             // Process ID
    u32 role_id;         // Role of the process
    u32 decision;        // AUDIT_DECISION_DENY or AUDIT_DECISION_ALLOW
    u32 hook_type;       // AUDIT_HOOK_* value
    u64 context;         // Hook-specific: inode, port, etc.
    u64 pod_id;          // Pod ID
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} audit_events SEC(".maps");

// Helper to emit audit event
static __always_inline void emit_audit_event(void *ctx, u32 pid, u32 role_id,
                                              u64 pod_id, u32 decision,
                                              u32 hook_type, u64 context)
{
    struct audit_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .pid = pid,
        .role_id = role_id,
        .pod_id = pod_id,
        .decision = decision,
        .hook_type = hook_type,
        .context = context,
    };

    bpf_perf_event_output(ctx, &audit_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
}

// Per-CPU buffer for collecting path components (bottom-up)
#define MAX_COMPONENTS 16
#define MAX_COMPONENT_LEN 64

// Bytes of each path component fed into the hash. Must stay in lockstep with
// the userspace hash in bpfjailer-daemon/src/bpf_loader.rs and
// bpfjailer-bootstrap/src/main.rs -- both sides must agree byte for byte.
#define MAX_COMPONENT_HASH_LEN 64
#define FNV1A64_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV1A64_PRIME        0x00000100000001b3ULL

struct path_components {
    u64 hashes[MAX_COMPONENTS];  // Hash of each component
    u8 count;                     // Number of components collected
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct path_components);
} path_buf SEC(".maps");

// FNV-1a (64-bit) over the whole component, with the length mixed in.
//
// Replaces a 32-bit djb2 that hashed only the first 32 bytes. That combination
// produced two classes of false-positive policy match:
//
//   1. Short collisions from the weak 32-bit mix, e.g. ".ssh" and "01sh" both
//      hashed to 0x7c784161, as did ".aws" and ".axR".
//   2. Any two components sharing a 32-byte prefix collided outright, because
//      everything past byte 32 was discarded.
//
// The wider digest addresses (1). Hashing up to MAX_COMPONENT_HASH_LEN bytes
// and folding in the length addresses (2) for names within that bound.
//
// This is still an unkeyed hash, so it resists accidental collisions rather
// than an attacker computing one offline. See the note in the module docs.
static __always_inline u64 hash_component(const unsigned char *name, u32 len)
{
    u64 hash = FNV1A64_OFFSET_BASIS;
    u32 hashed = 0;

    #pragma unroll
    for (int i = 0; i < MAX_COMPONENT_HASH_LEN; i++) {
        if (i >= len)
            break;
        unsigned char c = 0;
        bpf_probe_read_kernel(&c, 1, &name[i]);
        if (c == 0)
            break;
        hash ^= (u64)c;
        hash *= FNV1A64_PRIME;
        hashed++;
    }

    // Fold in the byte count so components sharing a prefix but differing in
    // length cannot alias to the same digest.
    hash ^= (u64)hashed;
    hash *= FNV1A64_PRIME;
    return hash;
}

// Walk dentry tree and collect path component hashes (bottom-up)
static __always_inline int collect_path_components(struct dentry *dentry, struct path_components *buf)
{
    struct dentry *current = dentry;
    struct dentry *parent = NULL;
    buf->count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_COMPONENTS; i++) {
        if (!current)
            break;

        // Bounds check for verifier
        if (buf->count >= MAX_COMPONENTS)
            break;

        // Read parent pointer using CO-RE
        parent = BPF_CORE_READ(current, d_parent);

        // If parent == current, we've reached root
        if (parent == current)
            break;

        // Read d_name using CO-RE
        u32 len = BPF_CORE_READ(current, d_name.len);
        const unsigned char *name = BPF_CORE_READ(current, d_name.name);

        if (len > 0 && name) {
            // Use local index for verifier
            u8 idx = buf->count;
            if (idx < MAX_COMPONENTS) {
                buf->hashes[idx] = hash_component(name, len);
                buf->count = idx + 1;
            }
        }

        current = parent;
    }

    return buf->count;
}

// Run state machine on collected path components (reversed, root-to-leaf)
static __always_inline int check_path_state_machine(u32 role_id, struct path_components *buf)
{
    if (buf->count == 0)
        return 0;  // No rule

    u32 state = PATH_STATE_ROOT;
    // Zeroed explicitly: the struct has 4 bytes of padding before .state, and
    // a BPF hash lookup compares the whole key. An initializer list leaves that
    // padding as whatever the stack held, so lookups match only by luck.
    struct path_state_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.role_id = role_id;
    key.state = 0;
    key.component_hash = 0;

    u8 count = buf->count;
    if (count > MAX_COMPONENTS)
        count = MAX_COMPONENTS;

    // Walk from root to leaf (reverse order since we collected bottom-up)
    // hashes[count-1] is the topmost dir (closest to root)
    // hashes[0] is the filename
    #pragma unroll
    for (int i = 0; i < MAX_COMPONENTS; i++) {
        if (i >= count)
            break;

        // Index from end to start (root to file)
        // Use unsigned to help verifier with bounds
        u32 idx = (u32)(count - 1 - i);

        // Explicit bounds check for BPF verifier
        if (idx >= MAX_COMPONENTS)
            break;

        key.state = state;
        key.component_hash = buf->hashes[idx & (MAX_COMPONENTS - 1)];

        struct path_state_value *val = bpf_map_lookup_elem(&path_states, &key);

        if (!val) {
            // Try wildcard match (component_hash = 0 means match any)
            key.component_hash = 0;
            val = bpf_map_lookup_elem(&path_states, &key);
        }

        if (!val) {
            // No transition, no rule
            return 0;
        }

        if (val->is_terminal) {
            return val->decision ? 1 : -13;
        }

        state = val->next_state;
    }

    // Reached end without terminal state - check if current state is accepting
    key.state = state;
    key.component_hash = 0;  // End-of-path marker
    struct path_state_value *final = bpf_map_lookup_elem(&path_states, &key);
    if (final && final->is_terminal) {
        return final->decision ? 1 : -13;
    }

    return 0;  // No rule matched
}

// Helper to check and migrate pending enrollment to task_storage
static __always_inline void check_pending_enrollment(struct task_struct *task, u32 pid)
{
    struct process_info *pending = bpf_map_lookup_elem(&pending_enrollments, &pid);
    if (!pending || pending->pod_id == 0) {
        return;
    }

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (info) {
        info->pod_id = pending->pod_id;
        info->role_id = pending->role_id;
        info->stack_depth = pending->stack_depth;
        info->flags = pending->flags;
    }

    // Remove from pending after migration
    bpf_map_delete_elem(&pending_enrollments, &pid);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags, u64 stack_start)
{
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!info) {
        return 0;
    }

    // Try to inherit from parent (for fork/clone)
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct process_info *parent_info = bpf_task_storage_get(&task_storage, current_task, NULL, 0);

    if (parent_info && parent_info->pod_id != 0) {
        // Inherit from parent
        info->pod_id = parent_info->pod_id;
        info->role_id = parent_info->role_id;
        info->stack_depth = parent_info->stack_depth;
        info->flags = parent_info->flags;
    } else {
        // Initialize new task
        info->pod_id = 0;
        info->role_id = 0;
        info->stack_depth = 0;
        info->flags = 0;
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check for pending enrollment and migrate to task_storage
    check_pending_enrollment(task, pid);

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, 0);
        return -13;
    }

    // Get dentry from file->f_path using CO-RE
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

    if (dentry) {
        // Get current cache generation
        u32 zero = 0;
        u32 *gen_ptr = bpf_map_lookup_elem(&cache_generation, &zero);
        u32 current_gen = gen_ptr ? *gen_ptr : 0;

        // Check inode cache first
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);

        if (inode) {
            // Zeroed explicitly: padded key, see path_state_key above.
            struct inode_cache_key cache_key;
            __builtin_memset(&cache_key, 0, sizeof(cache_key));
            cache_key.role_id = info->role_id;
            cache_key.inode = (u64)inode;
            struct inode_cache_value *cached = bpf_map_lookup_elem(&inode_cache, &cache_key);
            if (cached && cached->generation == current_gen) {
                // Cache hit with valid generation
                if (cached->decision)
                    return 0;  // Allow
                emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                                 AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, cache_key.inode);
                return -13;    // Deny
            }
        }

        // Get per-CPU path buffer
        struct path_components *buf = bpf_map_lookup_elem(&path_buf, &zero);

        if (buf) {
            // Collect path components by walking dentry tree
            collect_path_components(dentry, buf);

            // Run state machine
            int result = check_path_state_machine(info->role_id, buf);

            if (result != 0) {
                // Cache the decision with current generation
                if (inode) {
                    // Zeroed explicitly: padded key, see path_state_key above.
                    struct inode_cache_key cache_key;
                    __builtin_memset(&cache_key, 0, sizeof(cache_key));
                    cache_key.role_id = info->role_id;
                    cache_key.inode = (u64)inode;
                    struct inode_cache_value val = {
                        .decision = (result == 1) ? 1 : 0,
                        .generation = current_gen,
                    };
                    bpf_map_update_elem(&inode_cache, &cache_key, &val, 0);
                }

                if (result == 1) {
                    return 0;   // Explicit allow
                }
                emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                                 AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN,
                                 inode ? (u64)inode : 0);
                return -13;     // Explicit deny
            }
        }
    }

    // No path rule matched - fall back to role_flags
    if (!(*flags & 0x01)) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_FILE_OPEN, 0);
        return -13;  // File access blocked by role
    }

    return 0;
}

// Helper to convert network byte order to host byte order (big endian to little endian)
static __always_inline u16 bpf_ntohs(__be16 val)
{
    return (val >> 8) | (val << 8);
}

// Helper to check if IP matches a CIDR rule
// ip_addr and rule_ip should both be in network byte order
static __always_inline int ip_matches_cidr(u32 ip_addr, u32 rule_ip, u8 prefix_len)
{
    if (prefix_len == 0) {
        return 1;  // /0 matches everything
    }
    if (prefix_len >= 32) {
        return ip_addr == rule_ip;
    }

    // Create mask for prefix_len bits (in network byte order)
    // Network byte order is big-endian, so mask from MSB
    u32 mask = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i < prefix_len) {
            mask |= (1 << (31 - i));
        }
    }
    // Convert mask to network byte order
    mask = __builtin_bswap32(mask);

    return (ip_addr & mask) == (rule_ip & mask);
}

// Check IP-based egress rules
// Returns: 1 = explicit allow, 0 = no rule, -13 = explicit deny
static __always_inline int check_ip_access(u32 role_id, u32 ip_addr, u8 direction)
{
    // Check exact IP match first (prefix_len = 32)
    struct ip_rule_key key = {
        .role_id = role_id,
        .ip_addr = ip_addr,
        .prefix_len = 32,
        .direction = direction,
    };

    u8 *rule = bpf_map_lookup_elem(&ip_rules, &key);
    if (rule) {
        return *rule ? 1 : -13;
    }

    // Check common CIDR prefixes (24, 16, 12, 8, 0)
    // Note: Full LPM would require BPF_MAP_TYPE_LPM_TRIE, this is simplified
    u8 prefixes[] = {24, 16, 12, 8, 0};
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        u8 prefix = prefixes[i];

        // Mask the IP to get network address
        u32 mask = 0;
        if (prefix > 0) {
            #pragma unroll
            for (int j = 0; j < 32; j++) {
                if (j < prefix) {
                    mask |= (1 << (31 - j));
                }
            }
            mask = __builtin_bswap32(mask);
        }

        key.ip_addr = ip_addr & mask;
        key.prefix_len = prefix;

        rule = bpf_map_lookup_elem(&ip_rules, &key);
        if (rule) {
            return *rule ? 1 : -13;
        }
    }

    return 0;  // No rule found
}

// Check if connection is to the configured proxy
static __always_inline int is_proxy_connection(u32 role_id, u32 ip_addr, u16 port)
{
    struct proxy_config *config = bpf_map_lookup_elem(&proxy_config, &role_id);
    if (!config || !config->require_proxy) {
        return 0;  // No proxy requirement
    }

    // Check if destination is the proxy
    return (ip_addr == config->proxy_ip && port == config->proxy_port);
}

// Check proxy enforcement
// Returns: 0 = allowed, -13 = blocked (not going through proxy)
// Resolve a destination IP back to the domain it was resolved from, then
// consult that role's domain rules.
//
// dns_cache is populated by userspace: at policy load each domain in a role's
// domain_rules is resolved and every returned address recorded. BPF cannot
// parse DNS itself -- the verifier will not accept it -- so this is name
// filtering approximated by address, with the limits that implies:
//
//   * an address that changes after load is not covered until the next refresh
//   * a host serving several names shares one entry, last writer wins
//   * a process that resolves a name itself and connects to some other address
//     is not caught, because nothing here observes the resolution
//
// Returns 1 to allow, -13 to deny, 0 when the address is unknown to us and the
// decision belongs to the rules that follow.
static __always_inline int check_domain_access(u32 role_id, u32 ip_addr)
{
    if (ip_addr == 0)
        return 0;

    struct dns_cache_key ck = {
        .role_id = role_id,
        .ip_addr = ip_addr,
    };
    struct dns_cache_value *cached = bpf_map_lookup_elem(&dns_cache, &ck);
    if (!cached)
        return 0;  // address not associated with any name we were told about

    // Zeroed explicitly: padded key, see path_state_key above.
    struct domain_rule_key dk;
    __builtin_memset(&dk, 0, sizeof(dk));
    dk.role_id = role_id;
    dk.domain_hash = cached->domain_hash;
    u8 *allow = bpf_map_lookup_elem(&domain_rules, &dk);
    if (!allow)
        return 0;  // name known, but this role has no rule for it

    return *allow ? 1 : -13;
}

static __always_inline int check_proxy_requirement(u32 role_id, u32 ip_addr, u16 port)
{
    struct proxy_config *config = bpf_map_lookup_elem(&proxy_config, &role_id);
    if (!config || !config->require_proxy) {
        return 0;  // No proxy requirement, allow
    }

    // If proxy is required, only allow connections to the proxy itself
    if (ip_addr == config->proxy_ip && port == config->proxy_port) {
        return 0;  // Connection to proxy is allowed
    }

    // Also allow localhost connections (for local services)
    // 127.0.0.0/8 in network byte order
    u32 localhost_mask = 0x000000FF;  // 127.x.x.x in network byte order (big endian)
    if ((ip_addr & localhost_mask) == 0x0000007F) {
        return 0;  // Localhost allowed
    }

    return -13;  // Block non-proxy connections
}

// Check network access based on port/protocol rules
// Returns: 1 = explicit allow, 0 = no rule (defer to role_flags), -13 = explicit deny
static __always_inline int check_network_access(u32 role_id, struct socket *sock,
                                                  struct sockaddr *address, u8 direction)
{
    u16 port = 0;
    u8 protocol = 0;

    // Determine protocol from socket type
    short sock_type = 0;
    bpf_probe_read_kernel(&sock_type, sizeof(sock_type), &sock->type);

    if (sock_type == SOCK_STREAM) {
        protocol = PROTO_TCP;
    } else if (sock_type == SOCK_DGRAM) {
        protocol = PROTO_UDP;
    } else {
        // Unknown socket type, fall back to role_flags
        return 0;
    }

    // Extract port from address
    unsigned short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr4->sin_port);
        port = bpf_ntohs(be_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr6->sin6_port);
        port = bpf_ntohs(be_port);
    } else {
        // Unknown address family, no rule
        return 0;
    }

    // Check specific port rule first
    struct net_rule_key key = {
        .role_id = role_id,
        .port = port,
        .protocol = protocol,
        .direction = direction,
    };

    u8 *rule = bpf_map_lookup_elem(&network_rules, &key);
    if (rule) {
        // Specific rule found
        return *rule ? 1 : -13;  // 1 = explicit allow, -13 = explicit deny
    }

    // Check wildcard port rule (port = 0 means all ports)
    key.port = 0;
    rule = bpf_map_lookup_elem(&network_rules, &key);
    if (rule) {
        return *rule ? 1 : -13;
    }

    // No specific rule, fall back to role_flags
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;
    }

    int result = check_network_access(info->role_id, sock, address, 0);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_BIND, 0);
        return -13;  // Explicit deny overrides role_flags
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;
    }

    // Check role_flags first (bit 1 = network allowed)
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, 0);
        return -13;
    }

    // Extract IP address and port for additional checks
    u32 dest_ip = 0;
    u16 dest_port = 0;
    unsigned short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &addr4->sin_addr.s_addr);
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr4->sin_port);
        dest_port = bpf_ntohs(be_port);
    } else if (family == AF_INET6) {
        // For IPv6, extract the port (IP filtering is IPv4 only for now)
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        __be16 be_port = 0;
        bpf_probe_read_kernel(&be_port, sizeof(be_port), &addr6->sin6_port);
        dest_port = bpf_ntohs(be_port);
    }
    // Check proxy requirement first (if configured)
    if (dest_ip != 0) {
        int proxy_result = check_proxy_requirement(info->role_id, dest_ip, dest_port);
        if (proxy_result == -13) {
            emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                             AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, dest_ip);
            return -13;  // Blocked: not going through required proxy
        }
    }

    // Check domain rules first: they are the most specific statement of intent
    // the operator can make about an egress destination.
    if (dest_ip != 0) {
        int domain_result = check_domain_access(info->role_id, dest_ip);
        if (domain_result == -13) {
            emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                             AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, dest_ip);
            return -13;
        }
        if (domain_result == 1) {
            return 0;
        }
    }

    // Check IP-based rules (only for IPv4)
    if (dest_ip != 0) {
        int ip_result = check_ip_access(info->role_id, dest_ip, 1);  // direction=1 for connect
        if (ip_result == -13) {
            emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                             AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, dest_ip);
            return -13;  // IP explicitly blocked
        }
        if (ip_result == 1) {
            return 0;  // IP explicitly allowed
        }
    }

    // Fall back to port/protocol rules
    int result = check_network_access(info->role_id, sock, address, 1);

    if (!(*flags & 0x02)) {
        // Network blocked by role - only allow if explicit allow rule (result=1)
        if (result == 1) {
            return 0;  // Explicit allow overrides role_flags
        }
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, dest_ip);
        return -13;  // No rule or explicit deny -> block
    }

    // Network allowed by role - only block if explicit deny rule (result=-13)
    if (result == -13) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_SOCKET_CONNECT, dest_ip);
        return -13;  // Explicit deny overrides role_flags
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check for pending enrollment and migrate to task_storage
    check_pending_enrollment(task, pid);

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!info) {
        return 0;
    }

    // Track if this process was already enrolled before this exec
    u8 was_enrolled = (info->pod_id != 0);

    // If not enrolled, check for auto-enrollment by executable inode
    if (info->pod_id == 0) {
        // Get executable file's inode
        struct file *exe_file = BPF_CORE_READ(bprm, file);
        if (exe_file) {
            struct inode *exe_inode = BPF_CORE_READ(exe_file, f_inode);
            if (exe_inode) {
                u64 ino = BPF_CORE_READ(exe_inode, i_ino);
                struct exec_enrollment_value *enroll = bpf_map_lookup_elem(&exec_enrollment, &ino);
                if (enroll) {
                    // Auto-enroll based on executable
                    info->pod_id = enroll->pod_id;
                    info->role_id = enroll->role_id;
                    info->stack_depth = 0;
                    info->flags = 0;
                    // This is the initial enrollment, allow the exec
                    return 0;
                }
            }
        }
    }

    // If still not enrolled, check for auto-enrollment by cgroup
    if (info->pod_id == 0) {
        u64 cgroup_id = bpf_get_current_cgroup_id();
        struct exec_enrollment_value *enroll = bpf_map_lookup_elem(&cgroup_enrollment, &cgroup_id);
        if (enroll) {
            // Auto-enroll based on cgroup
            info->pod_id = enroll->pod_id;
            info->role_id = enroll->role_id;
            info->stack_depth = 0;
            info->flags = 0;
            // This is the initial enrollment, allow the exec
            return 0;
        }
    }

    // If still not enrolled, allow execution
    if (info->pod_id == 0) {
        return 0;
    }

    // Process was already enrolled - check exec permission for spawning child
    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -13;
    }

    // Only check allow_exec for CHILD processes (when already enrolled)
    if (was_enrolled && !(*flags & 0x04)) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -13;
    }

    return 0;
}

// Invalidate inode cache on rename - file path changed but inode stays same
SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    // Get the inode of the file being renamed
    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode)
        return 0;

    // We can't easily iterate and delete all entries for this inode across all roles
    // Instead, increment the global generation counter to invalidate all cached entries
    // This is a simple but effective approach for handling renames
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow rename, just invalidate cache
}

// Invalidate entire cache on mount/unmount - paths may resolve differently
SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    // Increment generation to invalidate all cached path decisions
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow mount, just invalidate cache
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
    // Increment generation to invalidate all cached path decisions
    u32 zero = 0;
    u32 *gen = bpf_map_lookup_elem(&cache_generation, &zero);
    if (gen) {
        __sync_fetch_and_add(gen, 1);
    }

    return 0;  // Always allow umount, just invalidate cache
}

// Block ptrace/debugging of enrolled processes
// Flag: 0x20 = allow_ptrace
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    // Check if the TARGET (child) is enrolled and protected
    struct process_info *child_info = bpf_task_storage_get(&task_storage, child, NULL, 0);

    if (!child_info || child_info->pod_id == 0) {
        return 0;  // Target not enrolled, allow ptrace
    }

    // Target is enrolled - check if its role allows being ptraced
    u8 *flags = bpf_map_lookup_elem(&role_flags, &child_info->role_id);
    if (!flags) {
        return -1;  // No flags found, deny ptrace
    }

    if (!(*flags & 0x20)) {
        // allow_ptrace = false, block debugging
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        emit_audit_event(ctx, pid, child_info->role_id, child_info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -1;
    }

    return 0;
}

// Block kernel module loading by enrolled processes
// Flag: 0x40 = allow_module_load
SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request, char *kmod_name)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;  // Not enrolled, allow module load
    }

    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -1;
    }

    if (!(*flags & 0x40)) {
        // allow_module_load = false, block module loading
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -1;
    }

    return 0;
}

// Block BPF program loading by enrolled processes
// Flag: 0x80 = allow_bpf_load
SEC("lsm/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_info *info = bpf_task_storage_get(&task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        return 0;  // Not enrolled, allow BPF operations
    }

    u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags) {
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -1;
    }

    if (!(*flags & 0x80)) {
        // allow_bpf_load = false, block BPF operations
        emit_audit_event(ctx, pid, info->role_id, info->pod_id,
                         AUDIT_DECISION_DENY, AUDIT_HOOK_BPRM_CHECK, 0);
        return -1;
    }

    return 0;
}

// =============================================================================
// DNS Interception for Domain-based Filtering (Simplified)
// =============================================================================
// Note: Full DNS parsing is too complex for BPF verifier, so domain
// filtering is done at IP level in check_domain_access() above, against a
// dns_cache that userspace populates by resolving each policy domain.

#define DNS_PORT 53
#define AUDIT_HOOK_DNS_QUERY 6

// Simplified socket_sendmsg hook - just monitors DNS traffic
// Full domain parsing would be done in userspace via audit events
SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    // For now, allow all sendmsg - domain filtering relies on:
    // 1. IP rules blocking private networks
    // 2. Userspace DNS proxy for domain-level filtering
    // Full BPF DNS parsing requires kernel 5.19+ with more helper functions
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
