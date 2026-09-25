# CIS mapping for the default `cis_*` roles

The reference is the **CIS Distribution Independent Linux Benchmark v2.0.0**.
It is the applicable document for any Linux that has no benchmark of its own.

**BpfJailer satisfies none of its controls, and this page exists to say so
precisely.** Every control in that benchmark is written against a file mode, an
installed package, or a line in a configuration file. BpfJailer changes none of
those — it denies operations at runtime. A scanner will not score a host higher
because these roles are enrolled.

What the roles give you is enforcement of the *thing several of those controls
are protecting*, at a point a file mode cannot reach: a process that already has
root still cannot open `/etc/shadow` if it is enrolled in one of these roles.
That is worth having. It is not compliance, and a compliance report should not
claim it is.

## The three tiers

| role | id | file | network | exec | ptrace | module load | BPF load |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cis_baseline` | 14 | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `cis_service` | 15 | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `cis_isolated` | 16 | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

Each tier is strictly stricter than the one above it; nothing a looser tier
denies is permitted by a tighter one. That is asserted in the test suite, not
just documented here.

- **`cis_baseline`** — safe to enrol anything into, including sshd. It denies
  only paths no process opens in normal operation, and grants file access,
  network and exec.
- **`cis_service`** — a network daemon. No exec, and the SSH host keys are
  denied as well.
- **`cis_isolated`** — `cis_service` with no network at all.

All three deny ptrace, kernel module loading and BPF program loading.

## The deny set

Shared by all three tiers:

```
/etc/shadow  /etc/gshadow  /etc/shadow-  /etc/gshadow-
/root/
/boot/
/etc/audit/
/etc/sudoers  /etc/sudoers.d/
```

`cis_service` and `cis_isolated` add `/etc/ssh/`.

Available to Rust callers building a role at runtime as
`SecretPatterns::cis_hardening()`; a test asserts the preset and the shipped
JSON never diverge.

## Control by control

### Closest to enforcing a control

**3.4.1–3.4.4 — DCCP, SCTP, RDS, TIPC disabled.** All three tiers set
`allow_module_load: false`, which denies `lsm/kernel_module_request`. Those four
protocols reach a system by kernel autoload when something calls `socket()` for
them, and that is exactly the path being denied — so for an enrolled process the
effect is the one the control wants.

Two honest limits. It covers **autoload only**: an explicit `insmod` or
`finit_module` by root is a different path and is not denied here. And it applies
only to enrolled processes, whereas the control's `install ... /bin/true` lines
in `modprobe.d` apply to the whole host. Use the modprobe blacklists *and* this;
neither replaces the other.

### Complements a control — enforces the access, not the mode

| Control | What CIS checks | What the roles do |
| --- | --- | --- |
| 6.1.3, 6.1.5 | `/etc/shadow`, `/etc/gshadow` mode `0000`/`0640` | deny the open outright |
| 6.1.7, 6.1.9 | `/etc/shadow-`, `/etc/gshadow-` modes | deny the open outright |
| 5.2.2 | SSH private host key files mode `0600` | `cis_service`/`cis_isolated` deny `/etc/ssh/` |
| 1.4 | bootloader config owned by root, mode `0600` | deny `/boot/` |
| 4.1 | auditd installed, enabled, configured | deny writes to `/etc/audit/` |
| 4.1.16 | changes to `/etc/sudoers` are collected | deny `/etc/sudoers`, `/etc/sudoers.d/` |

The difference matters when you write it down: CIS restricts *who* may open the
file by uid; these roles restrict *which processes* may open it at all,
including processes running as root. A host can pass 6.1.3 and still have every
daemon able to read `/etc/shadow`. It can also fail 6.1.3 while these roles stop
the read. They are independent properties.

### Cannot be expressed

**6.1.2, 6.1.4 — `/etc/passwd` and `/etc/group` mode `0644`.** These want
read-allowed, write-denied. The `lsm/file_open` hook receives only
`struct file *` and nothing in the BPF source reads `f_mode` or `f_flags`, so a
rule can only deny the open, not the write. Denying either file would break
username resolution in essentially every service, so neither is in the deny set.
If you need write protection on those, that is a file mode or an auditd watch,
not a jailer rule.

**1.6.1.1 — SELinux or AppArmor installed.** The control checks for `libselinux`
or `apparmor` as installed *packages*. BpfJailer is a mandatory access control
implementation and 1.6.1.1 will still fail with it in place, because the control
enumerates two named frameworks rather than describing a property. The
subsections beneath it (1.6.2.x SELinux, 1.6.3.x AppArmor) are guarded on the
respective package being installed and are simply skipped.

Record this as a documented deviation with the enforcement you do have described
against it. Do not record it as met.

## Enrolling

These roles enforce nothing until a process is enrolled in one. Nothing in the
shipped policy enrols anything — `exec_enrollments` and `cgroup_enrollments` are
empty, deliberately, because which processes to confine is a property of your
system and not of this package.

```json
"exec_enrollments": [
  { "executable_path": "/usr/sbin/my-daemon", "pod_id": 3000, "role": "cis_service" }
]
```

Two things to know before you do.

**Exec enrollment is keyed on the binary's inode, not its path.** A package
upgrade that replaces the file silently drops the enrollment. Re-apply policy
after upgrades, or enrol by cgroup instead.

**A role attached at or above a container's cgroup slice must be permissive
enough for the runtime, not just the workload.** A container runtime does its
setup inside the container's cgroup and opens `/proc/<pid>/ns/*`, which the
kernel gates behind `ptrace_may_access()` — so `allow_ptrace: false` at that
level stops containers starting at all. Enrol the workload, not the slice.

## What is not in these roles, and why

**No `network_rules`.** The benchmark prescribes no port list; 3.5 is about
having a host firewall with a default-deny policy, which is nftables' or
iptables' job. `allow_network` is the only part of that jailer can express.

**No `execution_rules`.** No control in the benchmark maps to allowing or
denying specific binaries.

**No `ip_rules`, `domain_rules` or `proxy`.** Those maps are not pinned, so in
daemonless mode they are written and then lost when the bootstrap exits. A rule
that silently stops applying is worse than one that was never written.

**No pattern deeper than three components.** A path longer than
`MAX_COMPONENTS` (16) reports no rule rather than a decision, and for a role
with `allow_file_access: true` that reads as *allowed*. A deep deny would
silently invert; every pattern here is shallow enough that it cannot.
