//! Packing of [`PolicyFlags`] into the single byte stored in the BPF
//! `role_flags` map.
//!
//! The BPF programs test individual bits of this byte to decide whether an
//! operation is permitted, so the bit assignment here is the contract between
//! userspace and `bpfjailer-bpf/src/main.bpf.c`.

use crate::types::PolicyFlags;

/// Bit assignments checked by the BPF programs.
pub const FLAG_ALLOW_FILE_ACCESS: u8 = 0x01;
pub const FLAG_ALLOW_NETWORK: u8 = 0x02;
pub const FLAG_ALLOW_EXEC: u8 = 0x04;
pub const FLAG_REQUIRE_SIGNED_BINARY: u8 = 0x08;
pub const FLAG_ALLOW_SETUID: u8 = 0x10;
pub const FLAG_ALLOW_PTRACE: u8 = 0x20;
pub const FLAG_ALLOW_MODULE_LOAD: u8 = 0x40;
pub const FLAG_ALLOW_BPF_LOAD: u8 = 0x80;

/// Pack [`PolicyFlags`] into the byte the BPF `role_flags` map stores.
///
/// `require_proxy` is deliberately absent: all eight bits are taken, and the
/// BPF side reads that setting from `proxy_config` instead.
pub fn policy_flags_to_u8(flags: &PolicyFlags) -> u8 {
    let mut byte = 0u8;
    if flags.allow_file_access {
        byte |= FLAG_ALLOW_FILE_ACCESS;
    }
    if flags.allow_network {
        byte |= FLAG_ALLOW_NETWORK;
    }
    if flags.allow_exec {
        byte |= FLAG_ALLOW_EXEC;
    }
    if flags.require_signed_binary {
        byte |= FLAG_REQUIRE_SIGNED_BINARY;
    }
    if flags.allow_setuid {
        byte |= FLAG_ALLOW_SETUID;
    }
    if flags.allow_ptrace {
        byte |= FLAG_ALLOW_PTRACE;
    }
    if flags.allow_module_load {
        byte |= FLAG_ALLOW_MODULE_LOAD;
    }
    if flags.allow_bpf_load {
        byte |= FLAG_ALLOW_BPF_LOAD;
    }
    byte
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> PolicyFlags {
        PolicyFlags::default()
    }

    fn all() -> PolicyFlags {
        PolicyFlags {
            allow_file_access: true,
            allow_network: true,
            allow_exec: true,
            require_signed_binary: true,
            allow_setuid: true,
            allow_ptrace: true,
            allow_module_load: true,
            allow_bpf_load: true,
            require_proxy: true,
        }
    }

    #[test]
    fn no_flags_packs_to_zero() {
        assert_eq!(policy_flags_to_u8(&none()), 0);
    }

    /// Every flag must reach the byte. The daemon previously packed only the
    /// first three, so a role granting ptrace, module load or BPF load was
    /// silently enforced as if it did not.
    #[test]
    fn every_flag_reaches_the_byte() {
        assert_eq!(policy_flags_to_u8(&all()), 0xFF);
    }

    /// Each flag must land on the bit the BPF programs actually test.
    /// Sets one field on a PolicyFlags, paired with the bit it must produce.
    type FlagCase = (fn(&mut PolicyFlags), u8);

    #[test]
    fn each_flag_maps_to_its_documented_bit() {
        let cases: [FlagCase; 8] = [
            (|f| f.allow_file_access = true, FLAG_ALLOW_FILE_ACCESS),
            (|f| f.allow_network = true, FLAG_ALLOW_NETWORK),
            (|f| f.allow_exec = true, FLAG_ALLOW_EXEC),
            (
                |f| f.require_signed_binary = true,
                FLAG_REQUIRE_SIGNED_BINARY,
            ),
            (|f| f.allow_setuid = true, FLAG_ALLOW_SETUID),
            (|f| f.allow_ptrace = true, FLAG_ALLOW_PTRACE),
            (|f| f.allow_module_load = true, FLAG_ALLOW_MODULE_LOAD),
            (|f| f.allow_bpf_load = true, FLAG_ALLOW_BPF_LOAD),
        ];
        for (set, expected_bit) in cases {
            let mut f = none();
            set(&mut f);
            assert_eq!(
                policy_flags_to_u8(&f),
                expected_bit,
                "flag should set exactly bit {expected_bit:#04x}"
            );
        }
    }

    /// The bit constants must be distinct and cover the byte, or two
    /// permissions would alias onto one bit.
    #[test]
    fn bits_are_distinct_and_cover_the_byte() {
        let bits = [
            FLAG_ALLOW_FILE_ACCESS,
            FLAG_ALLOW_NETWORK,
            FLAG_ALLOW_EXEC,
            FLAG_REQUIRE_SIGNED_BINARY,
            FLAG_ALLOW_SETUID,
            FLAG_ALLOW_PTRACE,
            FLAG_ALLOW_MODULE_LOAD,
            FLAG_ALLOW_BPF_LOAD,
        ];
        let mut seen = 0u8;
        for b in bits {
            assert_eq!(b.count_ones(), 1, "{b:#04x} must be a single bit");
            assert_eq!(seen & b, 0, "{b:#04x} collides with another flag");
            seen |= b;
        }
        assert_eq!(seen, 0xFF, "all eight bits must be assigned");
    }

    /// require_proxy has no bit -- all eight are taken and BPF reads it from
    /// proxy_config. Setting it alone must not disturb the byte.
    #[test]
    fn require_proxy_is_not_packed() {
        let mut f = none();
        f.require_proxy = true;
        assert_eq!(policy_flags_to_u8(&f), 0);
    }

    /// Guards the specific regression: a role that only grants ptrace must not
    /// pack to the same byte as a role that grants nothing.
    #[test]
    fn ptrace_only_role_is_distinguishable_from_empty_role() {
        let mut f = none();
        f.allow_ptrace = true;
        assert_ne!(policy_flags_to_u8(&f), policy_flags_to_u8(&none()));
    }
}

/// Bits the BPF programs actually test.
///
/// Kept as an explicit list so that a flag which is packed but never enforced
/// cannot pass silently: see [`unenforced_flags`].
pub const ENFORCED_FLAGS: u8 = FLAG_ALLOW_FILE_ACCESS
    | FLAG_ALLOW_NETWORK
    | FLAG_ALLOW_EXEC
    | FLAG_ALLOW_SETUID
    | FLAG_ALLOW_PTRACE
    | FLAG_ALLOW_MODULE_LOAD
    | FLAG_ALLOW_BPF_LOAD;

/// Names of flags a role sets that the BPF side does not enforce.
///
/// `require_signed_binary` is accepted by the policy schema and written into
/// `role_flags`, but `main.bpf.c` never tests that bit. A policy asking for it
/// therefore gets no enforcement. Callers use this to refuse such a policy
/// rather than apply it and look protected.
///
/// `allow_setuid` was in the same position until `bprm_check_security` began
/// refusing setuid and setgid binaries and `task_fix_setuid` began refusing
/// credential changes. It is enforced now, so denying it is honoured rather
/// than rejected.
///
/// Only restrictive intent is reported: `allow_setuid: true` grants something
/// that is unrestricted anyway, so it is not misleading. `allow_setuid: false`
/// asks for a restriction that will not happen, and is.
pub fn unenforced_flags(flags: &PolicyFlags) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags.require_signed_binary {
        out.push("require_signed_binary");
    }
    out
}

#[cfg(test)]
mod unenforced_tests {
    use super::*;

    fn permissive() -> PolicyFlags {
        PolicyFlags {
            allow_file_access: true,
            allow_network: true,
            allow_exec: true,
            require_signed_binary: false,
            allow_setuid: true,
            allow_ptrace: true,
            allow_module_load: true,
            allow_bpf_load: true,
            require_proxy: false,
        }
    }

    #[test]
    fn enforced_set_matches_the_bits_bpf_tests() {
        // main.bpf.c tests 0x01, 0x02, 0x04, 0x10, 0x20, 0x40, 0x80.
        assert_eq!(
            ENFORCED_FLAGS,
            0x01 | 0x02 | 0x04 | 0x10 | 0x20 | 0x40 | 0x80
        );
        assert_eq!(
            ENFORCED_FLAGS & FLAG_REQUIRE_SIGNED_BINARY,
            0,
            "require_signed_binary is not enforced"
        );
        assert_ne!(
            ENFORCED_FLAGS & FLAG_ALLOW_SETUID,
            0,
            "allow_setuid is enforced: bprm_check_security refuses setuid and \
             setgid binaries, task_fix_setuid refuses credential changes"
        );
    }

    #[test]
    fn a_fully_enforced_policy_reports_nothing() {
        assert!(unenforced_flags(&permissive()).is_empty());
    }

    #[test]
    fn require_signed_binary_is_reported() {
        let mut f = permissive();
        f.require_signed_binary = true;
        assert_eq!(unenforced_flags(&f), vec!["require_signed_binary"]);
    }

    /// This used to be reported, and refused with it: nothing tested the bit,
    /// so a role denying setuid was told the policy could not be applied. Both
    /// routes to that privilege are now closed, so the request is honoured.
    #[test]
    fn denying_setuid_is_accepted_now_that_it_is_enforced() {
        let mut f = permissive();
        f.allow_setuid = false;
        assert!(unenforced_flags(&f).is_empty());
    }

    #[test]
    fn granting_setuid_is_not_reported() {
        let mut f = permissive();
        f.allow_setuid = true;
        assert!(unenforced_flags(&f).is_empty());
    }

    #[test]
    fn several_unenforced_flags_are_all_reported() {
        let mut f = permissive();
        f.require_signed_binary = true;
        f.allow_setuid = false;
        assert_eq!(
            unenforced_flags(&f),
            vec!["require_signed_binary"],
            "only require_signed_binary is still unenforced"
        );
    }

    #[test]
    fn every_enforced_bit_is_reachable_from_policy_flags() {
        // If a bit is in ENFORCED_FLAGS, some field must be able to set it.
        let all = PolicyFlags {
            allow_file_access: true,
            allow_network: true,
            allow_exec: true,
            require_signed_binary: true,
            allow_setuid: true,
            allow_ptrace: true,
            allow_module_load: true,
            allow_bpf_load: true,
            require_proxy: true,
        };
        assert_eq!(policy_flags_to_u8(&all) & ENFORCED_FLAGS, ENFORCED_FLAGS);
    }
}
