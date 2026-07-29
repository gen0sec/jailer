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
    | FLAG_ALLOW_PTRACE
    | FLAG_ALLOW_MODULE_LOAD
    | FLAG_ALLOW_BPF_LOAD;

/// Names of flags a role sets that the BPF side does not enforce.
///
/// `require_signed_binary` and `allow_setuid` are accepted by the policy
/// schema and written into `role_flags`, but `main.bpf.c` never tests those
/// bits. A policy asking for them therefore gets no enforcement. Callers use
/// this to refuse such a policy rather than apply it and look protected.
///
/// Only restrictive intent is reported: `allow_setuid: true` grants something
/// that is unrestricted anyway, so it is not misleading. `allow_setuid: false`
/// asks for a restriction that will not happen, and is.
pub fn unenforced_flags(flags: &PolicyFlags) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags.require_signed_binary {
        out.push("require_signed_binary");
    }
    if !flags.allow_setuid {
        out.push("allow_setuid=false");
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
        // main.bpf.c tests 0x01, 0x02, 0x04, 0x20, 0x40, 0x80.
        assert_eq!(ENFORCED_FLAGS, 0x01 | 0x02 | 0x04 | 0x20 | 0x40 | 0x80);
        assert_eq!(
            ENFORCED_FLAGS & FLAG_REQUIRE_SIGNED_BINARY,
            0,
            "require_signed_binary is not enforced"
        );
        assert_eq!(
            ENFORCED_FLAGS & FLAG_ALLOW_SETUID,
            0,
            "allow_setuid is not enforced"
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

    #[test]
    fn denying_setuid_is_reported_because_it_will_not_happen() {
        let mut f = permissive();
        f.allow_setuid = false;
        assert_eq!(unenforced_flags(&f), vec!["allow_setuid=false"]);
    }

    #[test]
    fn granting_setuid_is_not_reported() {
        // allow_setuid: true asks for nothing to be restricted, which is what
        // happens anyway -- not misleading.
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
            vec!["require_signed_binary", "allow_setuid=false"]
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
