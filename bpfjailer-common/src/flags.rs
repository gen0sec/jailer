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
/// `require_signed_binary` and `allow_setuid` are accepted by the policy schema
/// and written into `role_flags`, but `main.bpf.c` never tests those bits. A
/// policy asking for them therefore gets no enforcement. Callers use this to
/// refuse such a policy rather than apply it and look protected.
///
/// `allow_setuid` was briefly moved into [`ENFORCED_FLAGS`] on the strength of
/// a `bprm_check_security` gate reading `bprm->secureexec`. That gate could
/// never fire: `bprm_fill_uid`, which sets the bit, runs from
/// `bprm_creds_from_file` inside `begin_new_exec`, which `load_binary` reaches
/// only AFTER `search_binary_handler` has already called
/// `security_bprm_check`. The bit is always 0 there. Enforcing it needs the
/// `bprm_creds_from_file` hook instead; until then this stays honest and the
/// policy is refused.
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

    /// Derived from the BPF source, not restated as a literal.
    ///
    /// This test used to assert `ENFORCED_FLAGS` against a hand-written
    /// constant with a comment listing the bits. That is what let `0x10` be
    /// declared enforced on the strength of a gate that could never fire: the
    /// comment and the literal were both edited to agree with the claim, and
    /// nothing checked the claim against `main.bpf.c`. Scanning the source is
    /// what `maps.rs` and `programs.rs` do, and it is what catches this.
    #[test]
    fn enforced_set_matches_the_bits_the_bpf_source_tests() {
        const BPF_SOURCE: &str = include_str!("../../bpfjailer-bpf/src/main.bpf.c");

        let mut tested = 0u8;
        for (at, _) in BPF_SOURCE.match_indices("flags & 0x") {
            let rest = &BPF_SOURCE[at + "flags & 0x".len()..];
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if let Ok(bit) = u8::from_str_radix(&hex, 16) {
                tested |= bit;
            }
        }

        assert_ne!(tested, 0, "the `flags & 0x..` scan found nothing");
        assert_eq!(
            ENFORCED_FLAGS, tested,
            "ENFORCED_FLAGS says {ENFORCED_FLAGS:#04x} but main.bpf.c tests \
             {tested:#04x}; a bit claimed here that the BPF side never reads is \
             a restriction the operator is told is in force and is not"
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
