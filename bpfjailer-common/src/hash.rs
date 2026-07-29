//! Hashing shared by the userspace loaders and the BPF programs.
//!
//! The userspace side builds the map keys that the BPF side looks up, so both
//! must produce identical digests. Keeping one implementation here — rather
//! than a copy in each loader — removes the obvious way for them to drift.

/// Bytes of each input fed into the hash.
///
/// Must equal `MAX_COMPONENT_HASH_LEN` in `bpfjailer-bpf/src/main.bpf.c`.
pub const MAX_HASH_LEN: usize = 64;

const FNV1A64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a (64-bit) with the input length folded in.
///
/// Must stay byte-for-byte identical to `hash_component()` in
/// `bpfjailer-bpf/src/main.bpf.c`.
///
/// This replaced a 32-bit djb2 that hashed only the first 32 bytes. That
/// combination produced two classes of false-positive policy match:
///
/// 1. Short collisions from the weak 32-bit mix — `".ssh"` and `"01sh"` both
///    hashed to `0x7c784161`, as did `".aws"` and `".axR"`.
/// 2. Any two inputs sharing a 32-byte prefix collided outright, because
///    everything past byte 32 was discarded.
///
/// The wider digest addresses (1); hashing up to [`MAX_HASH_LEN`] bytes and
/// folding in the length addresses (2) for inputs within that bound.
///
/// # Limitations
///
/// This is an unkeyed hash. It resists *accidental* collisions; it does not
/// stop someone computing a collision offline and naming a file to match. A
/// keyed construction (SipHash with a per-boot key), or verifying the
/// component string after a hash hit, would be needed for that.
///
/// Inputs longer than [`MAX_HASH_LEN`] bytes are still truncated, so two names
/// sharing a 64-byte prefix *and* of equal length collide.
pub fn fnv1a_hash_u64(s: &str) -> u64 {
    let mut hash = FNV1A64_OFFSET_BASIS;
    let mut hashed: u64 = 0;
    for c in s.bytes().take(MAX_HASH_LEN) {
        hash ^= c as u64;
        hash = hash.wrapping_mul(FNV1A64_PRIME);
        hashed += 1;
    }
    hash ^= hashed;
    hash.wrapping_mul(FNV1A64_PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The collisions reported in issue #21 against the old djb2 hash.
    #[test]
    fn reported_djb2_collisions_no_longer_collide() {
        for (a, b) in [(".ssh", "01sh"), (".aws", ".axR")] {
            assert_eq!(djb2_u32(a), djb2_u32(b), "precondition: old hash collided");
            assert_ne!(
                fnv1a_hash_u64(a),
                fnv1a_hash_u64(b),
                "{a:?} and {b:?} still collide"
            );
        }
    }

    /// The old hash read only 32 bytes, so anything sharing a 32-byte prefix
    /// collided regardless of what followed.
    #[test]
    fn shared_prefix_no_longer_collides_within_bound() {
        let a = format!("{}SECRET", "a".repeat(32));
        let b = format!("{}public", "a".repeat(32));
        assert_eq!(
            djb2_u32(&a),
            djb2_u32(&b),
            "precondition: old hash collided"
        );
        assert_ne!(fnv1a_hash_u64(&a), fnv1a_hash_u64(&b));
    }

    /// Length is folded in, so a prefix cannot alias its own extension.
    #[test]
    fn length_is_mixed_in() {
        assert_ne!(fnv1a_hash_u64("etc"), fnv1a_hash_u64("etcd"));
        assert_ne!(fnv1a_hash_u64(""), fnv1a_hash_u64("\0"));
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(fnv1a_hash_u64("/etc/shadow"), fnv1a_hash_u64("/etc/shadow"));
    }

    /// Known-answer test. If this changes, the BPF side must change with it or
    /// every policy silently stops matching.
    #[test]
    fn known_answers_pin_the_algorithm() {
        assert_eq!(fnv1a_hash_u64(""), 0xaf63_bd4c_8601_b7df);
        assert_eq!(fnv1a_hash_u64("etc"), 0xc441_4a60_7a45_4d4a);
        assert_eq!(fnv1a_hash_u64(".ssh"), 0xd05a_cb17_0a18_12d3);
        assert_eq!(fnv1a_hash_u64("/etc/shadow"), 0x994e_56fe_b673_6f3a);
        // Cross-check against an independent restatement of the algorithm.
        for s in ["", "etc", ".ssh", "/etc/shadow"] {
            assert_eq!(fnv1a_hash_u64(s), fnv1a_reference(s), "mismatch for {s:?}");
        }
    }

    /// Beyond MAX_HASH_LEN the input is truncated -- documented, not fixed.
    #[test]
    fn documents_truncation_beyond_bound() {
        let a = format!("{}X", "b".repeat(MAX_HASH_LEN));
        let b = format!("{}Y", "b".repeat(MAX_HASH_LEN));
        assert_eq!(
            fnv1a_hash_u64(&a),
            fnv1a_hash_u64(&b),
            "inputs past MAX_HASH_LEN are truncated; see fn docs"
        );
    }

    /// Independent restatement of the algorithm, so the test does not simply
    /// mirror the implementation it is checking.
    fn fnv1a_reference(s: &str) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut n: u64 = 0;
        for b in s.as_bytes().iter().take(64) {
            h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
            n += 1;
        }
        (h ^ n).wrapping_mul(0x100_0000_01b3)
    }

    /// The hash this replaced, kept only so the tests above can assert the
    /// collisions were real.
    fn djb2_u32(s: &str) -> u32 {
        let mut h: u32 = 5381;
        for c in s.bytes().take(32) {
            h = h.wrapping_mul(33).wrapping_add(c as u32);
        }
        h
    }
}
