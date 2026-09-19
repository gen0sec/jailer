//! What build is this?
//!
//! Neither binary could answer that. Nothing printed a version, nothing
//! compiled one in, and the repository had no tags -- so the only way to
//! identify what was installed on a host was to hash the binary and compare it
//! against a build you still had lying around.
//!
//! That is a gap the bootstrap's build id does not close: the build id
//! (`/run/bpfjailer/build-id`) identifies the *BPF object* a pin set came from,
//! which is what the staleness check needs, and deliberately says nothing about
//! the loader that wrote it.

/// The workspace version, which every crate here inherits from
/// `[workspace.package]` and `cargo release` owns.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The line to print when argv asks for the version, or `None` when it does
/// not.
///
/// Kept as a value rather than a function that prints and exits so it can be
/// tested; the caller does the printing.
pub fn version_line<I, S>(args: I, binary: &str) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|a| matches!(a.as_ref(), "--version" | "-V"))
        .then(|| format!("{binary} {VERSION}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOTSTRAP_SRC: &str = include_str!("../../bpfjailer-bootstrap/src/main.rs");
    const DAEMON_SRC: &str = include_str!("../../bpfjailer-daemon/src/main.rs");

    #[test]
    fn the_long_and_short_forms_are_both_accepted() {
        assert_eq!(
            version_line(["--version"], "bpfjailer-daemon"),
            Some(format!("bpfjailer-daemon {VERSION}"))
        );
        assert_eq!(
            version_line(["-V"], "bpfjailer-bootstrap"),
            Some(format!("bpfjailer-bootstrap {VERSION}"))
        );
    }

    /// The release workflow greps the tag out of this line, so it has to be
    /// exactly `<binary> <version>` with nothing else on it.
    #[test]
    fn the_line_is_the_binary_name_then_the_version() {
        let line = version_line(["--version"], "bpfjailer-daemon").expect("asked for it");
        let mut parts = line.split(' ');
        assert_eq!(parts.next(), Some("bpfjailer-daemon"));
        assert_eq!(parts.next(), Some(VERSION));
        assert_eq!(parts.next(), None);
    }

    #[test]
    fn nothing_else_triggers_it() {
        assert_eq!(version_line(Vec::<String>::new(), "x"), None);
        assert_eq!(version_line(["--help", "-v", "version"], "x"), None);
    }

    /// `cargo release` bumps `[workspace.package].version`; every crate
    /// inherits it. If a member ever stopped inheriting, this crate's version
    /// would keep moving while that binary's stood still -- and the version it
    /// printed would be a lie rather than an error.
    #[test]
    fn the_members_inherit_the_workspace_version() {
        for manifest in [
            include_str!("../../bpfjailer-bootstrap/Cargo.toml"),
            include_str!("../../bpfjailer-daemon/Cargo.toml"),
            include_str!("../Cargo.toml"),
        ] {
            assert!(
                manifest.contains("version.workspace = true"),
                "a crate pins its own version instead of inheriting the \
                 workspace one, so `cargo release` cannot keep them in step"
            );
        }
    }

    /// Both binaries must actually wire this up. A release that cannot report
    /// its own version has nothing to smoke-test the built artifact with.
    #[test]
    fn both_binaries_answer_the_version_flag() {
        for (name, src) in [
            ("bpfjailer-bootstrap", BOOTSTRAP_SRC),
            ("bpfjailer-daemon", DAEMON_SRC),
        ] {
            assert!(
                src.contains("version::version_line"),
                "{name} does not handle --version"
            );
        }
    }
}
