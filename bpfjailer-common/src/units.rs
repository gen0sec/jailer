//! What the shipped systemd units must let the binaries do.
//!
//! Both units run under `ProtectSystem=strict` with `ReadOnlyPaths=/`, so every
//! path a binary writes has to be granted back explicitly. Nothing tied the two
//! halves together, and they drifted: the bootstrap gained
//! `/run/bpfjailer/build-id` and `pin_all` propagates a failure to write it, but
//! its unit still granted only `/sys/fs/bpf`. Under its own unit the bootstrap
//! therefore pinned every program and map and *then* exited non-zero.
//!
//! No test could catch that by running anything -- CI has no systemd, and the
//! binaries work perfectly when run by hand. But the unit is a file, and the
//! paths are constants in the source, so the two can be compared directly.
//!
//! The path lists below are not hand-maintained: the source is scanned for
//! absolute path constants, and a constant that is not classified here fails
//! the suite. Forgetting to add one is the failure this module exists to
//! prevent, so forgetting is what it refuses to allow.

#[cfg(test)]
mod tests {
    /// How a binary uses an absolute path at runtime.
    ///
    /// Only [`Access::Writes`] needs a grant from the unit; a read succeeds under
    /// `ReadOnlyPaths=/` unaided.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Access {
        Writes,
        Reads,
    }

    /// Paths under a `RuntimeDirectory=`/`ReadWritePaths=` grant, i.e. the writable
    /// prefixes a unit establishes.
    fn writable_prefixes(unit: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in unit.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("ReadWritePaths=") {
                // Space-separated, and the directive may repeat. A leading `-`
                // marks the path optional to systemd; it grants the same access.
                out.extend(
                    v.split_whitespace()
                        .map(|p| p.trim_start_matches('-').to_string()),
                );
            } else if let Some(v) = line.strip_prefix("RuntimeDirectory=") {
                // systemd creates /run/<name> and makes it writable for the unit.
                out.extend(
                    v.split_whitespace()
                        .map(|name| format!("/run/{}", name.trim_start_matches('-'))),
                );
            }
        }
        out
    }

    /// Whether `path` falls under any prefix the unit makes writable.
    ///
    /// Prefix matching is on whole components, so `/run/bpfjailer` does not cover
    /// `/run/bpfjailer-other`.
    fn is_writable(path: &str, prefixes: &[String]) -> bool {
        prefixes
            .iter()
            .any(|p| path == p || path.starts_with(&format!("{}/", p.trim_end_matches('/'))))
    }

    /// Absolute path constants declared in a Rust source file.
    ///
    /// Matches both `const NAME: &str = "/x";` and the associated-const form
    /// `pub const NAME: &'static str = "/x";`. Relative paths are ignored: they
    /// resolve against the working directory, which systemd sets to `/`, and are
    /// fallbacks for running out of a build tree rather than installed layout.
    fn absolute_path_constants(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line
                .strip_prefix("pub const ")
                .or_else(|| line.strip_prefix("const "))
            else {
                continue;
            };
            let Some((name, value)) = rest.split_once(':') else {
                continue;
            };
            let Some((ty, literal)) = value.split_once('=') else {
                continue;
            };
            if !matches!(ty.trim(), "&str" | "&'static str") {
                continue;
            }
            let literal = literal.trim().trim_end_matches(';').trim();
            let Some(path) = literal.strip_prefix('"').and_then(|p| p.strip_suffix('"')) else {
                continue;
            };
            if path.starts_with('/') {
                out.push((name.trim().to_string(), path.to_string()));
            }
        }
        out
    }

    const BOOTSTRAP_UNIT: &str = include_str!("../../config/bpfjailer-bootstrap.service");
    const DAEMON_UNIT: &str = include_str!("../../config/bpfjailer-daemon.service");

    const BOOTSTRAP_SRC: &str = include_str!("../../bpfjailer-bootstrap/src/main.rs");
    const DAEMON_MAIN: &str = include_str!("../../bpfjailer-daemon/src/main.rs");
    const DAEMON_LOADER: &str = include_str!("../../bpfjailer-daemon/src/bpf_loader.rs");
    const DAEMON_ENROLLMENT: &str = include_str!("../../bpfjailer-daemon/src/enrollment.rs");

    /// Every absolute path constant, classified by how the binary uses it.
    ///
    /// A constant found in the source but missing here fails
    /// `every_path_constant_is_classified`, which is the point: the last one
    /// added (`BUILD_ID_PATH`) is exactly the one whose unit grant was missed.
    fn classified() -> Vec<(&'static str, Access)> {
        vec![
            // Written: the pin directory, and the build id recorded beside it.
            ("/sys/fs/bpf/bpfjailer", Access::Writes),
            ("/run/bpfjailer/build-id", Access::Writes),
            ("/run/bpfjailer/enrollment.sock", Access::Writes),
            // Read: the policy, loaded and never rewritten.
            ("/etc/bpfjailer/policy.json", Access::Reads),
        ]
    }

    fn access_of(path: &str) -> Option<Access> {
        classified()
            .into_iter()
            .find(|(p, _)| *p == path)
            .map(|(_, a)| a)
    }

    fn writes_in(sources: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = sources
            .iter()
            .flat_map(|s| absolute_path_constants(s))
            .filter(|(_, path)| access_of(path) == Some(Access::Writes))
            .map(|(_, path)| path)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn the_scanner_still_finds_the_constants() {
        let found = absolute_path_constants(BOOTSTRAP_SRC);
        assert!(
            found.len() >= 3,
            "only found {found:?} -- the path-constant scan has stopped working"
        );
        assert!(found.iter().any(|(n, _)| n == "BUILD_ID_PATH"));
        assert!(
            absolute_path_constants(DAEMON_LOADER)
                .iter()
                .any(|(n, _)| n == "BPF_PIN_PATH"),
            "the associated-const form is no longer matched"
        );
    }

    /// A new absolute path constant must be classified before it can ship. If
    /// it is written, the next test then demands the unit grant matching it.
    #[test]
    fn every_path_constant_is_classified() {
        let unclassified: Vec<_> = [BOOTSTRAP_SRC, DAEMON_MAIN, DAEMON_LOADER, DAEMON_ENROLLMENT]
            .iter()
            .flat_map(|s| absolute_path_constants(s))
            .filter(|(_, path)| access_of(path).is_none())
            .collect();

        assert!(
            unclassified.is_empty(),
            "these absolute path constants are not classified in units.rs, so \
                 nothing checks whether the systemd units allow them: {unclassified:?}"
        );
    }

    /// The regression this module exists for: the bootstrap writes
    /// `/run/bpfjailer/build-id` from `pin_all` and propagates the failure, so
    /// a unit that does not grant `/run/bpfjailer` makes it pin everything and
    /// then exit non-zero.
    #[test]
    fn the_bootstrap_unit_grants_every_path_the_bootstrap_writes() {
        let prefixes = writable_prefixes(BOOTSTRAP_UNIT);
        for path in writes_in(&[BOOTSTRAP_SRC]) {
            assert!(
                is_writable(&path, &prefixes),
                "the bootstrap writes {path} but bpfjailer-bootstrap.service \
                     grants only {prefixes:?}; under ProtectSystem=strict the write \
                     fails and the unit exits non-zero"
            );
        }
    }

    #[test]
    fn the_daemon_unit_grants_every_path_the_daemon_writes() {
        let prefixes = writable_prefixes(DAEMON_UNIT);
        for path in writes_in(&[DAEMON_MAIN, DAEMON_LOADER, DAEMON_ENROLLMENT]) {
            assert!(
                is_writable(&path, &prefixes),
                "the daemon writes {path} but bpfjailer-daemon.service grants \
                     only {prefixes:?}"
            );
        }
    }

    /// `ReadWritePaths=` does not create a missing directory, and systemd
    /// refuses to start a unit naming one that does not exist. Both binaries
    /// keep their runtime state under `/run/bpfjailer`, which is a tmpfs and so
    /// is empty on every boot -- it has to be declared, not assumed.
    #[test]
    fn both_units_declare_the_runtime_directory_rather_than_assuming_it() {
        for (name, unit) in [("bootstrap", BOOTSTRAP_UNIT), ("daemon", DAEMON_UNIT)] {
            assert!(
                unit.lines()
                    .any(|l| l.trim() == "RuntimeDirectory=bpfjailer"),
                "the {name} unit keeps state in /run/bpfjailer but does not \
                     declare RuntimeDirectory=bpfjailer, so the directory exists \
                     only if something else happened to create it"
            );
        }
    }

    /// The units must start the binaries whose constants were just checked.
    #[test]
    fn each_unit_starts_the_binary_it_was_checked_against() {
        assert!(BOOTSTRAP_UNIT.contains("ExecStart=/usr/sbin/bpfjailer-bootstrap"));
        assert!(DAEMON_UNIT.contains("ExecStart=/usr/sbin/bpfjailer-daemon"));
    }

    /// Discrimination control: the check above must be capable of failing.
    /// Without this, a unit that granted nothing and a scan that found nothing
    /// would both look like success.
    #[test]
    fn a_path_outside_every_grant_is_not_reported_writable() {
        let prefixes = writable_prefixes(BOOTSTRAP_UNIT);
        assert!(!prefixes.is_empty(), "no grants parsed out of the unit");
        assert!(!is_writable("/etc/bpfjailer/policy.json", &prefixes));
        assert!(!is_writable("/var/lib/bpfjailer/state", &prefixes));
        // Component-wise, so a sibling sharing a textual prefix is not covered.
        assert!(!is_writable("/run/bpfjailer-other/x", &prefixes));
    }

    #[test]
    fn a_runtime_directory_grants_the_path_it_creates() {
        let prefixes = writable_prefixes("RuntimeDirectory=bpfjailer\n");
        assert!(is_writable("/run/bpfjailer/build-id", &prefixes));
        assert!(is_writable("/run/bpfjailer", &prefixes));
    }

    #[test]
    fn read_write_paths_may_repeat_and_list_several() {
        let prefixes =
            writable_prefixes("ReadWritePaths=/sys/fs/bpf /run/x\nReadWritePaths=-/var/y\n");
        assert!(is_writable("/sys/fs/bpf/bpfjailer", &prefixes));
        assert!(is_writable("/run/x/z", &prefixes));
        assert!(is_writable("/var/y/z", &prefixes));
    }
}
