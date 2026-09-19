# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the most recent release is supported. This project is pre-1.0 and under
heavy development: policy formats and enforcement behaviour can change between
releases, and fixes land on `main` rather than being backported.

## What this project does and does not enforce

BpfJailer is a mandatory access control tool, so a setting that is accepted but
not applied is a security problem in itself, not a missing feature. Both loaders
therefore **refuse** a policy that asks for something this build cannot enforce,
rather than loading it and appearing to protect the host.

At present that means a policy is rejected if it sets:

- `require_signed_binary` — signature validation is a stub.
- `allow_setuid: false` — the `bprm_check_security` hook runs before the kernel
  evaluates setuid-ness, so the bit it would test is always clear there.
- `execution_rules[].args_pattern` — argv is not readable at `bprm` time, so
  such a rule would silently match on the path alone, which is broader than
  what was written.

If you find a setting that is accepted and *not* enforced, that is a
vulnerability under this policy. Please report it.

## Reporting a Vulnerability

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/gen0sec/jailer/security/advisories/new).

Please do not open a public issue for a suspected vulnerability.

Include the kernel version, the LSM list (`cat /sys/kernel/security/lsm`), the
policy that reproduces it, and whether you were running the daemon or the
bootstrap — the two load the same programs but differ in what they pin, and a
bypass often exists in only one of them.

You can expect an initial response within 7 days. If the report is accepted you
will be credited in the advisory unless you ask otherwise; if it is declined you
will get the reasoning.
