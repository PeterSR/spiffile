# Security Policy

spiffile is identity infrastructure; we treat security reports with
priority.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private
vulnerability reporting: the **Security** tab of
[PeterSR/spiffile](https://github.com/PeterSR/spiffile) → *Report a
vulnerability*. Do not open a public issue for anything you believe is a
security problem.

You can expect an acknowledgement within a few days. Please include a
reproduction (a token + bundle pair that verifies when it shouldn't is the
gold standard) and which implementation(s) it affects — given the parity
contract, a flaw in one implementation is worth checking in all three.

## Scope

In scope:

- the verification rules in [PROFILE.md](PROFILE.md) (e.g. a way to make a
  verifier accept a token for an identity whose bound keys didn't sign it),
- the implementations in `python/`, `ts/` and `go/`: token verification,
  bundle parsing, key handling, the provisioning helpers (e.g. key files
  created with permissive modes).

Not spiffile vulnerabilities (by design — see PROFILE.md §6):

- compromise of the file-delivery machinery. Whoever can write a workload's
  bundle or key files controls identity; the profile explicitly delegates
  that trust to your existing secret-delivery infrastructure.
- absence of transport encryption. Tokens authenticate, they don't encrypt;
  TLS underneath is the deployment's responsibility.

## Supported versions

Pre-1.0, security fixes target the latest release of each library. There are
no backport branches.
