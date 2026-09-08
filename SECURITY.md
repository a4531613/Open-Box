# Security-hardened Open-Box

This fork keeps the upstream Open-Box feature set while reducing the risk of running a root-capable transparent-proxy manager on a home router.

## Security boundary

The hardened build separates the LAN-facing panel from the original backend:

- LAN entry point: `security-gateway.mjs` on the router LAN IPv4 address, port `2026`
- Original Open-Box backend: loopback only on `127.0.0.1:2027`
- sing-box Clash API: loopback only on `127.0.0.1:9095`

The original backend still needs root privileges to manage firewall, DNS and services. The goal of the gateway is to keep that root-capable HTTP API off LAN/WAN interfaces and expose only an authenticated, constrained facade.

## Hardened defaults

- Panel does not bind to `0.0.0.0` by default.
- User management passwords are stored using `scrypt` with a random salt.
- Existing plaintext management passwords are migrated on first hardened startup and replaced in the legacy slot by a random internal backend credential.
- Failed login attempts are rate-limited; five failures lock the source temporarily.
- Password changes require both an authenticated session and the current password, and failed attempts share the login limiter.
- Session cookies use `HttpOnly` and `SameSite=Strict`; `Secure` is enabled when HTTPS is detected or explicitly configured.
- LAN clients cannot override Controller proxy targets using `x-zashboard-target-*`, `targetBase`, or `secret`.
- `/api/health` does not disclose the SQLite path.
- Basic browser hardening headers are added (`nosniff`, frame deny, no-referrer, same-origin resource policy).
- Persisted third-party mirror selection is reset to GitHub direct on panel startup unless the operator explicitly opts out.
- Hardened releases use a separate `secure-v*` release workflow and GitHub build provenance attestation.

## Installation

After a `secure-v*` release exists on this fork, install using the hardened direct-only installer:

```sh
curl -fsSL https://raw.githubusercontent.com/a4531613/Open-Box/main/scripts/install-secure.sh -o /tmp/openbox-install-secure.sh
less /tmp/openbox-install-secure.sh
sh /tmp/openbox-install-secure.sh
```

The hardened installer:

1. downloads only from the official GitHub Release endpoint for `a4531613/Open-Box`;
2. checks the SHA256 file before installation;
3. verifies that the tarball contains `security-gateway.mjs` and the hardened init script;
4. requires the release version to start with `secure-v`;
5. records the default update channel as `direct`.

Do not pipe the installer directly into `sh` if you want the strongest practical review workflow. Download it, inspect it, then execute it.

## Third-party mirrors

Third-party GitHub mirrors are not trusted by default. A mirror can serve both a malicious archive and a matching malicious checksum, so a same-origin SHA256 file does not authenticate the publisher.

The legacy updater still supports an explicit one-off mirror invocation for difficult network environments:

```sh
/opt/open-box/update.sh --mirror https://example-mirror.invalid
```

Use this only when you explicitly trust that mirror. Normal startup resets the persisted update channel to GitHub direct.

## Release model

Security releases use tags in this form:

```text
secure-v1.0.0
```

The security release workflow patches release artifacts so that:

- `update.sh` points to `a4531613/Open-Box` releases;
- the LuCI update checker points to `a4531613/Open-Box`;
- release archives contain the security gateway;
- SHA256 files are emitted;
- GitHub build provenance attestations are generated.

Do not publish a hardened release using an upstream-style `v*` tag, because the copied upstream release workflow is intentionally kept separate for easier upstream synchronization.

## Remaining risk

This is not a claim of zero risk. Transparent proxy management inherently requires high network privileges. The original backend still performs root-level operations and the LAN panel is HTTP unless you place an authenticated HTTPS reverse proxy in front of it or access it through a trusted VPN.

Recommended operating rules:

- never port-forward TCP/2026 from WAN;
- use a unique Open-Box password;
- keep OpenWrt/ImmortalWrt patched;
- prefer GitHub direct releases;
- review changes before merging upstream updates;
- keep CodeQL and Security CI green before creating a `secure-v*` tag.

## Security regression gates

The repository includes tests for:

- scrypt password hashing and verification;
- login lockout behavior;
- plaintext-password migration;
- unauthenticated API rejection;
- password-change authentication;
- Controller target override rejection;
- health endpoint information exposure.

`Security CI` runs the server test suite, sing-box config validation, panel build and shell syntax checks. CodeQL runs on pushes, pull requests and weekly schedule.
