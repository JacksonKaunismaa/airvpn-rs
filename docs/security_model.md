# Security Model

## Credential isolation: credentials never leave root

The central security invariant: **VPN credentials exist only in root-owned memory
and root-owned files. They never enter user-readable address space or transit the
IPC socket.**

### How it works

```
┌─────────────────────────────────────────────────────┐
│  ROOT (helper daemon, pid 1 descendant)             │
│                                                     │
│  /etc/airvpn-rs/default.profile  (root:root 0600)  │
│       │                                             │
│       ▼                                             │
│  config::load_profile_options()                     │
│       │                                             │
│       ├──► connect::run()  ──► api::fetch_*()       │
│       │    (credentials in Zeroizing<String>)       │
│       │                                             │
│       ├──► dispatch_list_servers()                   │
│       │                                             │
│       └──► handle_import_eddie()                    │
│            (reads Eddie profile, saves to ours)     │
│                                                     │
│  ── IPC boundary (/run/airvpn-rs/helper.sock) ───── │
│                                                     │
│  Outbound responses NEVER contain credentials:      │
│  • GET /profile  → strips login + password fields   │
│  • GET /status   → connection state only            │
│  • GET /events   → log lines + state changes        │
│  • POST /connect → no creds in request or response  │
└─────────────────────────────────────────────────────┘
         ▲
         │ Unix socket (0660 root:wheel)
         │
┌────────┴────────────────────────────────────────────┐
│  USER (CLI or GUI)                                  │
│                                                     │
│  ConnectRequest  — server filters, flags, no creds  │
│  ImportEddieRequest — { accept: bool }              │
│  SaveProfileRequest — settings only (e.g. locklast) │
│  ProfileResponse — options + credentials_configured  │
│                    (boolean, not the actual creds)   │
└─────────────────────────────────────────────────────┘
```

### Boundary enforcement by endpoint

| Endpoint | Direction | Credential content | Notes |
|----------|-----------|-------------------|-------|
| `POST /connect` | user → helper | None — `ConnectRequest` has no credential fields | Helper resolves creds from profile internally |
| `POST /import-eddie` | user → helper | None — just `{accept: bool}` | Helper reads Eddie profile using peer UID (`SO_PEERCRED`) |
| `GET /profile` | helper → user | Stripped — `options.remove("login"); options.remove("password")` | Returns `credentials_configured: bool` instead |
| `POST /profile` | user → helper | Settings only | Could theoretically write creds, but that flows inward (user → root), not outward |
| `GET /status` | helper → user | None | Connection state + lock status |
| `GET /events` | helper → user | None | Log lines, state changes, stats |
| `GET /servers` | helper → user | None | Helper uses its own creds for API call, returns server list |

### In-memory protections

- Credentials in `connect::SessionParams` are `Zeroizing<String>` — zeroed on drop
- WireGuard private key and preshared key are `Zeroizing<String>`
- API response XML (contains key material) wrapped in `Zeroizing<String>`
- PBKDF2-derived keys use `Zeroizing<[u8; 32]>`
- `wg setconf` reads config from a temp file (root-only), deleted after use

### First-time credential entry

Two paths, both root-only:

1. **`sudo airvpn connect`** — prompts for username/password in the root helper
   process via `rpassword::prompt_password()`. Saved to profile after successful
   connection. The CLI process that invoked sudo never sees the credentials.

2. **Eddie import** — helper uses `SO_PEERCRED` to find the connecting user's UID,
   locates their Eddie profile at `~/.config/eddie/default.profile`, decrypts it
   (dropping privileges via `sudo -u` for keyring access if needed), and saves
   credentials to our root-owned profile. The user-space client only sends
   `{accept: true}`.

### What this defends against

- **Malicious user-space process**: Cannot read `/etc/airvpn-rs/default.profile`
  (0600 root:root). Cannot extract credentials from socket responses (stripped).
  Cannot sniff credentials from helper memory (different address space, root-owned).
- **Compromised GUI**: The GUI never has credentials in memory. A compromised GUI
  can tell the helper to connect/disconnect but cannot exfiltrate credentials.
- **Socket eavesdropping**: Even if another wheel-group user connects to the socket,
  no endpoint returns credential material.

### What this does NOT defend against

- **Root compromise**: Game over. Root can read the profile, attach to helper memory,
  keylog, etc. No client-side mitigation possible.
- **Helper process compromise**: If an attacker gets code execution inside the helper,
  they have the credentials. This is inherent to any architecture where a daemon
  holds secrets.

---

## Profile encryption: v2n is fine

airvpn-rs saves profiles as v2n (AES-256-CBC with a hardcoded password). This
sounds scary but is the correct choice for our threat model.

### Why the encryption format doesn't matter

The profile lives at `/etc/airvpn-rs/default.profile`, owned `root:root 0600`.
The real security boundary is **Unix file permissions**, not the encryption
format. To read the file you need root, and if you have root, you can decrypt
any format:

| Format | What protects it | Root attacker | Non-root attacker |
|--------|-----------------|---------------|-------------------|
| v2n (hardcoded password) | File permissions (0600) | Trivial — password is in source code | Can't read the file |
| v2s (keyring password) | File permissions + keyring | `sudo -u $USER secret-tool lookup` while user is logged in | Can't read the file |
| v2p (user password) | File permissions + user's memory | Can keylog, modify PAM, swap binary | Can't read the file |

For a non-root attacker (the realistic local threat), all three formats are
equally secure because they can't read a `root:root 0600` file regardless. The
encryption is irrelevant — file permissions are the gate.

### What about stolen laptops?

If disk encryption (LUKS) is enabled: everything is protected. Format doesn't
matter.

If LUKS is not enabled: the attacker can mount the disk and read files as root.
v2s would be marginally better here (keyring file is encrypted with the login
password), but if you don't have LUKS, your VPN credentials are the least of
your worries.

### What about "root access while logged out"?

This is a contrived scenario. If an attacker has root, they can wait for login,
install a keylogger, modify PAM, etc. Root = game over regardless of encryption
format.

### Eddie compatibility

Eddie uses three formats (v2n, v2s, v2p) with PBKDF2-HMAC-SHA1 at 10,000
iterations and 8-byte salts. This is weak by modern standards (OWASP recommends
600,000+ iterations for PBKDF2-SHA1), but:

1. We must match Eddie's parameters to import Eddie profiles.
2. We re-save as v2n with `root:root 0600`, so the PBKDF2 strength of the
   imported file is irrelevant to our security posture.
3. The Eddie profile at `~/.config/eddie/default.profile` is user-owned, so any
   process running as the user can read it regardless of encryption strength.
   Warning about weak PBKDF2 during import would be misleading — the file
   permissions are the actual problem, and we fix that by re-saving to
   `/etc/airvpn-rs/` as root.

A PBKDF2 strength warning during Eddie import was considered and rejected as
noise. It would suggest the encryption matters when it doesn't.

### The `default_format()` function

`profile.rs` contains a `default_format()` function that would prefer v2s when
a keyring is available. This is dead code — never called. It exists for
potential future use but the reasoning above explains why v2n is the right
default.

## Socket authentication (helper daemon)

The helper socket at `/run/airvpn-rs/helper.sock` uses file permissions
(`0o660`) with group chown to the launching user's primary group. On typical
desktop Linux (Ubuntu, Arch, Fedora), primary groups are per-user, so only
root and the launching user can connect.

This is adequate for the target audience (single-user Linux desktops). The
main risk is systems using a shared `users` group (NixOS, some enterprise
setups), where all local users could connect. `SO_PEERCRED` peer credential
checking would be defense-in-depth but is not critical for the typical case.

## Threat model summary

The threats we actually defend against:

1. **Network surveillance** — VPN tunnel + kill switch (nftables)
2. **DNS leaks** — resolv.conf management + systemd-resolved integration
3. **IPv6 leaks** — sysctl disable on all interfaces including `default`
4. **Traffic leaks between sessions** — persistent nftables lock (boot-time)
5. **Traffic leaks during crashes** — recovery module + state persistence
6. **Credential exposure to non-root users** — `root:root 0600` file permissions

The threats we don't try to defend against (and why):

1. **Root compromise** — game over regardless; no client-side mitigation
2. **Stolen laptop without LUKS** — outside our scope; LUKS is the answer
3. **Malicious local root process** — same as root compromise
