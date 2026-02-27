# Plan: Eddie-compatible profile format + servers.locklast/startlast

## Context

When WiFi drops, the client penalizes the server and rotates. Eddie solves
this with `servers.locklast` and `servers.startlast` settings stored in its
encrypted profile. The user has these enabled in Eddie and wants the same
behavior, with interchangeable profiles.

Currently our profile stores JSON. Eddie stores XML. We need to switch to
Eddie's XML format so profiles are interchangeable.

## Step 1: Switch profile content from JSON to XML

**File:** `src/config.rs`

Replace JSON profile content with Eddie's XML `<option>` format:

```xml
<eddie>
  <options>
    <option name="login" value="username" />
    <option name="password" value="password" />
    <option name="servers.locklast" value="True" />
    <option name="servers.startlast" value="True" />
    <option name="servers.last" value="sha256hex" />
  </options>
</eddie>
```

- Read: decrypt profile → parse XML → extract `<option>` elements into a HashMap
- Write: read existing profile → patch changed options → serialize XML → encrypt
- Only write non-default values (Eddie convention)
- Ignore unknown options on read (forward-compatible with Eddie's GUI options)
- `servers.last` uses SHA256(server_name) to match Eddie

New public API:
- `load_profile_options() -> HashMap<String, String>` — all options from profile
- `save_profile_option(key, value)` — patch a single option, preserve others
- `resolve_credentials()` — refactored to use load_profile_options internally

Eddie profile path (`~/.config/eddie/default.profile`) can be read as a
fallback if our profile doesn't exist — same encryption, same format.

**No changes to `src/profile.rs`** — the encryption layer is format-agnostic.

## Step 2: CLI flags

**File:** `src/main.rs` Connect command

```rust
#[arg(long)]
no_lock_last: bool,    // disable servers.locklast for this session

#[arg(long)]
no_start_last: bool,   // disable servers.startlast for this session
```

Negative-only flags (positive is the default), matching existing `--no-lock`,
`--no-reconnect` pattern.

## Step 3: Connection loop changes

**File:** `src/main.rs`

**Before loop (~line 472):**
```
options = config::load_profile_options()
lock_last = options["servers.locklast"] != "False" && !cli.no_lock_last
start_last = options["servers.startlast"] != "False" && !cli.no_start_last
last_server = options["servers.last"]  // SHA256 → reverse-lookup against manifest

if CLI --server:
    forced_server = server_name
elif start_last && last_server found in manifest:
    forced_server = last_server_name
else:
    forced_server = None
```

**In error/penalty paths:**
```
if network_down || lock_last:
    // don't penalize, don't clear forced_server
else:
    penalize + clear forced_server (existing behavior)
```

**After successful connection (~line 873):**
```
config::save_profile_option("servers.last", SHA256(server_name))
```

## Step 4: Update divergences doc

Note that `servers.locklast` and `servers.startlast` default to `true` in
our profile (Eddie defaults to `false`). This is the only divergence — the
format and option names are Eddie-identical.

## Files touched

| File | Changes |
|------|---------|
| `src/config.rs` | XML read/write, option API, Eddie fallback |
| `src/main.rs` | CLI flags, loop logic, save after connect |
| `docs/known_divergences.md` | Default-true note |

## Verification

1. `cargo test` — existing + new tests pass
2. Copy Eddie profile to our path → credentials + settings load correctly
3. Connect, kill WiFi, observe same-server retry
4. Restart client → reconnects to last server (startlast)
5. `--no-lock-last` → rotates on error as before
