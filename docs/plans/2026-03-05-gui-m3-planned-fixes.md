# GUI M3 Planned Fixes

Issues identified during M2 review. User decisions noted for each.

## Security

### SaveProfile should block credential writes from non-root clients
SaveProfile accepts arbitrary key/value pairs including `login`/`password`.
A process connected to the socket (0660/wheel) could overwrite credentials.
GetProfile already strips credentials (M2 fix). SaveProfile should refuse
to write `login` or `password` keys — credential setup must go through
`sudo airvpn connect` or the Eddie import flow.

**User decision:** Block writes to login/password in SaveProfile handler.

### SaveProfile atomicity
Currently saves one key at a time in a loop. If the helper crashes mid-save,
the profile is partially written. Should write all options atomically
(write to temp file, rename over original).

**User decision:** Fix this. Use atomic write (write-then-rename).

## UX

### Eddie import confirmation dialog
GUI currently auto-accepts Eddie profile import. The CLI asks for
confirmation. Users with stale Eddie profiles may get unexpected credential
imports.

**User decision:** Add a confirmation dialog in the GUI showing the Eddie
profile path and asking whether to import.

### Server list auto-refresh
Server data is fetched once on first Servers tab visit and never refreshed
automatically. Eddie refreshes every ~3 minutes. Load/users data goes stale.

**User decision:** Refresh server list every ~3 minutes (match Eddie).

### Progressive server list loading
Ideal model: show the server list immediately with base scores (no ping),
then update scores with ping results as they come in. User sees the list
sort/reorder as latency data arrives. Currently it's all-or-nothing
(skip_ping=true by default, no ping data at all).

**User decision:** Implement progressive loading — instant list, then
background ping updates.

### Sorting should be client-side
Server sorting should happen in the GUI/CLI client, not in the helper.
The helper should return unsorted data. The `sort` field on `ListServers`
was a design mistake — remove it, move sorting to clients.

**User decision:** Remove `sort` from ListServers IPC command. CLI and GUI
both sort client-side.

### Log memory growth
`Vec<LogEntry>` grows unbounded. VPN sessions can run for months.
Need a ring buffer or periodic pruning.

**User decision:** Bound the log buffer. Clear old entries automatically.

### ListServers loading feedback
When the API call is slow, the GUI shows "Loading servers..." with no
progress indicator or timeout. Should have a spinner or timeout message.

**User decision:** Add proper loading feedback.

## Features removed in M2

### `--debug` flag for CLI servers
`airvpn servers --debug` (raw XML manifest dump) was removed during the
ServerList unification. Developer tool, not user-facing.

**User decision:** Not a priority. User doesn't use it.
