# Eddie CLI Reference (AirVPN Official Client)

Comprehensive analysis of the Eddie source code at [github.com/AirVPN/Eddie](https://github.com/AirVPN/Eddie) (v2.24.6, commit 621fdcd).
This document serves as a reference for auditing a Rust reimplementation.

---

## 1. API Communication

### 1.1 Bootstrap URLs

The AirVPN provider definition is stored in `resources/providers/AirVPN.json`:

```json
{
  "code": "AirVPN",
  "class": "service",
  "fetch_mode": "rsa4096+aes256",
  "manifest": {
    "auth_rsa_exponent": "AQAB",
    "auth_rsa_modulus": "wuQXz7eZeEB...<base64 RSA-4096 modulus>...",
    "urls": [
      { "address": "http://63.33.78.166" },
      { "address": "http://54.93.175.114" },
      { "address": "http://82.196.3.205" },
      { "address": "http://63.33.116.50" },
      { "address": "http://[2a03:b0c0:0:1010::9b:c001]" },
      { "address": "http://bootme.org" }
    ]
  }
}
```

Additional bootstrap URLs can be added via the `bootstrap.urls` profile option (semicolon-delimited).
Once a manifest is fetched, its `//urls/url` nodes provide updated bootstrap URLs.

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 662-695, `GetBootstrapUrls()`)

### 1.2 API Actions

Three API actions exist:

| Action | When | Additional Parameters |
|--------|------|----------------------|
| `act=manifest` | Periodic refresh (default: every 24h or server-recommended interval) | `ts=<unix_timestamp>` |
| `act=user` | Login/authentication | (none beyond base params) |
| `act=connect` | Pre-connection authorization | `server=<server_name>` |

**Source:** `src/Lib.Core/Providers/Service.cs:595`, `src/Lib.Core/Engine.cs:1628`, `src/Lib.Core/Session.cs:174`

### 1.3 Base API Parameters

Every API request includes:

```
login      = <username>
password   = <password>
software   = "EddieDesktop_2.24.6"
arch       = <os_architecture>      (e.g. "x64")
system     = <platform_code>        (e.g. "linux_x64")
version    = 296                    (integer version)
```

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 1040-1055, `FetchUrls()`)

### 1.4 Encrypted API Envelope (RSA-4096 + AES-256-CBC)

The `FetchUrl()` method (lines 912-1038) constructs an encrypted envelope:

**Step 1: Generate ephemeral AES-256 session key**
```csharp
Aes aes = Aes.Create();
aes.KeySize = 256;
aes.GenerateKey();
aes.GenerateIV();
```
The default .NET Aes mode is CBC with PKCS7 padding.

**Step 2: Build 'S' parameter (RSA-encrypted session key)**

The RSA public key (modulus + exponent) comes from the manifest's `auth_rsa_modulus` and `auth_rsa_exponent` attributes (both Base64-encoded).

```csharp
// S = RSA_Encrypt({key: aes.Key, iv: aes.IV})
Dictionary<string, byte[]> assocParamS = new Dictionary<string, byte[]>();
assocParamS["key"] = aes.Key;
assocParamS["iv"] = aes.IV;
bytesParamS = csp.Encrypt(AssocToUtf8Bytes(assocParamS), false);
// false = PKCS#1 v1.5 padding (NOT OAEP)
```

**Step 3: Build 'D' parameter (AES-encrypted request data)**

```csharp
// D = AES_CBC_Encrypt(parameters_dict)
byte[] aesDataIn = AssocToUtf8Bytes(parameters);
// ... CryptoStream with aes.CreateEncryptor() ...
bytesParamD = aesCryptStream.ToArray();
```

**Step 4: HTTP POST**

```
POST <bootstrap_url>
Content-Type: application/x-www-form-urlencoded

s=<base64(bytesParamS)>&d=<base64(bytesParamD)>
```

**Step 5: Decrypt response**

Response body is AES-CBC-decrypted with the same session key+IV, yielding XML.

**AssocToUtf8Bytes format** (lines 1188-1206):

For `Dictionary<string, string>`:
```
Base64(key_utf8):Base64(value_utf8)\n
```
For `Dictionary<string, byte[]>`:
```
Base64(key_utf8):Base64(value_bytes)\n
```

**RSA padding:** `csp.Encrypt(data, false)` = PKCS#1 v1.5 padding. This is NOT OAEP.

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 912-1038)

### 1.5 Constants

```csharp
Name                  = "Eddie"
AppID                 = "ec80475d661a5f449069818262b08d645c570f8f"
NotSecretPayload      = UTF8("4af85e84255b077ad890dba297e811b7d016add1")
PasswordIfEmpty       = "e6552ddf3ac5c8755a82870d91273a63eab0da1e"
VersionInt            = 296
VersionDesc           = "2.24.6"
WebSite               = "https://eddie.website"
WebSiteIPv4           = "188.166.41.48"
WebSiteIPv6           = "2a03:b0c0:2:d0::11b4:6001"
DnsVpn                = "10.4.0.1"
ElevatedVersionExpected = "v1378"
ElevatedServicePort   = 9350
```

**Source:** `src/Lib.Core/Constants.cs`

---

## 2. Server Manifest Parsing

### 2.1 Manifest XML Structure

The manifest response is XML with this structure:

```xml
<manifest auth_rsa_modulus="..." auth_rsa_exponent="..." time="..." next_update="...">
  <urls>
    <url address="http://..." />
  </urls>
  <servers_groups>
    <servers_group group="..." ips_entry="..." country_code="..." ... />
  </servers_groups>
  <servers>
    <server name="..." group="..." ips_entry="..." ips_exit="..." country_code="..."
            location="..." scorebase="..." bw="..." bw_max="..." users="..."
            users_max="..." warning_open="..." warning_closed="..."
            support_ipv4="..." support_ipv6="..." support_check="..."
            openvpn_directives="..." ciphers_tls="..." ciphers_tlssuites="..."
            ciphers_data="..." />
  </servers>
  <modes>
    <mode title="..." type="..." protocol="..." port="..." entry="..."
          transport="..." specs="..." openvpn_minversion="..." openvpn_directives="..." />
  </modes>
  <messages>
    <message kind="..." text="..." url="..." from_time="..." to_time="..." />
  </messages>
</manifest>
```

### 2.2 Server Attributes

Parsed from `//servers/server` nodes with group fallback from `//servers_groups/servers_group`:

| XML Attribute | ConnectionInfo Field | Type |
|---------------|---------------------|------|
| `name` | `DisplayName`, `ProviderName` | string |
| `ips_entry` | `IpsEntry` | IpAddresses (comma-separated) |
| `ips_exit` | `IpsExit` | IpAddresses |
| `country_code` | `CountryCode` | string |
| `location` | `Location` | string |
| `scorebase` | `ScoreBase` | Int64 |
| `bw` | `Bandwidth` | Int64 |
| `bw_max` | `BandwidthMax` | Int64 (default: 1) |
| `users` | `Users` | Int64 |
| `users_max` | `UsersMax` | Int64 (default: 100) |
| `warning_open` | `WarningOpen` | string |
| `warning_closed` | `WarningClosed` | string |
| `support_ipv4` | `SupportIPv4` | bool |
| `support_ipv6` | `SupportIPv6` | bool |
| `support_check` | `SupportCheck` | bool |
| `openvpn_directives` | `OvpnDirectives` | string |
| `ciphers_tls` | `CiphersTls` | List (colon-delimited) |
| `ciphers_tlssuites` | `CiphersTlsSuites` | List (colon-delimited) |
| `ciphers_data` | `CiphersData` | List (colon-delimited) |

**Server code** = SHA256 hash of the server name.

**Group fallback:** `XmlGetServerAttributeString()` first checks the server node, then falls back to the server group node.

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 738-779, `OnBuildConnections()`)

### 2.3 Connection Modes

Parsed from `//modes/mode` nodes:

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Display name |
| `type` | string | "openvpn" or "wireguard" |
| `protocol` | string | "TCP" or "UDP" |
| `port` | int | Destination port |
| `entry` | int | Entry IP index (alt) |
| `transport` | string | "SSH", "SSL", or "" (standard) |
| `specs` | string | Version requirements |
| `openvpn_minversion` | string | Minimum OpenVPN version |
| `openvpn_directives` | string | Extra OpenVPN directives |

**Mode selection cascade** (4 laps):
1. Exact match: type + protocol + port + entry index
2. type + protocol + port
3. type + protocol
4. type only
5. Fallback: `GetModeAuto()` (auto-selection)

**Source:** `src/Lib.Core/ConnectionMode.cs`, `src/Lib.Core/Providers/Service.cs` (lines 848-910)

### 2.4 User XML Node

The `act=user` response provides a user node with these attributes:

```xml
<user ca="..." ta="..." tls_crypt="..." wg_public_key="..."
      ssh_<format>="..." ssl_crt="...">
  <keys>
    <key name="..." crt="..." key="..."
         wg_private_key="..." wg_ipv4="..." wg_ipv6="..."
         wg_dns_ipv4="..." wg_dns_ipv6="..." wg_preshared="..." />
  </keys>
</user>
```

| User Attribute | Purpose |
|----------------|---------|
| `ca` | CA certificate (OpenVPN) |
| `ta` | TLS-Auth key (OpenVPN) |
| `tls_crypt` | TLS-Crypt key (OpenVPN) |
| `wg_public_key` | WireGuard server public key |
| `ssh_<format>` | SSH key material |
| `ssl_crt` | SSL client certificate |

| Key Attribute | Purpose |
|---------------|---------|
| `name` | Key name (matches `key` profile option) |
| `crt` | Client certificate (OpenVPN) |
| `key` | Client private key (OpenVPN) |
| `wg_private_key` | WireGuard client private key |
| `wg_ipv4` | WireGuard IPv4 tunnel address |
| `wg_ipv6` | WireGuard IPv6 tunnel address |
| `wg_dns_ipv4` | WireGuard DNS IPv4 |
| `wg_dns_ipv6` | WireGuard DNS IPv6 |
| `wg_preshared` | WireGuard preshared key |

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 243-276, `OnBuildConnection()`)

---

## 3. Server Selection Algorithm

### 3.1 Scoring

```csharp
public int Score()
{
    if (HasWarningsErrors()) return 99998;
    if (HasWarnings())       return 99997;
    if (Ping == -1)          return 99995;

    double PenalityB = Penality * penality_factor;  // default: 1000
    double PingB     = Ping * ping_factor;           // default: 1
    double LoadB     = LoadPerc() * load_factor;     // default: 1
    double UsersB    = UsersPerc() * users_factor;   // default: 1
    double ScoreB    = ScoreBase;

    if (scoreType == "speed") {
        ScoreB /= speed_factor;           // default: 1
        LoadB  /= speed_load_factor;      // default: 1
        UsersB /= speed_users_factor;     // default: 1
    } else if (scoreType == "latency") {
        ScoreB /= latency_factor;         // default: 500
        LoadB  /= latency_load_factor;    // default: 10
        UsersB /= latency_users_factor;   // default: 10
    }

    return (int)(PenalityB + PingB + LoadB + ScoreB + UsersB);
}
```

Lower score = better server. Servers are sorted by score; first is selected.

**Source:** `src/Lib.Core/ConnectionInfo.cs` (Score method)

### 3.2 Latency Measurement

- **Protocol:** ICMP ping (via .NET `System.Net.NetworkInformation.Ping` on Windows, elevated `ping-engine` command on Linux/macOS)
- **Target:** First IPv4 address from `IpsEntry`
- **Timeout:** Configurable via `pinger.timeout`, default 3000ms (TTL: 64, buffer: 32 bytes)
- **Concurrency:** `pinger.jobs` concurrent pings, default 25
- **Interval:** 180 seconds between successful pings per server
- **Retry:** 5 seconds after failure
- **Averaging:** `Ping = (Ping + result) / 2` (rolling average)
- **Failure handling:** 5 consecutive failures marks server invalid

**Source:** `src/Lib.Core/Jobs/Latency.cs`, `src/Lib.Core/PingManager.cs`

### 3.3 Selection Flow

1. Check forced server (`server` option)
2. Reconnect to last server if `servers.startlast` enabled
3. Wait for latency tests if active
4. Call `GetConnections(false)` which returns filtered, sorted list
5. Pick first (lowest score)

**Source:** `src/Lib.Core/Engine.cs` (`PickConnection()`)

---

## 4. WireGuard Configuration Generation

### 4.1 Config Builder

`src/Lib.Core/ConfigBuilder/WireGuard.cs` generates standard WireGuard INI format:

```ini
[Interface]
Address = 10.x.x.x/32, fd7d:xxxx::/128
PrivateKey = <base64_private_key>
DNS = 10.4.0.1, fd7d:76ee:3ec5:7::1
MTU = 1320

[Peer]
PublicKey = <base64_public_key>
PresharedKey = <base64_preshared_key>
Endpoint = <server_ip>:<port>
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
```

**Key parameters:**
- **MTU:** Default 1320 (when `wireguard.interface.mtu == -1`). Can be overridden.
- **AllowedIPs:** Always forced to `0.0.0.0/0, ::/0` in `Adaptation()` regardless of parsed values.
- **PersistentKeepalive:** Default 15 seconds.
- **Interface name:** Default "Eddie" (from `network.iface.name` option), truncated to 12 chars.
- **IPv6 endpoints:** Wrapped in brackets: `[2001:db8::1]:1234`

### 4.2 DNS Handling

If `dns.delegate == false` (default), DNS servers are removed from the WireGuard config and stored separately for Eddie's own DNS management. If custom DNS servers are set via `dns.servers`, they replace the API-provided DNS.

### 4.3 IPv4/IPv6 Filtering

If IPv4 is disabled (`ConfigIPv4 == false`), IPv4 addresses are removed from `InterfaceAddresses`.
Same for IPv6. This is controlled by `network.ipv4.mode` and `network.ipv6.mode`.

**Source:** `src/Lib.Core/ConnectionTypes/WireGuard.cs`, `src/Lib.Core/ConfigBuilder/WireGuard.cs`

---

## 5. WireGuard Connection Lifecycle (Linux)

### 5.1 Elevated Command

The main process sends to the elevated helper:

```
command=wireguard
action=start
id=<connection_id>
interface=Eddie
config=<INI config text>
handshake_timeout_first=50
handshake_timeout_connected=200
```

### 5.2 Elevated Handler Sequence (impl.cpp)

1. **Delete existing interface** if `/proc/sys/net/ipv4/conf/<iface>` exists
2. **Parse config** into key-value map using INI parser
3. **Configure WireGuard peer** via kernel netlink API (libwg):
   - Set public key (`WGPEER_HAS_PUBLIC_KEY`)
   - Set preshared key (`WGPEER_HAS_PRESHARED_KEY`)
   - Set persistent keepalive (`WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL`)
   - Set allowed IPs (`WGPEER_REPLACE_ALLOWEDIPS`)
   - Parse endpoint (supports IPv4 and IPv6, brackets stripped for v6)
4. **Configure WireGuard device** via kernel netlink API:
   - Set private key (`WGDEVICE_HAS_PRIVATE_KEY`)
   - Set listen port (optional, `WGDEVICE_HAS_LISTEN_PORT`)
   - Set fwmark (optional, `WGDEVICE_HAS_FWMARK`)
5. **Create device:** `wg_add_device(name)` via `NETLINK_ROUTE` (`RTM_NEWLINK` with `IFLA_INFO_KIND=wireguard`)
6. **Apply config:** `wg_set_device()` via `WG_CMD_SET_DEVICE` generic netlink
7. **Add IP addresses:** `ip -4 address add <addr> dev <iface>` and `ip -6 address add ...`
8. **Set MTU:** `ip link set mtu <mtu> dev <iface>`
9. **Bring up:** `ip link set <iface> up`
10. **Monitor handshake loop** (1-second poll):
    - Check `WireGuardLastHandshake()` for new handshakes
    - First handshake triggers "handshake-first" -> `Session.ConnectedStep()`
    - No handshake within `handshake_timeout_first` seconds -> "handshake-out" (error)
    - Connected but no handshake within `handshake_timeout_connected` seconds -> "handshake-out"
11. **Stop:** On stop request, `wg_del_device()` removes the interface

**Config map keys used by elevated:**
```
interface.privatekey
interface.listenport
interface.fwmark
interface.address      (comma-separated)
interface.mtu
peer.publickey
peer.presharedkey
peer.persistentkeepalive
peer.allowedips        (comma-separated)
peer.endpoint          (ip:port, IPv6 as [ip]:port)
```

**Source:** `src/App.CLI.Linux.Elevated/src/impl.cpp`, `src/App.CLI.Linux.Elevated/src/wireguard.c`

---

## 6. Network Lock (Kill Switch)

### 6.1 Architecture

Network Lock uses a plugin system:
- `NetworkLockManager` orchestrates activation/deactivation
- Platform-specific plugins implement actual firewall rules
- Linux has: `NetworkLockNftables`, `NetworkLockIptables`, `NetworkLockIptablesNFT`, `NetworkLockIptablesLegacy`

### 6.2 Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `netlock` | false | Enable network lock |
| `netlock.mode` | "auto" | Lock implementation |
| `netlock.incoming` | "block" | Default INPUT policy |
| `netlock.outgoing` | "block" | Default OUTPUT policy |
| `netlock.allow_private` | true | Allow RFC1918 + IPv6 link-local |
| `netlock.allow_dhcp` | true | Allow DHCP broadcast |
| `netlock.allow_ping` | true | Allow ICMP echo |
| `netlock.allow_dns` | false | Allow detected DNS servers |
| `netlock.allow_ipv4ipv6translation` | true | Allow RFC 6052/8215 translation |
| `netlock.allowlist.incoming.ips` | "" | Manual incoming allowlist |
| `netlock.allowlist.outgoing.ips` | "" | Manual outgoing allowlist |

### 6.3 Allowlist Sources (Outgoing)

1. Manual IPs from `netlock.allowlist.outgoing.ips` (supports `#` comments)
2. Routes marked as `"out"` in `routes.custom`
3. Detected DNS servers (if `netlock.allow_dns`)
4. Provider-specific allowlist (VPN bootstrap IPs)
5. VPN server entry IPs

### 6.4 nftables Rules (Complete)

The nftables implementation generates rules via `nft -f <file>`. The full ruleset:

**Tables created:** `ip nat`, `ip6 nat`, `ip mangle`, `ip6 mangle`, `ip filter`, `ip6 filter`

**Filter chains:** INPUT, FORWARD, OUTPUT with configurable default policies (drop/accept)

**INPUT chain rules (in order):**
1. `flush ruleset` (clears everything first)
2. Loopback: `iifname "lo" counter accept`
3. IPv6 loopback validation: `iifname != "lo" ip6 saddr ::1 counter reject`
4. DHCP (conditional): `ip saddr 255.255.255.255 accept`, `ip6 saddr ff02::1:2 accept`, `ip6 saddr ff05::1:3 accept`
5. IPv4/IPv6 translation (conditional): `ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 accept`, `ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 accept`
6. Private networks (conditional):
   - `ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 accept`
   - `ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 accept`
   - `ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 accept`
   - `ip6 saddr fe80::/10 ip6 daddr fe80::/10 accept`
   - `ip6 saddr ff00::/8 ip6 daddr ff00::/8 accept`
   - `ip6 saddr fc00::/7 ip6 daddr fc00::/7 accept`
7. Ping (conditional): `icmp type echo-request accept`, `meta l4proto ipv6-icmp accept`
8. IPv6 RH0 protection: `rt type 0 counter drop`
9. ICMPv6 neighbor discovery: router-advert, neighbor-solicit, neighbor-advert, redirect (all with `ip6 hoplimit 255`)
10. Connection tracking: `ct state related,established accept`
11. Allowlisted incoming IPs (per-IP rules with SHA256-hashed comments)
12. Default policy fallback rule

**OUTPUT chain rules (in order):**
1. Loopback: `oifname "lo" accept`
2. IPv6 RH0 protection: `rt type 0 counter drop`
3. DHCP (conditional): `ip daddr 255.255.255.255 accept`, etc.
4. IPv4/IPv6 translation (conditional)
5. Private networks + multicast (conditional):
   - Same private ranges as INPUT
   - Multicast: `ip daddr 224.0.0.0/24 accept` (from each private range)
   - SSDP: `ip daddr 239.255.255.250 accept`
   - SLP v2: `ip daddr 239.255.255.253 accept`
6. Ping (conditional): `icmp type echo-reply accept`
7. Established connections (if incoming=allow): `ct state established accept`
8. Allowlisted incoming IPs (bidirectional): `ip daddr <ip> ct state established accept`
9. Allowlisted outgoing IPs: `ip daddr <ip> accept`
10. Default policy fallback rule

**FORWARD chain:** IPv6 RH0 drop + default policy fallback.

**IP comment format:** `eddie_ip_<SHA256("ipv4_out_" + ip.ToCIDR() + "_1")>`

### 6.5 Elevated Command Handlers

| Command | Description |
|---------|-------------|
| `netlock-nftables-activate` | Backs up current ruleset, writes rules to temp file, applies via `nft -f` |
| `netlock-nftables-deactivate` | Restores backed-up ruleset |
| `netlock-nftables-accept-ip` | Add/remove individual IP rules |
| `netlock-nftables-interface` | Add/remove interface-specific rules |
| `netlock-iptables-activate` | Backs up via `iptables-save`, applies via `iptables-restore` |
| `netlock-iptables-deactivate` | Restores via `iptables-restore` from backup |
| `netlock-iptables-accept-ip` | Insert/delete IP rules into chains |
| `netlock-iptables-interface` | Manage per-interface rules |

**Source:** `src/Lib.Platform.Linux/NetworkLockNftables.cs`, `src/App.CLI.Linux.Elevated/src/impl.cpp`

---

## 7. DNS Management

### 7.1 DNS Switch (Linux)

Two strategies attempted in order:

**Strategy 1: systemd-resolved** (if active)
- Uses `resolvectl dns <interface> <dns_servers>` per interface
- Uses `resolvectl default-route <interface> true/false` (true for tun interfaces)
- Backs up `/run/systemd/resolve/netif/<index>` per interface
- Skips `lo`/`lo0` interfaces

**Strategy 2: /etc/resolv.conf** (fallback)
- Moves `/etc/resolv.conf` to `/etc/resolv.conf.eddievpn`
- Writes new `/etc/resolv.conf` with VPN DNS servers:
  ```
  # Created by Eddie. Do not edit.
  # Your resolv.conf file is backed up in /etc/resolv.conf.eddievpn
  nameserver 10.4.0.1
  nameserver fd7d:76ee:3ec5:7::1
  ```
- Sets permissions: `0644` (`S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH`)

### 7.2 DNS Restore

- Restores `/etc/resolv.conf.eddievpn` back to `/etc/resolv.conf`
- Restarts `systemd-resolved` if active
- Restores per-interface settings from backup files

### 7.3 DNS Flush

Restarts DNS cache services in this order:
1. systemd services: configured via `linux.dns.services` option (default: `"nscd;dnsmasq;named;bind9"`)
2. systemd-resolved: `resolvectl flush-caches`
3. init.d fallback for non-systemd systems

### 7.4 DNS Check (Post-Connection)

1. Generate random token: `hash = RandomGenerator.GetRandomToken()`
2. Query DNS: resolve `<check_dns_query>.replace("{hash}", hash)` (provider-configured template)
3. Verify via HTTP: `GET https://<server_name>_exit.<check_domain>/check/dns/`
4. Response JSON: `{"dns": "<hash>"}` - must match the generated token
5. Retries: up to `checking.ntry` times (default: 5) with increasing delay

**Source:** `src/App.CLI.Linux.Elevated/src/impl.cpp` (dns-switch-do/restore/flush handlers), `src/Lib.Core/Providers/Service.cs` (lines 476-556)

---

## 8. Connection Lifecycle

### 8.1 State Machine

```
Phase 1: Initialization
  -> Select server (PickConnection)
  -> Validate IPv4/IPv6 support
  -> Build connection config
  -> Apply credentials
  -> Pre-connection authorization (act=connect)

Phase 2: Waiting Connection
  -> Launch elevated WireGuard/OpenVPN command
  -> Wait for handshake

Phase 3: Connected (ConnectedStep)
  -> Configure DNS
  -> Apply routes
  -> Detect exit IP
  -> Network lock notification
  -> Tunnel check (act=check/tun)
  -> DNS check (act=check/dns)

Phase 4: Running
  -> Monitor for reset signals
  -> Track bandwidth stats

Phase 5: Disconnection
  -> Send stop to elevated
  -> Wait for interface teardown
  -> Restore DNS
  -> Remove routes
  -> Restore IPv6 if blocked

Phase 6: Cleanup
  -> Apply penalties if error
  -> Retry or exit based on reset level
```

### 8.2 Reset Levels

| Level | Behavior |
|-------|----------|
| `""` (clear) | No reset |
| `"RETRY"` | Retry same server |
| `"ERROR"` | Apply 30s penalty to server, retry different server after 3s |
| `"SWITCH"` | Immediate switch to different server |
| `"FATAL"` | Stop completely |

### 8.3 Post-Connection Verification

**Tunnel check:**
```
URL: https://<server_name>_exit.<check_domain>/check/tun/
ForceResolve: <check_domain>:<exit_ip>
Response: {"ip": "<tunnel_ip>", "ts": "<unix_timestamp>"}
Verify: ip must be in connection's VPN IPs
```

**Real IP detection:**
```
URL: https://<server_name>.<check_domain>/check/tun/
ForceResolve: <check_domain>:<entry_ip>
Response: {"ip": "<real_ip>", "ts": "<unix_timestamp>"}
```

**Source:** `src/Lib.Core/Session.cs`, `src/Lib.Core/Providers/Service.cs` (lines 283-557)

---

## 9. Route Management

### 9.1 Elevated Route Command

```
command=route
layer=ipv4|ipv6
action=add|delete
destination=<cidr>
gateway=<ip>         (optional)
interface=<name>     (optional)
metric=<int>         (optional)
```

Executes: `ip -4|-6 route add|delete <cidr> [via <gw>] [dev <iface>] [metric <n>]`

### 9.2 Route Phases

- **Pre:** Non-VPN routes added before connection
- **Up:** VPN gateway routes added after connected
- **Post:** All routes removed during cleanup

**Source:** `src/App.CLI.Linux.Elevated/src/impl.cpp`, `src/Lib.Core/Session.cs`

---

## 10. IPv6 Management

### 10.1 IPv6 Block

When `network.ipv6.mode == "in-block"` (default):
- Iterates `/proc/sys/net/ipv6/conf/` for all interfaces
- Skips `all`, `lo`, `lo0`
- Sets `sysctl -w net.ipv6.conf.<iface>.disable_ipv6=1` for each

### 10.2 IPv6 Restore

Reverses with `sysctl -w net.ipv6.conf.<iface>.disable_ipv6=0` for each interface that was blocked.

**Source:** `src/App.CLI.Linux.Elevated/src/impl.cpp`

---

## 11. Credential Storage

### 11.1 Profile Storage Formats

| Version | Encryption | Description |
|---------|-----------|-------------|
| `v2n` | None | Password = `Constants.PasswordIfEmpty` |
| `v2s` | OS keyring | `secret-tool` on Linux |
| `v2p` | User password | Interactive prompt |

**File structure:** `[3-byte header][64-byte ID][encrypted XML data]`

### 11.2 Encryption for Storage (AES-Then-HMAC)

Used for profile/credential encryption at rest:

**Parameters:**
- AES-256-CBC with PKCS7 padding (128-bit blocks)
- HMAC-SHA256 for authentication (32-byte tag)
- PBKDF2 (Rfc2898DeriveBytes) with SHA1, 10000 iterations, 64-bit (8-byte) salt
- Separate salts for encryption key and auth key
- Constant-time tag comparison

**Wire format:**
```
[non_secret_payload][crypt_salt(8)][auth_salt(8)][IV(16)][ciphertext][HMAC(32)]
```

**Source:** `src/Lib.Core/Crypto/AESThenHMAC.cs`, `src/Lib.Core/Storage.cs`

---

## 12. Elevated Process IPC Protocol

### 12.1 Transport

- TCP socket on localhost, random port (2048-65528)
- ASCII encoding, 4096-byte receive buffer

### 12.2 Authentication

Initial handshake: `session-key:<key>; version:<expected_version>; path:<app_path>`

### 12.3 Command Format

Parameters are Base64-encoded key-value pairs:
```
key1:base64(value1);key2:base64(value2);\n
```

### 12.4 Response Protocol

Messages follow format: `ee:<kind>:<command_id>:<data>`

| Kind | Purpose |
|------|---------|
| `log` | Verbose logging (Base64-encoded) |
| `fatal` | Fatal error |
| `pid` | Process ID reporting |
| `data` | Command response data |
| `exception` | Error response |
| `end` | Command completion |

**Source:** `src/Lib.Core/Elevated/IElevated.cs`, `src/Lib.Core/Elevated/ISocket.cs`

---

## 13. Key Configuration Defaults

| Option | Default | Description |
|--------|---------|-------------|
| `mode.type` | "auto" | Connection type selection |
| `mode.protocol` | "udp" | Transport protocol |
| `mode.port` | 443 | Connection port |
| `mode.alt` | 0 | Alternative entry IP index |
| `network.entry.iplayer` | "ipv4-ipv6" | Entry IP layer preference |
| `network.ipv4.mode` | "in" | IPv4 mode |
| `network.ipv6.mode` | "in-block" | IPv6 mode (block by default) |
| `network.iface.name` | "" | Interface name (default: "Eddie") |
| `dns.mode` | "auto" | DNS resolution method |
| `dns.delegate` | false | Let VPN handle DNS directly |
| `dns.check` | true | Verify DNS after connection |
| `dns.cache.ttl` | 3600 | DNS cache TTL (seconds) |
| `servers.scoretype` | "Speed" | "Speed" or "Latency" scoring |
| `pinger.enabled` | true | Enable latency measurement |
| `pinger.jobs` | 25 | Concurrent ping operations |
| `pinger.timeout` | 3000 | Ping timeout (ms) |
| `checking.ntry` | 5 | Post-connection check retries |
| `http.timeout` | 10 | HTTP request timeout (seconds) |
| `advanced.penality_on_error` | 30 | Penalty seconds on error |
| `advanced.manifest.refresh` | -1 | Manifest refresh interval (-1=server-recommended) |
| `wireguard.interface.mtu` | -1 | WireGuard MTU (-1=1320 default) |
| `wireguard.peer.persistentkeepalive` | 15 | PersistentKeepalive (seconds) |
| `wireguard.handshake.timeout.first` | 50 | First handshake timeout (seconds) |
| `wireguard.handshake.timeout.connected` | 200 | Connected handshake timeout (seconds) |
| `wireguard.interface.skip_commands` | true | Skip PreUp/PostUp/PreDown/PostDown |

**Source:** `src/Lib.Core/ProfileOptions.cs`

---

## 14. Entry IP Selection

The entry IP is chosen based on `network.entry.iplayer`:

| Value | Behavior |
|-------|----------|
| `ipv4-ipv6` | Try IPv4 first, fall back to IPv6 |
| `ipv6-ipv4` | Try IPv6 first, fall back to IPv4 |
| `ipv4-only` | IPv4 only |
| `ipv6-only` | IPv6 only |

The `mode.alt` (EntryIndex) selects which IP from the server's entry IP list to use (servers may have multiple entry IPs for different data centers).

**Source:** `src/Lib.Core/Providers/Service.cs` (lines 117-141)

---

## 15. Exit IP Discovery

Background job queries web services from `discover.ip_webservice.list`:
- Default: `https://eddie.website/ipinfo/{@ip}`
- Extracts: country code, city name, latitude, longitude
- Normalizes field names across providers
- Updates every `discover.interval` seconds (default: 86400 = 24h)

**Source:** `src/Lib.Core/Jobs/Discover.cs`

---

## 16. File Paths

| Item | Path |
|------|------|
| Eddie profiles | `~/.eddie/` (migrated from `~/.airvpn/`) |
| Elevated service | `/usr/lib/systemd/system/eddie-elevated.service` |
| DNS backup | `/etc/resolv.conf.eddievpn` |
| systemd-resolved backup | `/etc/systemd_resolve_netif_<iface>.eddievpn` |
| nftables backup | `<temp>/netlock_nftables_backup.nft` |
| iptables backup (IPv4) | `<temp>/netlock_iptables_backup_ipv4.txt` |
| iptables backup (IPv6) | `<temp>/netlock_iptables_backup_ipv6.txt` |
| WireGuard kernel module | `/sys/module/wireguard/version` |

---

*Document generated from Eddie v2.24.6 source. All file references are relative to https://github.com/AirVPN/Eddie/tree/master/src/*
