# Blackhole

An encrypted proxy tool written in Go that is designed to be difficult to detect, like a black hole. It includes client and server binaries.

## Features

- **SOCKS4/SOCKS5 proxy**: the client automatically accepts SOCKS4, SOCKS4a, and unauthenticated SOCKS5 on the same local listener.
  - SOCKS4 supports IPv4 TCP `CONNECT`; SOCKS4a adds domain targets. The SOCKS4 user ID is accepted and ignored.
  - SOCKS5 supports TCP `CONNECT` and UDP `ASSOCIATE` with Full Cone NAT behavior.
- **Multiplexing**: one socket connection supports multiple channels, reducing connection overhead.
- **TCP half-close**: mux FIN/CLOSE controls preserve directional EOF for protocols that finish sending before they finish receiving.
- **Per-channel flow control**: each mux channel has an independent dynamic receive window to prevent one slow channel from blocking the entire mux connection.
- **XChaCha20 encryption**: traffic between client and server is encrypted with the XChaCha20 stream cipher.
- **Obfuscation headers**: the client first packet has a 32-byte plaintext obfuscation head plus an 8-byte header auth tag; later packets use 6-byte headers. Headers impersonate private protocol headers, are generated with PCG32, and rotate every 16 days.
- **HMAC validation**: packets use truncated HMAC-SHA256 validation to protect integrity.
- **Multi-user support**: one server port supports multiple users with separate encryption passwords and traffic accounting.
- **Traffic obfuscation**: dynamic padding obscures traffic characteristics.
- **Traffic balancing**: dynamic upload/download balancing avoids excessive traffic ratios and helps reduce behavioral fingerprints.
- **Replay resistance**: timestamp checks and nonce cache tables block replay attacks.
- **UDP over TCP**: UDP traffic is carried over regular mux TCP connections, providing Full Cone NAT behavior.

## Architecture

```text
TCP traffic:
┌──────────┐ SOCKS4/5 TCP  ┌──────────┐    XChaCha20/Mux    ┌──────────┐    TCP     ┌──────────┐
│   App    │ ──────────>   │  Client  │ ─────────────────>  │  Server  │ ────────>  │  Target  │
└──────────┘               └──────────┘                     └──────────┘            └──────────┘

UDP traffic:
┌──────────┐  SOCKS5 UDP   ┌──────────┐    XChaCha20/Mux    ┌──────────┐    UDP     ┌──────────┐
│   App    │ <──────────>  │  Client  │ <────────────────>  │  Server  │ <────────> │  Target  │
└──────────┘               └──────────┘                     └──────────┘            └──────────┘
                              local UDP                       Full Cone NAT
```

## Protocol

Detailed protocol documentation is in `protocol.md`.

## Build

```bash
# Build all command binaries
go build -o ./bin/client ./cmd/client
go build -o ./bin/server ./cmd/server
go build -o ./bin/httpclient ./cmd/httpclient
go build -o ./bin/test_udp_dns ./cmd/test_udp_dns
go build -o ./bin/test ./cmd/test
```

The version is read from the source code.
GitHub release archives include `client.json`, `server.json`, and `httpclient.json` as ready-to-edit sample configs. Android archives set `client_binary` to an explicit empty string because the SOCKS client must be started separately there. Local build scripts do not copy or overwrite configuration files in `bin/`.

All command binaries support:

```bash
./bin/client -version
```

## Configuration

### Client Config

Minimal client config:

```json
{
  "local_addr": "127.0.0.1:1080",
  "server_addr": "127.0.0.1:18080",
  "key": "header-pass",
  "name": "default",
  "password": "user-pass"
}
```

Full client config:

```json
{
  "server_addr": "127.0.0.1:18080",
  "local_addr": "127.0.0.1:1080",
  "proxy": "",
  "server_response_timeout": 20,
  "udp_associate_idle_timeout": 60,
  "max_active_channels": 32,
  "max_channel_allocations": 128,
  "max_mux_age": 600,
  "debug": false,
  "activity_log": false,
  "flow_control_debug": false,
  "key": "header-pass",
  "header_type": "printable",
  "name": "default",
  "password": "user-pass"
}
```

#### Client fields

- **`local_addr`**: Local SOCKS listener address. The listener detects the SOCKS version from the first byte. SOCKS4 supports IPv4 `CONNECT`, SOCKS4a supports domain `CONNECT`, SOCKS4 `BIND` is rejected, and UDP is available only through SOCKS5 `UDP ASSOCIATE`.
- **`server_addr`**: Server address in `host:port` form for the single-server configuration.
- **`key`**: Global server key used by the selected server connection.
- **`name`**: User name used to authenticate the single-server configuration.
- **`password`**: Password used to authenticate the single-server configuration.
- **`servers`**: Optional multi-server list. Each entry has its own `server_addr`, `key`, `name`, `password`, optional `proxy`, `header_type`, and `remarks`. An entry missing a required connection or credential field is skipped.
- **`proxy`**: Optional unauthenticated proxy for outbound mux TCP connections. Supported values are `http://host:port` and `socks5://host:port`. HTTP uses `CONNECT`; SOCKS5 uses no-auth `CONNECT`. A `proxy` inside a `servers` entry overrides this global value.
- **`header_type`**: Obfuscation-header byte set. Supported values are `printable`, `any`, `ALPHABET`, `Alphabet`, `alphabet`, and `alnum`. The `alnum` type limits generated magic bytes to `A-Z`, `a-z`, and `0-9`.
- **`server_response_timeout`**: Overall seconds from sending a TCP connect or UDP associate channel request until receiving the final target setup result. The intermediate channel-registration acknowledgement does not extend the deadline. The default is `20` for an omitted or non-positive value.
- **`udp_associate_idle_timeout`**: Idle seconds before the local client closes a UDP association. Any accepted upstream or downstream UDP packet refreshes the timer. The default is `60` for an omitted or non-positive value.
- **`max_active_channels`**: Maximum channels that one client mux may keep active at the same time. The default is `32` for an omitted or non-positive value; configured positive values are capped at `224`.
- **`max_channel_allocations`**: Total channels one client mux may allocate before a new mux is opened. The default is `128`; configured values are clamped to `[1,224]`.
- **`max_mux_age`**: Seconds during which a client-created mux may accept new channels. Existing channels continue running after the age expires. The default is `600`, configured values are clamped to `[60,3600]`, and the setting does not apply to server-to-server reverse-upstream muxes.
- **`debug`**: Enables bounded diagnostics such as the configured server list, previous-mux allocation summaries, and malformed channel-response prefixes. Payload and response prefixes remain limited to 64 bytes. Default: `false`.
- **`activity_log`**: Enables routine logs such as SOCKS target and channel-close lines. Default: `false`.
- **`flow_control_debug`**: Enables verbose logs when a client-side channel receive window grows or shrinks. Default: `false`.

#### Multi-server selection

When a new mux is needed, the client ranks servers by health first, then combines passive throughput with server RTT. RTT is measured from sending a TCP connect or UDP associate channel request until the selected server acknowledges that it registered and parsed the channel, before reverse-route forwarding or target setup. The client averages the 5 most recent samples; a server without samples is treated as `100 ms`, and a server without measured throughput starts at `1 MiB/s`. Existing healthy muxes are reused according to their passive throughput. An unhealthy existing mux is not reused, but it does not prevent the client from opening another mux.

Dial, invalid-response, and no-response failures place a server into progressively longer retry cooldowns. Servers still in cooldown are skipped while at least one server is ready. If every configured server is cooling down, the client still tries one: each server receives weight `1 / ln(remaining_cooldown_seconds + 1)`, so a server closer to recovery is more likely to be selected without forcing every request onto a single endpoint.

### Server Config

Minimal server config:

```json
{
  "listen_addr": "0.0.0.0:18080",
  "key": "header-pass",
  "users": [
    {
      "name": "default",
      "password": "user-pass",
      "enable": true
    }
  ]
}
```

Full server config:

```json
{
  "listen_addr": "0.0.0.0:18080",
  "key": "header-pass",
  "header_type": "printable",
  "outbounds": {
    "tor": "socks5://127.0.0.1:9050"
  },
  "acl": {
    "default": "direct",
    "rules": [
      {
        "match": [".onion"],
        "action": "proxy",
        "proxy": "tor"
      }
    ]
  },
  "forward_addr": "",
  "dns_hijack": true,
  "dns_cache_ttl": 1200,
  "dns_cache_size": 4096,
  "dns_upstream_addrs": ["system", "1.1.1.1:53", "8.8.8.8:53"],
  "fake_dns_ttl": 1200,
  "fake_dns_size": 1024,
  "fake_dns_ipv6_prefix96": "fdff:ffff:ffff:ffff::/96",
  "debug": false,
  "activity_log": false,
  "flow_control_debug": false,
  "flow_control_buffer_limit": 1,
  "allow_reverse_routes": true,
  "reverse_upstreams": [],
  "users": [
    {
      "name": "default",
      "password": "user-pass",
      "enable": true,
      "allow_reverse_routes": true,
      "u": 0,
      "d": 0
    }
  ]
}
```

#### Basic server fields

- **`listen_addr`**: TCP listen address in `host:port` form.
- **`key`**: Global server key used for handshake-header authentication and obfuscation-header pools.
- **`header_type`**: Obfuscation-header byte set. It accepts the same values as the client `header_type`.
- **`forward_addr`**: Optional fallback target for connections that do not authenticate as Blackhole traffic. The server pre-matches at most 8 deterministic leading bytes against the current and adjacent handshake epochs. A definite mismatch is forwarded immediately; a possible match is read through the complete 32-byte head and 8-byte auth tag before routing. Forwarding preserves every byte already read and uses a fixed 30-second connect timeout.

#### `users`

At least one user with a non-empty trimmed `name` and `password` is required. Blank-name or blank-password entries are ignored, disabled users remain configured but cannot authenticate, and duplicate non-empty names make configuration loading fail.

- **`name`**: Unique user name.
- **`password`**: User password.
- **`enable`**: Whether the user may authenticate.
- **`allow_reverse_routes`**: Grants this user permission to register reverse routes. It must explicitly be `true`; omission means no permission.
- **`acl`**: Optional user-specific ACL evaluated before the server-level ACL.
- **`u` / `d`**: Persisted upload and download counters. The server writes traffic deltas back to the configuration file atomically every 5 minutes.

#### `outbounds` and `acl`

- **`outbounds`**: Map of names to unauthenticated HTTP/SOCKS5 proxy URLs that ACL rules may reference.
- **`acl.default`**: Server fallback action. Supported values are `direct`, `reject`, `proxy:name`, or an outbound name.
- **`acl.rules`**: Ordered rules; the first matching rule decides the action. A rule contains an OR-list in `match`, an `action` of `direct`, `reject`, or `proxy`, and a `proxy` name when the action is `proxy`.
- **`users[].acl`**: Uses the same rule syntax and is evaluated before the server ACL. Its `default` may additionally be `"default"` to fall back to the server ACL.

ACL matches support IPv4/IPv6 CIDR, optional single ports or port ranges, exact domains, suffix domains such as `.example.com` or `*.example.com`, `*` for every domain target, and optional domain ports or port ranges. Decisions use one server-wide 256-entry LRU with a sliding 300-second TTL.

When the default action is empty or `direct`, the server applies a built-in reject ACL before allowing direct access. It covers unspecified, private, shared, loopback, link-local, multicast, and ULA ranges: `0.0.0.0/32`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `::/128`, `::1/128`, `fe80::/10`, `ff00::/8`, and `fc00::/7`. IPv4-mapped IPv6 targets are normalized to IPv4 first. An explicit matching `direct` rule can intentionally override this built-in protection.

For a direct domain target, the server resolves the domain locally and checks every resulting IP against ACL again. Direct IPs are tried first, followed by proxy-allowed IPs if direct attempts fail. A request fails if all resolved IPs are rejected. Every UDP datagram is checked using its actual target; a proxy action is rejected because these HTTP/SOCKS5 TCP proxies cannot carry UDP.

#### DNS and FakeDNS fields

- **`dns_hijack`**: Whether the server resolves ordinary UDP/53 single-question DNS requests instead of using the client-requested DNS target. Default: `true`. Cache hits are returned directly in either mode.
- **`dns_cache_ttl`**: DNS cache lifetime in seconds. Reads update LRU order but do not extend TTL. Default: `1200`.
- **`dns_cache_size`**: Maximum DNS cache entries. Default: `4096`.
- **`dns_upstream_addrs`**: Upstreams used for hijacked cache misses. Default: `["system", "1.1.1.1:53", "8.8.8.8:53"]`. On Linux, `system` expands to nameservers from `/etc/resolv.conf`; elsewhere, or when none are found, it is ignored.
- **`fake_dns_ttl`**: FakeDNS mapping lifetime in seconds. Default: `1200`.
- **`fake_dns_size`**: Maximum FakeDNS mappings. Default: `1024`.
- **`fake_dns_ipv6_prefix96`**: IPv6 `/96` prefix used for FakeDNS addresses. Default: `fdff:ffff:ffff:ffff::/96`.

In non-hijack mode, cache entries are scoped by the requested DNS target. Forwarded responses are cached only when source address, transaction ID, and question match a pending query; unsolicited, truncated, and non-success responses are not cached. Hijacked misses run asynchronously, and semantically identical concurrent queries share one upstream lookup while preserving each caller's transaction ID. Each upstream attempt has a 3-second timeout and failure falls through to the next upstream.

FakeDNS handles only `.onion` and `.i2p` before any real DNS lookup, even when `dns_hijack` is disabled. AAAA and ANY queries receive a temporary IPv6 address; other query types receive no answers. A later TCP request to that IPv6 address is restored to the original domain before ACL evaluation.

#### Reverse-routing fields

- **`allow_reverse_routes`**: Server-wide master switch. Default: `true`. It does not grant permission by itself; the authenticated user must also explicitly enable `users[].allow_reverse_routes`.
- **`reverse_upstreams`**: Upstream servers to which this server connects and registers routes. Connection fields match client `servers` entries.
- **`reverse_upstreams[].route.accept`**: Route patterns accepted through this upstream registration.
- **`reverse_upstreams[].route.reject`**: Route patterns rejected before `accept` is checked.
- **`reverse_upstreams[].route.ipv6_prefix96`**: Optional IPv6 `/96` prefix advertised for reverse FakeDNS routing.
- **`reverse_upstreams[].route.priority`**: Route priority. Smaller values are preferred. Default: `256` when omitted, including registrations from older versions.

Reverse-route patterns use the same address, domain, and port syntax as ACL matches. Matching routes are tried by ascending priority; routes with the same priority retain the existing newest-registration-first behavior. Removing a user's permission during runtime configuration refresh removes that user's existing routes.

A reverse-upstream mux has no allocation-age limit and permits all 224 data-channel IDs as both total and active channels. After more than half the IDs have been allocated, the server opens and registers a replacement mux while the older one remains available until close or ID exhaustion. Before the first channel request, refresh-idle keepalives preserve the reverse mux; after channel traffic starts, keepalive returns to normal mode. A non-empty channel request counts as real data activity.

After a reverse-route update is accepted, both sides switch that mux's later-packet obfuscation/padding pool to `SHA256(user_password)[:8]`. The final channel `4` fragment is the switch point; no extra ACK is used.

Reverse-upstream example:

```json
{
  "server_addr": "upstream.example.com:18080",
  "key": "header-pass",
  "name": "default",
  "password": "user-pass",
  "route": {
    "priority": 100,
    "accept": ["192.168.0.0/16", ".example.com:443"],
    "reject": ["192.168.1.0/24:80~1024"],
    "ipv6_prefix96": "fd12:3456:789a:1::/96"
  }
}
```

#### Logging and flow-control fields

- **`debug`**: Enables bounded diagnostics for malformed channel requests. Payload prefixes remain limited to 64 bytes. Default: `false`.
- **`activity_log`**: Enables routine server-side channel-close logs. Default: `false`.
- **`flow_control_debug`**: Enables verbose logs when a server-side channel receive window grows or shrinks. Default: `false`.
- **`flow_control_buffer_limit`**: Server-wide adaptive receive-window growth budget in GiB, shared by inbound and reverse-upstream muxes. Decimals are accepted, such as `0.5` for 512 MiB. Default: `1`. The first 256 KiB per channel is free, so exhaustion never rejects a new channel; it only prevents further growth. Credit already advertised to the peer remains charged after a shrink until that credit is consumed.

Protocol-validation failures are appended to `error-YYYY-MM-DD.log` in the process working directory. File dates and timestamps use UTC, allowing old files to be removed by date. Each entry includes the reason, remote address, and at most the first 100 received bytes as hexadecimal.

#### UDP behavior

Server UDP relays have a fixed 120-second idle fallback timeout; normally the client closes an idle association first. Server-to-client UDP frames preserve the actual remote source address and port and accept responses from any remote source.

The client-side SOCKS5 relay pins an association to the IP and port of its first valid local datagram and drops later datagrams from other local sources. SOCKS5 `FRAG` sequences are reassembled before entering the mux stream, with a fixed 5-second lifetime, consecutive fragment numbering, a 127-fragment limit, and a bounded final datagram size. Invalid, incomplete, expired, or target-changing sequences are dropped as a whole.

### HTTP Client Config

```json
{
  "local_addr": "127.0.0.1:8080",
  "client_config_path": "client.json",
  "client_binary": "client"
}
```

If `client_binary` is omitted, it defaults to `"client"`. When it is explicitly set to an empty string, `httpclient` assumes the client is already running at the `local_addr` in `client_config_path`; it neither starts a subprocess nor waits for readiness. This mode supports Android environments where subprocess creation is unavailable. If `client_config_path` is empty or omitted, it defaults to `client.json`. Relative client config paths are resolved from the directory containing `httpclient.json`.

Local HTTP request headers, upstream SOCKS5 connection setup, and ordinary HTTP response headers each use a fixed 20-second timeout. When `httpclient` starts the SOCKS5 client subprocess, its readiness probe waits up to 10 seconds. An upstream setup or response timeout is returned as HTTP `504`; other upstream connection failures return `502`. Request cancellation is propagated through the HTTP server and outbound dial. Established `CONNECT` tunnels relay both directions with TCP half-close, allowing one direction to reach EOF while the reverse direction continues draining.

## Usage

### Start Server

```bash
./bin/server -c server.json
```

`-c` accepts absolute paths and nested relative paths. Relative paths are resolved from the process working directory.

### Start Client

```bash
./bin/client -c client.json
```

`-c` accepts absolute paths and nested relative paths. Relative paths are resolved from the process working directory.

### Run Test

```bash
./bin/test
```

The test program:

1. Starts the server and client automatically.
2. Connects to `www.google.com` through the SOCKS5 proxy.
3. Prints the test result.

## FAQ

### 1. Why does the first packet use a fixed header, while later packets are selected from a header pool?

To make the traffic look like a private protocol, the first packet has a fixed, explicit handshake header, while later packets look like other message types. Later packets also use a power-law distribution to better resemble how different packet types appear at different frequencies in real protocols.

### 2. Why is an independent server `key` needed?

The goal is to give different connections the same set of parameters initialized from `key`, including first-packet and later-packet headers, padding rule tables, and related protocol shape. That makes connections from different users behave consistently and look more like the same private protocol. The key also participates in first-packet authentication, so unrelated traffic can be rejected with good performance.

### 3. Why does the server warn when a user password is shorter than 14 characters?

The user password is combined with the per-epoch seed to derive the encryption key and mux MAC key. If the password is too short or has too little character variety, it is easier to guess or brute-force offline when traffic is captured. The warning is a conservative rule: at least 14 characters, including uppercase letters, lowercase letters, and digits. This keeps the password closer to the information entropy expected by nonce authentication.

### 4. Why does drain close at a fixed time before the timestamp is received, or before the preset deadline?

Before timestamp authentication, the peer is not trusted. Delaying different errors until a deadline fixed relative to socket creation reduces timing differences between failure reasons. After the timestamp is authenticated and the first deadline has already passed, later authentication errors enter the second randomized drain stage.

### 5. Why do later packets use truncated HMAC and sacrifice some authentication strength?

Mux packets already run inside an encrypted stream and are also covered by a packet MAC. The header MAC mainly binds the plaintext obfuscation prefix and compact mux header fields. Truncation reduces repeated per-packet overhead; the saved bytes make room for a wider padding obfuscation range. This is a deliberate choice to allocate more overhead budget to traffic-analysis resistance. AEAD tags cannot be truncated in the same way, so AEAD is not used here.

### 6. Why not use directly random padding lengths?

Fully random padding is easy to implement, but it can create an abnormal packet-length distribution: many different lengths appear with almost the same frequency. That distribution can reveal the presence of random padding and may even expose the padding range. The segmented mapping approach acts like a shuffle over the original distribution, making the padding much less visible from the outside.

### 7. Why do most ordinary data packets omit the padding-size field and compute it from a predefined rule?

This is meant to make lazy third-party client implementations harder. Every implementation is forced to use the same function, avoiding clients that skip padding or use random padding and thereby expose the server. It also ensures all clients under the same server behave the same way, which looks more like a coherent private protocol.

### 8. Why is there a traffic balancing mechanism?

Many proxy flows have very asymmetric upload/download ratios. If one direction stays almost silent for a long time, the connection can become easier to classify from traffic ratio alone. Probabilistic channel 0 balance control packets add limited reply traffic when the ratio is too skewed, partially masking the original traffic ratio without forcing all connections into a fixed ratio.
