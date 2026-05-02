# awall-nft

`awall-nft` is a lightweight generator that converts a small, practical subset of
Alpine Wall (awall)-style JSON configuration into native nftables rules.

It is designed for embedded Linux gateways and router-like products where writing
iptables/nftables rules by hand is error-prone, while larger firewall managers can
be too heavy or too dynamic for the target system.

The project is intentionally not a full awall reimplementation. It focuses on the
subset that is useful for the current product use case:

- zones
- base policies
- filter rules
- DNAT
- SNAT masquerade
- TCP MSS clamp
- service definitions
- SSH-style connection limiting

The generated ruleset can be checked with `nft -c -f` before applying it.

## Motivation

The original system uses awall JSON as a declarative firewall configuration layer.
awall then generates iptables rules.

That has worked well, but iptables is gradually becoming legacy infrastructure,
and awall does not currently generate native nftables rules. At the same time,
directly writing nftables rules is easy to get wrong:

- choosing the wrong hook or priority
- mixing up `input`, `forward`, and `output`
- forgetting NAT/filter interactions
- allowing traffic from an unintended interface
- forgetting IPv4/IPv6 differences
- creating noisy log-drop rules on Internet-facing interfaces

`awall-nft` keeps the small declarative configuration model, but generates native
nftables rules directly.

## Design goals

- Keep the configuration model small and understandable.
- Treat JSON configuration as the single source of truth.
- Generate native nftables rules, not iptables rules.
- Validate before applying.
- Default to safe behavior:
  - `input`, `forward`, and `output` chains use `policy drop`.
  - only explicitly configured zone interfaces are allowed.
  - unexpected interfaces are not implicitly trusted.
- Avoid noisy default logging for Internet-facing drops.
- Keep the implementation lightweight and suitable for embedded Linux.

## Current status

The current implementation can:

- parse awall-style JSON files using `sunny`
- read `optional/main.json` and its import list
- merge `base`, `zone`, `filter`, `dnat`, and `snat` JSON files
- parse awall service definitions
- validate the merged configuration
- resolve service names such as `ssh`, `dns`, and `rdp`
- normalize wildcard-like interface names such as `br+` and `wg+`
- generate nftables rules
- run `nft -c -f` to check a generated ruleset
- optionally apply a checked ruleset with `nft -f`

The generated nftables ruleset has already been checked successfully with
`nft -c`.

## Configuration flow

The expected awall-style layout is:

```text
/etc/awall/
  optional/
    main.json
  private/
    base.json
    zone.json
    filter.json
    dnat.json
    snat.json
```

A typical `optional/main.json` looks like this:

```json
{
  "description": "Main firewall",
  "import": [
    "base",
    "zone",
    "filter",
    "dnat",
    "snat"
  ]
}
```

`awall-nft` reads `main.json`, loads the imported JSON files from the private
directory, merges them, validates them, resolves services, and emits nftables
rules.

## Supported awall subset

### Zones

Example:

```json
{
  "zone": {
    "LAN": {
      "iface": ["ppp100", "br+"]
    },
    "WAN": {
      "iface": ["ppp0", "ppp1", "wlan0", "wwan0"]
    },
    "Closed": {
      "iface": ["eth0", "eth1"]
    }
  }
}
```

Interface names ending in `+` are emitted as nftables prefix matches:

```text
br+ -> iifname "br*"
wg+ -> iifname "wg*"
```

### Policies

Example:

```json
{
  "policy": [
    { "in": "_fw", "out": "WAN", "action": "accept" },
    { "in": "LAN", "action": "accept" },
    { "out": "LAN", "action": "accept" },
    { "in": "WAN", "action": "drop" },
    { "in": "Closed", "action": "accept" },
    { "out": "Closed", "action": "accept" }
  ]
}
```

The generated nftables filter chains use `policy drop`, then explicitly emit
rules for the configured zones.

This avoids accidentally accepting traffic on unexpected interfaces such as USB
NICs or dynamically created interfaces.

### Filter rules

Example:

```json
{
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "service": "ssh",
      "action": "accept",
      "conn-limit": {
        "count": 3,
        "interval": 20
      }
    }
  ]
}
```

The service name is resolved using `services.json`.

### DNAT

Example:

```json
{
  "dnat": [
    {
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "to-addr": "192.168.253.5",
      "to-port": 22
    },
    {
      "in": "Closed",
      "service": "rdp",
      "to-addr": "192.168.253.201",
      "to-port": 3389
    }
  ]
}
```

Both inline service definitions and named services are supported.

### SNAT / masquerade

The current supported SNAT form is the practical masquerade form:

```json
{
  "snat": [
    { "out": ["WAN", "Closed"] }
  ]
}
```

This is emitted as nftables `masquerade` rules for the interfaces in those zones.

Unsupported for now:

- `to-addr` SNAT
- `to-port` SNAT
- service-scoped SNAT
- `action: exclude`

### TCP MSS clamp

Example:

```json
{
  "clamp-mss": [
    { "out": ["WAN", "Closed"] }
  ]
}
```

This is emitted in an nftables postrouting mangle hook using:

```nft
tcp flags syn tcp option maxseg size set rt mtu
```

### Services

The service definition format supports both object and array forms:

```json
{
  "service": {
    "ssh": { "proto": "tcp", "port": 22 },
    "dns": [
      { "proto": "udp", "port": 53 },
      { "proto": "tcp", "port": 53 }
    ],
    "ipsec": [
      { "proto": "esp" },
      { "proto": "udp", "port": [500, 4500] }
    ]
  }
}
```

`port` may be either a single number or an array.

Supported protocols currently include:

- `tcp`
- `udp`
- `icmp`
- `icmpv6`
- `esp`
- `gre`
- `ospf`
- `igmp`

### Connection limiting

awall may generate iptables `recent` rules like:

```iptables
-m recent --update --seconds 20 --hitcount 3 --rsource -j logdrop
-m recent --set --rsource -j ACCEPT
```

`awall-nft` emits a native nftables meter-based rule instead. It intentionally
does not log drops.

For:

```json
"conn-limit": {
  "count": 3,
  "interval": 20
}
```

the generated rule uses a per-source-address meter and converts the rate to a
per-minute value:

```text
ceil(count * 60 / interval)
```

So `3` in `20` seconds becomes `9/minute`.

This is not an exact behavioral clone of iptables `recent`, but it is suitable
for suppressing SSH scan bursts without flooding logs.

## Generated nftables structure

The generator currently emits:

```text
table inet awall_nft
  chain input
  chain forward
  chain output
  chain postrouting_mangle

table ip awall_nft_nat
  chain prerouting
  chain postrouting
```

The filter chains use `policy drop`.

The NAT table is IPv4-only at the moment because the current use case is IPv4
DNAT/SNAT masquerade.

## CLI

### Generate ruleset

```sh
awall_nft generate \
  --main /etc/awall/optional/main.json \
  --private-dir /etc/awall/private \
  --services /usr/share/awall/mandatory/services.json \
  -o /tmp/awall_nft.nft
```

The defaults are:

```text
--main        /etc/awall/optional/main.json
--private-dir /etc/awall/private
--services    /usr/share/awall/mandatory/services.json
```

So the same command can usually be shortened to:

```sh
awall_nft generate -o /tmp/awall_nft.nft
```

### Check generated ruleset

```sh
awall_nft check /tmp/awall_nft.nft
```

This runs:

```sh
nft -c -f /tmp/awall_nft.nft
```

### Generate and check

```sh
awall_nft build-check -o /tmp/awall_nft.nft
```

### Apply ruleset

```sh
awall_nft apply /tmp/awall_nft.nft
```

By default, `apply` checks the ruleset first. To skip the check:

```sh
awall_nft apply --no-check /tmp/awall_nft.nft
```

Skipping the check is not recommended for normal use.

## Build

```sh
nimble build -d:release
```

Cross-compiling to ARM is also possible, for example:

```sh
nimble build -d:release --cpu:arm
arm-linux-gnueabihf-strip awall_nft
```

## Suggested boot-time use

Because the generator is lightweight, the ruleset can be generated at boot time
instead of saving and restoring a generated firewall state.

A typical flow is:

```sh
awall_nft generate -o /run/awall_nft/ruleset.nft
awall_nft apply /run/awall_nft/ruleset.nft
```

This keeps the JSON configuration as the source of truth.

## Differences from awall/iptables

Intentional differences:

- Native nftables output instead of iptables rules.
- No logdrop chains by default.
- `conn-limit` uses nftables meter/limit instead of iptables `recent`.
- Filter chains use `policy drop`.
- Undefined interfaces are not trusted.
- Rules are compacted using nftables sets and prefix interface matches.

Unsupported or incomplete areas:

- full awall compatibility
- arbitrary awall variables
- nested imports
- full SNAT feature set
- ipset/address-set configuration
- flowtable generation
- rollback/apply safety beyond `nft -c`

## Future ideas

Possible future extensions:

- address-set/ipset-like support using nftables sets
- flowtable generation for static Ethernet forwarding paths
- richer validation
- rollback-safe apply mode
- configurable logging
- IPv6 NAT support if needed
- WebUI integration
- systemd service integration

## License

MIT
