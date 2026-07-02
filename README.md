# awall-nft

`awall-nft` is a small nftables tool for Linux routers.

Its main feature is **dynamic nftables flowtable synchronization** for runtime
interfaces such as PPP, WireGuard, bridges, LTE/WWAN, and product-specific
virtual links.

It also includes an awall-style JSON to nftables generator. That generator is
useful, but it is not the only reason this project exists. The `flowtable-sync`
subcommand can be useful even if you do not use Alpine Linux or awall JSON as
your firewall configuration format.

## Main feature: dynamic flowtable synchronization

Linux routers often use nftables flowtables to reduce forwarding overhead. The
hard part is not the initial static ruleset. The hard part is keeping the
flowtable device list correct when interfaces appear or disappear at runtime.

Typical examples are:

- PPP interfaces created by `pppd`
- WireGuard interfaces created by `wg-quick` or another interface manager
- bridge interfaces and bridge members
- LTE/WWAN interfaces
- virtual interfaces created by containers or product-specific services

Many router stacks handle this by regenerating or reloading the whole firewall
when interface state changes. `awall-nft flowtable-sync` takes a narrower
approach.

It updates only the flowtable-related objects:

1. read the current configuration
2. resolve configured flowtable directions to currently existing interfaces
3. flush the dedicated `flowtable_forward` chain
4. delete and recreate the `ft_forward` flowtable object with the current device set
5. re-add only the `flow add @ft_forward` rules

It does **not** flush, regenerate, or reapply the whole firewall ruleset.

This makes it suitable for hooks such as:

```sh
# /etc/ppp/ip-up.d/awall-nft-flowtable
# /etc/ppp/ip-down.d/awall-nft-flowtable
#!/bin/sh
/usr/local/sbin/awall_nft flowtable-sync || true
```

or WireGuard:

```ini
PostUp = /usr/local/sbin/awall_nft flowtable-sync || true
PostDown = /usr/local/sbin/awall_nft flowtable-sync || true
```

Normal output is intentionally compact:

```text
flowtable-sync: synced 1 rule(s), skipped 2 rule(s), devices: eth0, eth1, wlisc
```

## Why router engineers may care

If you are working on OpenWrt, firewall4, a custom Linux router, or an embedded
gateway, the interesting part of this project may be the **procedure** used by
`flowtable-sync`.

The key idea is to keep a stable insertion point for flow-offload rules and to
replace only the flowtable object and its companion chain. This avoids the broad
side effects of a full firewall reload while still allowing the flowtable device
set to follow runtime-created interfaces.

This project does not claim to replace OpenWrt firewall4. It documents and
implements a minimal nftables transaction sequence for one specific problem:

> keeping nftables flowtable devices synchronized with dynamic router interfaces
> without reloading the whole firewall.

## Secondary feature: awall-style nftables generation

The same binary can also generate a native nftables ruleset from a small,
practical subset of Alpine Wall (awall)-style JSON configuration.

This generator is intended for embedded Linux gateways and router-like products
where writing iptables/nftables rules by hand is error-prone, while larger
firewall managers can be too heavy or too dynamic for the target system.

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
- explicit nftables flowtable hints for forwarding paths
- dynamic flowtable synchronization for runtime interfaces

The generated ruleset can be checked with `nft -c -f` before applying it.

## Generator motivation

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
- Keep firewall permission rules separate from flowtable optimization hints.

## Current status

The current implementation can:

- parse awall-style JSON files using `sunny`
- read `optional/main.json` and its import list
- merge `base`, `zone`, `filter`, `dnat`, and `snat` JSON files
- parse awall service definitions
- validate the merged configuration
- resolve service names such as `ssh`, `dns`, and `rdp`
- normalize wildcard-like interface names such as `br+` and `wg+`
- allow optional zones with an empty interface list
- generate nftables rules
- generate explicit nftables flowtable rules for configured zone-to-zone directions
- limit initial flowtable devices to existing exact `ethN` interfaces
- run `nft -c -f` to check a generated ruleset
- optionally apply a checked ruleset with `nft -f`
- show the normalized configuration in a human-readable form

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

Policy order is significant, matching awall's rule ordering model.  Broad
one-sided policies are expanded in the order they appear, and more specific
Guest/DMZ policies should be placed before broad legacy policies when they are
intended to restrict those zones.

Example:

```json
{
  "policy": [
    { "in": "Guest", "out": "WAN", "action": "accept" },
    { "in": "Guest", "out": "LAN", "action": "drop" },
    { "in": "Guest", "out": "Closed", "action": "drop" },

    { "in": "DMZ", "out": "WAN", "action": "accept" },
    { "in": "DMZ", "out": "LAN", "action": "drop" },
    { "in": "DMZ", "out": "Closed", "action": "drop" },

    { "in": "_fw", "out": "WAN", "action": "accept" },
    { "in": "LAN", "action": "accept" },
    { "out": "LAN", "action": "accept" },
    { "in": "WAN", "action": "drop" },
    { "in": "Closed", "action": "accept" },
    { "out": "Closed", "action": "accept" }
  ]
}
```

In this example, `Guest -> LAN` is dropped before the later broad
`out=LAN accept` policy can match.  `show forward` can be used to inspect the
effective forward policy order.

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

### Flowtable hints

`flowtable` is an `awall-nft`-specific extension. It is not part of the
standard awall permission model.

It does not allow traffic by itself. Normal `policy`, `filter`, `dnat`, and
`snat` processing still decides which packets are accepted. The `flowtable`
section only marks explicit forward directions that may be accelerated through
nftables flowtable after they have passed the normal rules.

Example:

```json
{
  "flowtable": [
    { "in": "LAN", "out": "Closed" },
    { "in": "Closed", "out": "LAN" },
    { "in": "Closed", "out": "Closed" },
    { "in": "Guest", "out": "WAN" }
  ]
}
```

The direction is expressed in zone names, not raw interface names. For example,
`{ "in": "LAN", "out": "Closed" }` means that forward traffic entering from
interfaces in the `LAN` zone and leaving through interfaces in the `Closed` zone
may be added to the flowtable.

Important properties:

- `flowtable` is an optimization hint, not a firewall permission rule.
- `awall-nft` does not infer flowtable eligibility from `policy` rules.
- `in` and `out` are required.
- `_fw` is rejected because flowtable applies to forwarded traffic only.
- Broad one-sided policies such as `{ "in": "LAN", "action": "accept" }` do
  not automatically create flowtable rules.
- WAN-facing directions should be added only when the resulting fast path is
  understood and intended.
- `Guest -> WAN` and `DMZ -> WAN` are reasonable candidates when those forward
  policies are explicitly allowed.

During normal ruleset generation, the static generator is intentionally
conservative: only existing exact Ethernet interfaces such as `eth0` and `eth1`
are added to the initial nftables flowtable device list. Prefix-style or dynamic
interfaces such as `ppp+`, `wg+`, `br+`, `wlan0`, `wwan0`, or a WireGuard-based
closed-network interface such as `wlisc` are handled by `flowtable-sync`.

This avoids `nft -c` failures when a configured interface does not exist yet.
`flowtable-sync` reads the same JSON configuration, resolves the configured
flowtable zone directions against the currently existing interfaces, recreates
the `ft_forward` flowtable object with the desired device set, and rebuilds the
`flowtable_forward` chain. It does not rebuild the whole firewall ruleset.

Typical generated output looks like this:

```nft
flowtable ft_forward {
  hook ingress priority 0;
  devices = { eth0, eth1 };
}

chain flowtable_forward {
  iifname "eth0" oifname "eth1" meta l4proto { tcp, udp } flow add @ft_forward
  iifname "eth1" oifname "eth0" meta l4proto { tcp, udp } flow add @ft_forward
  # awall_nft flowtable-sync may replace this chain
}
```

The generated `forward` chain jumps to `flowtable_forward` after accepting
established/related traffic and before the normal forward rules.

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
  flowtable ft_forward        # emitted when flowtable devices exist
  chain input
  chain flowtable_forward
  chain forward
  chain output
  chain postrouting_mangle

table ip awall_nft_nat
  chain prerouting
  chain postrouting
```

The filter chains use `policy drop`. The `flowtable_forward` chain is emitted as
a stable insertion point for flowtable rules. `flowtable-sync` can refresh that
chain and recreate the `ft_forward` flowtable object without rewriting the whole
ruleset.

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

By default, the generated ruleset no longer starts with `flush ruleset`.
Instead, it emits a prelude that replaces only the tables managed by awall_nft:

```nft
destroy table inet awall_nft
destroy table ip awall_nft_nat
```

This keeps tables created by other services, such as LXC, while recreating only the awall_nft-managed tables.
Use `--flush-ruleset` only when a full nftables reset is explicitly desired.

```sh
awall_nft generate --flush-ruleset -o /tmp/awall_nft.nft
```

To emit no cleanup prelude, use:

```sh
awall_nft generate --no-replace-managed-tables -o /tmp/awall_nft.nft
```

`--no-flush-ruleset` remains as a compatibility alias.

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

### Show normalized configuration

```sh
awall_nft show all
```

`show` is read-only.  It loads and normalizes the same configuration used by
`generate`, then prints a human-readable summary.  It does not run `nft` and does
not modify the firewall.

Available topics:

```text
all
zones
policies
forward
filters
dnat
snat
clamp-mss
flowtable
```

`show forward` is useful when broad policies and explicit Guest/DMZ policies are
mixed.  It prints the policy order that affects FORWARD rule generation, for
example:

```text
policy[0] Guest -> WAN  accept
policy[1] Guest -> LAN  drop
policy[4] LAN -> *  accept
policy[5] * -> LAN  accept
```

`*` means that the corresponding side was omitted in the original awall-style
policy.

### Synchronize flowtable devices

```sh
awall_nft flowtable-sync
```

This command is intended for runtime-created interfaces such as PPP, WireGuard,
bridges, and product-specific closed-network interfaces such as `wlisc`.

It performs the following limited update:

1. read and normalize the current awall-style JSON configuration
2. resolve explicit `flowtable` zone directions to currently existing interfaces
3. flush `chain inet awall_nft flowtable_forward`
4. recreate `flowtable inet awall_nft ft_forward` with the resolved devices
5. re-add the matching `flow add @ft_forward` rules

It does not regenerate or reapply the whole firewall ruleset.

Typical hook examples:

```sh
# /etc/ppp/ip-up.d/awall-nft-flowtable
# /etc/ppp/ip-down.d/awall-nft-flowtable
#!/bin/sh
/usr/local/sbin/awall_nft flowtable-sync || true
```

For WireGuard or a WireGuard-based closed-network interface, call the same command
from the interface manager, or from `PostUp` / `PostDown` when using `wg-quick`.

Normal output is intentionally compact:

```text
flowtable-sync: synced 1 rule(s), skipped 2 rule(s), devices: eth0, eth1, wlisc
```

`flowtable-sync` is serialized with a process-level lock under
`/run/lock/awall_nft/`. It is safe to call it from multiple interface or
boot-time hooks; concurrent invocations wait for the running instance instead of
updating nftables in parallel. When this happens, `flowtable-sync` logs that it
is waiting for the lock and logs again after the lock has been acquired.

Rules whose input or output side resolves to no existing interface are skipped.

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
- Zones with an empty interface list are allowed and skipped by the emitter.
- Rules are compacted using nftables sets and prefix interface matches.

Unsupported or incomplete areas:

- full awall compatibility
- arbitrary awall variables
- nested imports
- full SNAT feature set
- ipset/address-set configuration
- rollback/apply safety beyond `nft -c`

## Future ideas

Possible future extensions:

- address-set/ipset-like support using nftables sets
- richer validation
- rollback-safe apply mode
- configurable logging
- IPv6 NAT support if needed
- WebUI integration
- systemd service integration

## License

MIT
