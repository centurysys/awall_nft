import std/[algorithm, options, os, strformat, strutils, tables]

import ./errors
import ./types

type
  FlowtableMode* = enum
    ftOff
    ftAuto
    ftOn

  NftEmitOptions* = object
    inetTableName*: string
    natTableName*: string
    includeFlushRuleset*: bool
    allowRoutingIcmp*: bool
    flowtableMode*: FlowtableMode
    flowtableName*: string

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc defaultNftEmitOptions*(): NftEmitOptions =
  result = NftEmitOptions(
    inetTableName: "awall_nft",
    natTableName: "awall_nft_nat",
    includeFlushRuleset: true,
    allowRoutingIcmp: true,
    flowtableMode: ftAuto,
    flowtableName: "ft_forward",
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc q(s: string): string =
  result = "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc indent(level: int): string =
  result = repeat("  ", level)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addLine(outp: var string, level: int, line: string) =
  outp.add(indent(level))
  outp.add(line)
  outp.add("\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sortedStrings(values: seq[string]): seq[string] =
  result = values
  result.sort(proc(a, b: string): int =
    result = cmp(a, b)
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc joinQuotedSet(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 1:
    result = q(sorted[0])
    return

  var parts: seq[string] = @[]

  for value in sorted:
    parts.add(q(value))

  result = "{ " & parts.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc joinBareSet(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 1:
    result = sorted[0]
    return

  result = "{ " & sorted.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc nftIdentPart(s: string): string =
  result = ""

  for ch in s:
    if ch in {'a'..'z'} or ch in {'0'..'9'}:
      result.add(ch)
    elif ch in {'A'..'Z'}:
      result.add(toLowerAscii(ch))
    else:
      result.add('_')

  if result.len == 0:
    result = "unnamed"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneIfaceSetName(zone: ZoneName): string =
  result = &"if_{nftIdentPart(string(zone))}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc forwardKnownIfaceSetName(): string =
  result = "if_forward_known"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc flowtablePairSetName(): string =
  result = "flowtable_pairs"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc joinPortSet(ports: seq[uint16]): string =
  if ports.len == 1:
    result = $ports[0]
    return

  var parts: seq[string] = @[]

  for port in ports:
    parts.add($port)

  result = "{ " & parts.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc combineConds(a: string, b: string): string =
  if a.len == 0:
    result = b
    return

  if b.len == 0:
    result = a
    return

  result = a & " " & b

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc actionText(action: Action): string =
  case action
  of actAccept:
    result = "accept"
  of actDrop:
    result = "drop"
  of actReject:
    result = "reject"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc protoText(proto: Protocol): string =
  case proto
  of protoTcp:
    result = "tcp"
  of protoUdp:
    result = "udp"
  of protoIcmp:
    result = "icmp"
  of protoIcmpv6:
    result = "icmpv6"
  of protoEsp:
    result = "esp"
  of protoGre:
    result = "gre"
  of protoOspf:
    result = "ospf"
  of protoIgmp:
    result = "igmp"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc cartesianConditions(a: seq[string], b: seq[string]): seq[string] =
  result = @[]

  for left in a:
    for right in b:
      result.add(combineConds(left, right))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneRuntime(cfg: NormalizedConfig, zone: ZoneName): AE[ZoneRuntime] =
  if cfg.zones.hasKey(zone):
    result = ok(cfg.zones[zone])
    return

  result = fail[ZoneRuntime](
    ekUnknownZone,
    "unknown zone in nft emitter: " & $zone
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneMatchConditions(
    cfg: NormalizedConfig,
    zones: seq[ZoneName],
    direction: string,
    useNamedSets = true
): AE[seq[string]] =
  var conditions: seq[string] = @[]

  if zones.len == 0:
    conditions.add("")
    result = ok(conditions)
    return

  for zone in zones:
    if zone == ZoneFirewall:
      conditions.add("")
      continue

    let runtime = ?zoneRuntime(cfg, zone)

    var exacts: seq[string] = @[]

    for iface in runtime.exactIfaces:
      exacts.add(string(iface))

    if exacts.len > 0:
      if useNamedSets:
        conditions.add(&"{direction} @{zoneIfaceSetName(zone)}")
      else:
        conditions.add(&"{direction} {joinQuotedSet(exacts)}")

    for prefix in sortedStrings(runtime.prefixIfaces):
      conditions.add(direction & " " & q(prefix & "*"))

  result = ok(conditions)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectForwardKnownIifMatches(
    cfg: NormalizedConfig
): tuple[exacts: seq[string], prefixes: seq[string]] =
  var exactSeen = initTable[string, bool]()
  var prefixSeen = initTable[string, bool]()

  result.exacts = @[]
  result.prefixes = @[]

  for _, runtime in cfg.zones:
    for iface in runtime.exactIfaces:
      let name = string(iface)

      if not exactSeen.hasKey(name):
        exactSeen[name] = true
        result.exacts.add(name)

    for prefix in runtime.prefixIfaces:
      if not prefixSeen.hasKey(prefix):
        prefixSeen[prefix] = true
        result.prefixes.add(prefix)

  result.exacts = sortedStrings(result.exacts)
  result.prefixes = sortedStrings(result.prefixes)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isDigitString(s: string): bool =
  if s.len == 0:
    result = false
    return

  for ch in s:
    if ch < '0' or ch > '9':
      result = false
      return

  result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isStaticEthernetFlowIface(name: string): bool =
  ## Conservative auto-detection for the first flowtable implementation.
  ##
  ## Only ethN-style exact interfaces are selected automatically. Dynamic or
  ## virtual interfaces such as ppp*, wg*, br*, wlan*, wwan*, veth*, lxcbr* are
  ## intentionally excluded for now.
  if not name.startsWith("eth"):
    result = false
    return

  result = isDigitString(name[3 ..< name.len])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc netIfaceExists(name: string): bool =
  ## nftables flowtable devices must exist when the ruleset is checked/applied.
  ##
  ## Zone definitions may intentionally contain future or optional interfaces.
  ## Those are fine for iifname/oifname matches, but they cannot be listed in
  ## flowtable devices. Therefore flowtable generation must use only currently
  ## existing netdevices.
  result = dirExists("/sys/class/net" / name)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectFlowtableIfaces(cfg: NormalizedConfig, opts: NftEmitOptions): seq[string] =
  result = @[]

  if opts.flowtableMode == ftOff:
    return

  var seen = initTable[string, bool]()

  for _, zone in cfg.zones:
    for iface in zone.exactIfaces:
      let name = string(iface)

      if not isStaticEthernetFlowIface(name):
        continue

      if not netIfaceExists(name):
        continue

      if not seen.hasKey(name):
        seen[name] = true
        result.add(name)

  result = sortedStrings(result)

  if opts.flowtableMode == ftAuto and result.len < 2:
    result = @[]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc serviceMatchText(match: NormalizedServiceMatch): AE[string] =
  case match.proto
  of protoTcp, protoUdp:
    if match.ports.len == 0:
      return fail[string](
        ekInvalidRule,
        $match.proto & " match requires at least one port"
      )

    result = ok(protoText(match.proto) & " dport " & joinPortSet(match.ports))

  of protoIcmp:
    if match.icmpType.isSome:
      result = ok("icmp type " & $match.icmpType.get())
    else:
      result = ok("icmp")

  of protoIcmpv6:
    if match.icmpType.isSome:
      result = ok("icmpv6 type " & $match.icmpType.get())
    else:
      result = ok("icmpv6")

  of protoEsp, protoGre, protoOspf, protoIgmp:
    result = ok("meta l4proto " & protoText(match.proto))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc tcpUdpOnly(match: NormalizedServiceMatch, where: string): AE[void] =
  case match.proto
  of protoTcp, protoUdp:
    result = okVoid()
  else:
    result = failVoid(
      ekUnsupported,
      where & ": conn-limit is supported only for tcp/udp port rules"
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc ratePerMinute(limit: ConnLimit): uint32 =
  let numerator = limit.count * 60
  result = (numerator + limit.interval - 1) div limit.interval

  if result == 0:
    result = 1

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc connLimitDropRule(
    baseCondition: string,
    match: NormalizedServiceMatch,
    limit: ConnLimit,
    meterName: string,
    familyPrefix: string
): AE[string] =
  ?tcpUdpOnly(match, "conn-limit")

  let svc = ?serviceMatchText(match)
  let rate = ratePerMinute(limit)
  let condition = combineConds(baseCondition, svc)
  let meter =
    "ct state new meter " & meterName & " { " & familyPrefix &
    " saddr timeout " & $limit.interval & "s limit rate over " &
    $rate & "/minute } drop"

  result = ok(combineConds(condition, meter))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc connLimitDropRules(
    baseCondition: string,
    match: NormalizedServiceMatch,
    limit: ConnLimit,
    meterName: string
): AE[seq[string]] =
  var rules: seq[string] = @[]

  case match.family
  of famInet:
    rules.add(?connLimitDropRule(baseCondition, match, limit, meterName, "ip"))

  of famInet6:
    rules.add(?connLimitDropRule(baseCondition, match, limit, meterName, "ip6"))

  of famAny:
    rules.add(?connLimitDropRule(baseCondition, match, limit, meterName & "_ip", "ip"))
    rules.add(?connLimitDropRule(baseCondition, match, limit, meterName & "_ip6", "ip6"))

  result = ok(rules)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc filterChain(rule: NormalizedFilterRule): string =
  let inIsFw = rule.inZones.len == 1 and rule.inZones[0] == ZoneFirewall
  let outIsFw = rule.outZones.len == 1 and rule.outZones[0] == ZoneFirewall

  if outIsFw:
    result = "input"
    return

  if inIsFw:
    result = "output"
    return

  result = "forward"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc filterBaseConditions(
    cfg: NormalizedConfig,
    rule: NormalizedFilterRule,
    chain: string
): AE[seq[string]] =
  case chain
  of "input":
    result = zoneMatchConditions(cfg, rule.inZones, "iifname")
  of "output":
    result = zoneMatchConditions(cfg, rule.outZones, "oifname")
  else:
    let inConds = ?zoneMatchConditions(cfg, rule.inZones, "iifname")
    let outConds = ?zoneMatchConditions(cfg, rule.outZones, "oifname")
    result = ok(cartesianConditions(inConds, outConds))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitRoutingIcmpRules(outp: var string, chain: string, opts: NftEmitOptions) =
  if not opts.allowRoutingIcmp:
    return

  case chain
  of "input":
    addLine(outp, 2, "ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")
    addLine(outp, 2, "ip6 nexthdr ipv6-icmp accept")

  of "forward":
    addLine(outp, 2, "ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")
    addLine(outp, 2, "ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept")

  of "output":
    addLine(outp, 2, "ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")
    addLine(outp, 2, "ip6 nexthdr ipv6-icmp accept")

  else:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc policyAppliesToInput(policy: PolicyRule): bool =
  if policy.inZones.len > 0 and policy.outZones.len == 0:
    result = true
    return

  if policy.outZones.len == 1 and policy.outZones[0] == ZoneFirewall:
    result = true
    return

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc policyAppliesToForward(policy: PolicyRule): bool =
  if policy.inZones.len > 0 and policy.outZones.len == 0:
    result = true
    return

  if policy.outZones.len > 0 and policy.inZones.len == 0:
    result = true
    return

  if policy.inZones.len > 0 and policy.outZones.len > 0:
    if policy.inZones.len == 1 and policy.inZones[0] == ZoneFirewall:
      result = false
      return

    if policy.outZones.len == 1 and policy.outZones[0] == ZoneFirewall:
      result = false
      return

    result = true
    return

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc policyAppliesToOutput(policy: PolicyRule): bool =
  if policy.inZones.len == 1 and policy.inZones[0] == ZoneFirewall:
    result = true
    return

  if policy.outZones.len > 0 and policy.inZones.len == 0:
    result = true
    return

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitPolicyForInput(
    outp: var string,
    cfg: NormalizedConfig,
    policy: PolicyRule
): AE[void] =
  if policy.outZones.len == 1 and policy.outZones[0] == ZoneFirewall:
    let inConds = ?zoneMatchConditions(cfg, policy.inZones, "iifname")

    for cond in inConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

    result = okVoid()
    return

  if policy.inZones.len > 0 and policy.outZones.len == 0:
    let inConds = ?zoneMatchConditions(cfg, policy.inZones, "iifname")

    for cond in inConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitPolicyForForward(
    outp: var string,
    cfg: NormalizedConfig,
    policy: PolicyRule
): AE[void] =
  if policy.inZones.len > 0 and policy.outZones.len > 0:
    let inConds = ?zoneMatchConditions(cfg, policy.inZones, "iifname")
    let outConds = ?zoneMatchConditions(cfg, policy.outZones, "oifname")

    for cond in cartesianConditions(inConds, outConds):
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

    result = okVoid()
    return

  if policy.inZones.len > 0:
    let inConds = ?zoneMatchConditions(cfg, policy.inZones, "iifname")

    for cond in inConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

    result = okVoid()
    return

  if policy.outZones.len > 0:
    let outConds = ?zoneMatchConditions(cfg, policy.outZones, "oifname")

    for cond in outConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitPolicyForOutput(
    outp: var string,
    cfg: NormalizedConfig,
    policy: PolicyRule
): AE[void] =
  if policy.inZones.len == 1 and policy.inZones[0] == ZoneFirewall:
    let outConds = ?zoneMatchConditions(cfg, policy.outZones, "oifname")

    for cond in outConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

    result = okVoid()
    return

  if policy.outZones.len > 0 and policy.inZones.len == 0:
    let outConds = ?zoneMatchConditions(cfg, policy.outZones, "oifname")

    for cond in outConds:
      addLine(outp, 2, combineConds(cond, actionText(policy.action)))

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFilterRuleForChain(
    outp: var string,
    cfg: NormalizedConfig,
    rule: NormalizedFilterRule,
    chain: string,
    ruleIndex: int
): AE[void] =
  let baseConds = ?filterBaseConditions(cfg, rule, chain)

  for baseCond in baseConds:
    for match in rule.matches:
      if rule.connLimit.isSome:
        let meterName = "limit_filter_" & chain & "_" & $ruleIndex
        let drops = ?connLimitDropRules(
          baseCond,
          match,
          rule.connLimit.get(),
          meterName
        )

        for dropRule in drops:
          addLine(outp, 2, dropRule)

      let svc = ?serviceMatchText(match)
      let condition = combineConds(baseCond, svc)
      let line = combineConds(condition, actionText(rule.action))
      addLine(outp, 2, line)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitNamedIfaceSet(outp: var string, setName: string, ifaces: seq[string]) =
  let sorted = sortedStrings(ifaces)

  if sorted.len == 0:
    return

  var parts: seq[string] = @[]

  for iface in sorted:
    parts.add(q(iface))

  let elementsText = parts.join(", ")

  addLine(outp, 1, &"set {setName} {{")
  addLine(outp, 2, "type ifname;")
  addLine(outp, 2, &"elements = {{ {elementsText} }};")
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitZoneIfaceSets(outp: var string, cfg: NormalizedConfig) =
  var zoneNames: seq[ZoneName] = @[]

  for zoneName, _ in cfg.zones:
    zoneNames.add(zoneName)

  zoneNames.sort(proc(a, b: ZoneName): int =
    result = cmp(string(a), string(b))
  )

  for zoneName in zoneNames:
    let runtime = cfg.zones[zoneName]
    var ifaces: seq[string] = @[]

    for iface in runtime.exactIfaces:
      ifaces.add(string(iface))

    emitNamedIfaceSet(outp, zoneIfaceSetName(zoneName), ifaces)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitForwardKnownIfaceSet(outp: var string, cfg: NormalizedConfig) =
  let matches = collectForwardKnownIifMatches(cfg)
  emitNamedIfaceSet(outp, forwardKnownIfaceSetName(), matches.exacts)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitInputChain(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  addLine(outp, 1, "chain input {")
  addLine(outp, 2, "type filter hook input priority filter; policy drop;")
  addLine(outp, 2, "ct state established,related accept")
  addLine(outp, 2, "iifname " & q("lo") & " accept")
  emitRoutingIcmpRules(outp, "input", opts)

  var index = 0

  for rule in cfg.filters:
    if filterChain(rule) == "input":
      ?emitFilterRuleForChain(outp, cfg, rule, "input", index)

    inc(index)

  for policy in cfg.policies:
    if policyAppliesToInput(policy):
      ?emitPolicyForInput(outp, cfg, policy)

  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFlowtableObject(outp: var string, ifaces: seq[string], opts: NftEmitOptions) =
  if ifaces.len == 0:
    return

  addLine(outp, 1, "flowtable " & opts.flowtableName & " {")
  addLine(outp, 2, "hook ingress priority 0;")
  addLine(outp, 2, "devices = " & joinBareSet(ifaces) & ";")
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc containsString(values: seq[string], target: string): bool =
  for value in values:
    if value == target:
      result = true
      return

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addUniqueString(values: var seq[string], value: string) =
  if not containsString(values, value):
    values.add(value)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneFlowtableIfaces(
    cfg: NormalizedConfig,
    zones: seq[ZoneName],
    flowIfaces: seq[string]
): AE[seq[string]] =
  var names: seq[string] = @[]

  if zones.len == 0:
    result = ok(flowIfaces)
    return

  for zone in zones:
    if zone == ZoneFirewall:
      continue

    let runtime = ?zoneRuntime(cfg, zone)

    for iface in runtime.exactIfaces:
      let name = string(iface)

      if containsString(flowIfaces, name):
        addUniqueString(names, name)

    for prefix in runtime.prefixIfaces:
      for iface in flowIfaces:
        if iface.startsWith(prefix):
          addUniqueString(names, iface)

  result = ok(sortedStrings(names))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectFlowtablePairElements(
    cfg: NormalizedConfig,
    flowIfaces: seq[string]
): AE[seq[string]] =
  ## Collect exact iifname/oifname pairs that may enter the nftables flowtable.
  ##
  ## The flowtable section is an optimization hint, not a permission rule.
  ## Normal policy/filter/DNAT rules must still allow the traffic. This collector
  ## only decides which already-allowed zone directions may enter the nftables
  ## flowtable fast path.
  var seen = initTable[string, bool]()
  var elements: seq[string] = @[]

  for rule in cfg.flowtableRules:
    let inIfaces = ?zoneFlowtableIfaces(cfg, rule.inZones, flowIfaces)
    let outIfaces = ?zoneFlowtableIfaces(cfg, rule.outZones, flowIfaces)

    for inIface in inIfaces:
      for outIface in outIfaces:
        if inIface == outIface:
          continue

        let element = &"{q(inIface)} . {q(outIface)}"

        if seen.hasKey(element):
          continue

        seen[element] = true
        elements.add(element)

  result = ok(sortedStrings(elements))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFlowtablePairSet(
    outp: var string,
    cfg: NormalizedConfig,
    flowIfaces: seq[string]
): AE[void] =
  let elements = ?collectFlowtablePairElements(cfg, flowIfaces)

  if elements.len == 0:
    result = okVoid()
    return

  let elementsText = elements.join(", ")

  addLine(outp, 1, &"set {flowtablePairSetName()} {{")
  addLine(outp, 2, "type ifname . ifname;")
  addLine(outp, 2, &"elements = {{ {elementsText} }};")
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFlowtableForwardRules(
    outp: var string,
    cfg: NormalizedConfig,
    flowIfaces: seq[string],
    opts: NftEmitOptions
): AE[void] =
  let elements = ?collectFlowtablePairElements(cfg, flowIfaces)

  if elements.len == 0:
    result = okVoid()
    return

  addLine(
    outp,
    2,
    &"iifname . oifname @{flowtablePairSetName()} ct state established meta l4proto {{ tcp, udp }} counter flow add @{opts.flowtableName}"
  )

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFlowtableForwardChain(
    outp: var string,
    cfg: NormalizedConfig,
    ifaces: seq[string],
    opts: NftEmitOptions
): AE[void] =
  addLine(outp, 1, "chain flowtable_forward {")

  if ifaces.len == 0:
    addLine(outp, 2, "# awall_nft flowtable-sync manages this chain")
  else:
    ?emitFlowtableForwardRules(outp, cfg, ifaces, opts)
    addLine(outp, 2, "# awall_nft flowtable-sync may replace this chain")

  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitForwardKnownIifChain(outp: var string, cfg: NormalizedConfig): AE[void] =
  let matches = collectForwardKnownIifMatches(cfg)

  addLine(outp, 1, "chain forward_known_iif {")

  if matches.exacts.len > 0:
    addLine(outp, 2, &"iifname @{forwardKnownIfaceSetName()} return")

  for prefix in matches.prefixes:
    addLine(outp, 2, "iifname " & q(prefix & "*") & " return")

  addLine(outp, 2, "drop")
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatForwardDaddrText(rule: NormalizedDnatRule, match: NormalizedServiceMatch): string =
  let targetAddress = string(rule.toAddr)

  if match.family == famInet6 or targetAddress.contains(":"):
    result = &"ip6 daddr {targetAddress}"
    return

  result = &"ip daddr {targetAddress}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatForwardServiceText(
    rule: NormalizedDnatRule,
    match: NormalizedServiceMatch
): AE[string] =
  case match.proto
  of protoTcp, protoUdp:
    if rule.toPort.isSome:
      result = ok(&"{protoText(match.proto)} dport {rule.toPort.get()}")
      return

    result = serviceMatchText(match)

  else:
    result = serviceMatchText(match)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitDnatForwardAcceptRules(outp: var string, cfg: NormalizedConfig): AE[void] =
  for rule in cfg.dnats:
    let inConds = ?zoneMatchConditions(cfg, rule.inZones, "iifname")

    for baseCond in inConds:
      for match in rule.matches:
        let daddr = dnatForwardDaddrText(rule, match)
        let svc = ?dnatForwardServiceText(rule, match)
        let condition = combineConds(baseCond, combineConds("ct status dnat", daddr))
        let line = combineConds(combineConds(condition, svc), "accept")
        addLine(outp, 2, line)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitForwardChain(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  addLine(outp, 1, "chain forward {")
  addLine(outp, 2, "type filter hook forward priority filter; policy drop;")
  addLine(outp, 2, "jump flowtable_forward")
  addLine(outp, 2, "ct state established,related accept")
  emitRoutingIcmpRules(outp, "forward", opts)
  addLine(outp, 2, "jump forward_known_iif")
  ?emitDnatForwardAcceptRules(outp, cfg)

  var index = 0

  for rule in cfg.filters:
    if filterChain(rule) == "forward":
      ?emitFilterRuleForChain(outp, cfg, rule, "forward", index)

    inc(index)

  for policy in cfg.policies:
    if policyAppliesToForward(policy):
      ?emitPolicyForForward(outp, cfg, policy)

  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitOutputChain(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  addLine(outp, 1, "chain output {")
  addLine(outp, 2, "type filter hook output priority filter; policy drop;")
  addLine(outp, 2, "ct state established,related accept")
  addLine(outp, 2, "oifname " & q("lo") & " accept")
  emitRoutingIcmpRules(outp, "output", opts)

  var index = 0

  for rule in cfg.filters:
    if filterChain(rule) == "output":
      ?emitFilterRuleForChain(outp, cfg, rule, "output", index)

    inc(index)

  for policy in cfg.policies:
    if policyAppliesToOutput(policy):
      ?emitPolicyForOutput(outp, cfg, policy)

  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitClampMssRules(outp: var string, cfg: NormalizedConfig): AE[void] =
  for rule in cfg.clampMssRules:
    let outConds = ?zoneMatchConditions(cfg, rule.outZones, "oifname")

    for cond in outConds:
      let line = combineConds(
        cond,
        "tcp flags syn tcp option maxseg size set rt mtu"
      )
      addLine(outp, 2, line)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitPostroutingMangleChain(outp: var string, cfg: NormalizedConfig): AE[void] =
  addLine(outp, 1, "chain postrouting_mangle {")
  addLine(outp, 2, "type filter hook postrouting priority mangle; policy accept;")
  ?emitClampMssRules(outp, cfg)
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatToText(rule: NormalizedDnatRule): string =
  if rule.toPort.isSome:
    result = "dnat to " & string(rule.toAddr) & ":" & $rule.toPort.get()
  else:
    result = "dnat to " & string(rule.toAddr)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitDnatRules(outp: var string, cfg: NormalizedConfig): AE[void] =
  for rule in cfg.dnats:
    let inConds = ?zoneMatchConditions(cfg, rule.inZones, "iifname", useNamedSets = false)

    for baseCond in inConds:
      for match in rule.matches:
        let svc = ?serviceMatchText(match)
        let condition = combineConds(baseCond, svc)
        let line = combineConds(condition, dnatToText(rule))
        addLine(outp, 2, line)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitSnatRules(outp: var string, cfg: NormalizedConfig): AE[void] =
  for rule in cfg.snats:
    let outConds = ?zoneMatchConditions(cfg, rule.outZones, "oifname", useNamedSets = false)

    for cond in outConds:
      let line = combineConds(cond, "masquerade")
      addLine(outp, 2, line)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFilterTable(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  let flowIfaces = collectFlowtableIfaces(cfg, opts)

  addLine(outp, 0, "table inet " & opts.inetTableName & " {")
  emitZoneIfaceSets(outp, cfg)
  emitForwardKnownIfaceSet(outp, cfg)
  ?emitFlowtablePairSet(outp, cfg, flowIfaces)
  ?emitInputChain(outp, cfg, opts)
  emitFlowtableObject(outp, flowIfaces, opts)
  ?emitFlowtableForwardChain(outp, cfg, flowIfaces, opts)
  ?emitForwardKnownIifChain(outp, cfg)
  ?emitForwardChain(outp, cfg, opts)
  ?emitOutputChain(outp, cfg, opts)
  ?emitPostroutingMangleChain(outp, cfg)
  addLine(outp, 0, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitNatTable(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  addLine(outp, 0, "table ip " & opts.natTableName & " {")
  addLine(outp, 1, "chain prerouting {")
  addLine(outp, 2, "type nat hook prerouting priority dstnat; policy accept;")
  ?emitDnatRules(outp, cfg)
  addLine(outp, 1, "}")
  addLine(outp, 0, "")

  addLine(outp, 1, "chain postrouting {")
  addLine(outp, 2, "type nat hook postrouting priority srcnat; policy accept;")
  ?emitSnatRules(outp, cfg)
  addLine(outp, 1, "}")
  addLine(outp, 0, "}")
  addLine(outp, 0, "")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitNft*(cfg: NormalizedConfig, opts: NftEmitOptions): AE[string] =
  var outp = ""

  if opts.includeFlushRuleset:
    addLine(outp, 0, "flush ruleset")
    addLine(outp, 0, "")

  ?emitFilterTable(outp, cfg, opts)
  ?emitNatTable(outp, cfg, opts)

  result = ok(outp)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitNft*(cfg: NormalizedConfig): AE[string] =
  result = emitNft(cfg, defaultNftEmitOptions())
