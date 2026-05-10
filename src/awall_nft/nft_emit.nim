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
    direction: string
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
      conditions.add(direction & " " & joinQuotedSet(exacts))

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
proc emitFlowtableForwardRule(
    outp: var string,
    seen: var Table[string, bool],
    inIface: string,
    outIfaces: seq[string],
    opts: NftEmitOptions
) =
  if inIface.len == 0 or outIfaces.len == 0:
    return

  var effectiveOutIfaces: seq[string] = @[]

  for outIface in outIfaces:
    if outIface == inIface:
      continue

    effectiveOutIfaces.addUniqueString(outIface)

  if effectiveOutIfaces.len == 0:
    return

  let inExpr = q(inIface)
  let outExpr = joinQuotedSet(effectiveOutIfaces)
  let line = &"iifname {inExpr} oifname {outExpr} ct state established meta l4proto {{ tcp, udp }} counter flow add @{opts.flowtableName}"

  if seen.hasKey(line):
    return

  seen[line] = true
  addLine(outp, 2, line)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitFlowtableForwardRules(
    outp: var string,
    cfg: NormalizedConfig,
    flowIfaces: seq[string],
    opts: NftEmitOptions
): AE[void] =
  ## Emit flow add rules only from the explicit awall_nft flowtable section.
  ##
  ## The flowtable section is an optimization hint, not a permission rule.
  ## Normal policy/filter/DNAT rules must still allow the traffic. This emitter
  ## only uses it to decide which already-allowed zone directions may enter the
  ## nftables flowtable fast path.
  var seen = initTable[string, bool]()

  for rule in cfg.flowtableRules:
    let inIfaces = ?zoneFlowtableIfaces(cfg, rule.inZones, flowIfaces)
    let outIfaces = ?zoneFlowtableIfaces(cfg, rule.outZones, flowIfaces)

    for inIface in inIfaces:
      emitFlowtableForwardRule(outp, seen, inIface, outIfaces, opts)

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
    addLine(outp, 2, "iifname " & joinQuotedSet(matches.exacts) & " return")

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
  let targetAddr = string(rule.toAddr)

  if match.family == famInet6 or targetAddr.contains(":"):
    result = &"ip6 daddr {targetAddr}"
    return

  result = &"ip daddr {targetAddr}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatForwardServiceText(
    rule: NormalizedDnatRule,
    match: NormalizedServiceMatch
): AE[string] =
  case match.proto
  of protoTcp, protoUdp:
    var ports: seq[uint16] = @[]

    if rule.toPort.isSome:
      ports.add(rule.toPort.get())
    else:
      ports = match.ports

    if ports.len == 0:
      return fail[string](
        ekInvalidRule,
        $match.proto & " DNAT forward accept requires at least one port"
      )

    result = ok(&"{protoText(match.proto)} dport {joinPortSet(ports)}")

  of protoIcmp, protoIcmpv6, protoEsp, protoGre, protoOspf, protoIgmp:
    result = serviceMatchText(match)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitDnatForwardAcceptRules(outp: var string, cfg: NormalizedConfig): AE[void] =
  ## Allow explicitly DNATed forwarded packets before broad policy rules.
  ##
  ## DNAT is performed in prerouting, before the forward chain.  These rules
  ## match the translated destination address and port, and also require
  ## `ct status dnat` so packets that directly target the internal address are
  ## not accepted merely because they look like a DNAT destination.
  var seen = initTable[string, bool]()

  for rule in cfg.dnats:
    let inConds = ?zoneMatchConditions(cfg, rule.inZones, "iifname")

    for baseCond in inConds:
      for match in rule.matches:
        let daddr = dnatForwardDaddrText(rule, match)
        let svc = ?dnatForwardServiceText(rule, match)
        let condition = combineConds(
          combineConds(combineConds(baseCond, "ct status dnat"), daddr),
          svc
        )
        let line = combineConds(condition, "accept")

        if seen.hasKey(line):
          continue

        seen[line] = true
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
    let inConds = ?zoneMatchConditions(cfg, rule.inZones, "iifname")

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
    let outConds = ?zoneMatchConditions(cfg, rule.outZones, "oifname")

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
