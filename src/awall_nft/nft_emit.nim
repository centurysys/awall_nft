import std/[algorithm, options, strutils, tables]

import ./errors
import ./types

type
  NftEmitOptions* = object
    inetTableName*: string
    natTableName*: string
    includeFlushRuleset*: bool
    allowRoutingIcmp*: bool

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc defaultNftEmitOptions*(): NftEmitOptions =
  result = NftEmitOptions(
    inetTableName: "awall_nft",
    natTableName: "awall_nft_nat",
    includeFlushRuleset: true,
    allowRoutingIcmp: true,
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

  if conditions.len == 0:
    conditions.add("")

  result = ok(conditions)

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
proc emitForwardChain(outp: var string, cfg: NormalizedConfig, opts: NftEmitOptions): AE[void] =
  addLine(outp, 1, "chain forward {")
  addLine(outp, 2, "type filter hook forward priority filter; policy drop;")
  addLine(outp, 2, "ct state established,related accept")
  emitRoutingIcmpRules(outp, "forward", opts)

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
  addLine(outp, 0, "table inet " & opts.inetTableName & " {")
  ?emitInputChain(outp, cfg, opts)
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
