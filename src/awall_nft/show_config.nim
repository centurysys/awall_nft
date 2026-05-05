import std/[algorithm, options, strformat, strutils, tables]

import ./errors
import ./load_config
import ./normalize
import ./types

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
proc joinOrDash(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 0:
    result = "-"
    return

  result = sorted.join(", ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneNames(zones: seq[ZoneName]): seq[string] =
  for zone in zones:
    result.add($zone)

  result = sortedStrings(result)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatZones(zones: seq[ZoneName]): string =
  result = joinOrDash(zoneNames(zones))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatRawPolicySide(label: string, zones: seq[ZoneName]): string =
  if zones.len == 0:
    result = ""
    return

  result = label & "=" & formatZones(zones)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatForwardSide(zones: seq[ZoneName]): string =
  if zones.len == 0:
    result = "*"
    return

  result = formatZones(zones)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isFwOnly(zones: seq[ZoneName]): bool =
  if zones.len != 1:
    result = false
    return

  result = $zones[0] == "_fw"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hasForwardEffect(inZones: seq[ZoneName], outZones: seq[ZoneName]): bool =
  if inZones.len == 0 and outZones.len == 0:
    result = false
    return

  if isFwOnly(inZones):
    result = false
    return

  if isFwOnly(outZones):
    result = false
    return

  result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatPorts(ports: seq[uint16]): string =
  var parts: seq[string] = @[]

  for port in ports:
    parts.add($port)

  result = joinOrDash(parts)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatAction(action: Action): string =
  result = $action

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatNatAction(action: NatAction): string =
  result = $action

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatFamily(family: Family): string =
  if family == famAny:
    result = "any"
  else:
    result = $family

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatMatch(match: NormalizedServiceMatch): string =
  var parts: seq[string] = @[]

  parts.add("family=" & formatFamily(match.family))
  parts.add("proto=" & $match.proto)

  if match.ports.len > 0:
    parts.add("ports=" & formatPorts(match.ports))

  if match.icmpType.isSome:
    parts.add("icmp-type=" & $match.icmpType.get())

  if match.icmpReplyType.isSome:
    parts.add("icmp-reply-type=" & $match.icmpReplyType.get())

  if match.ctHelper.isSome:
    parts.add("ct-helper=" & match.ctHelper.get())

  result = parts.join(" ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatMatches(matches: seq[NormalizedServiceMatch]): string =
  var parts: seq[string] = @[]

  for match in matches:
    parts.add(formatMatch(match))

  result = joinOrDash(parts)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatServiceSpec(service: ServiceSpec): string =
  case service.kind
  of sskNone:
    result = "-"
  of sskName:
    result = service.name
  of sskInline:
    var parts: seq[string] = @[]

    for atom in service.atoms:
      var atomParts: seq[string] = @[]
      atomParts.add("family=" & formatFamily(atom.family))
      atomParts.add("proto=" & $atom.proto)

      if atom.port.items.len > 0:
        atomParts.add("ports=" & formatPorts(atom.port.items))

      if atom.`type` != 0:
        atomParts.add("icmp-type=" & $atom.`type`)

      if atom.replyType != 0:
        atomParts.add("icmp-reply-type=" & $atom.replyType)

      if atom.ctHelper.len > 0:
        atomParts.add("ct-helper=" & atom.ctHelper)

      parts.add(atomParts.join(" "))

    result = joinOrDash(parts)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sortedZoneNames(cfg: NormalizedConfig): seq[ZoneName] =
  var names: seq[string] = @[]

  for zoneName in cfg.zones.keys:
    names.add($zoneName)

  for name in sortedStrings(names):
    result.add(ZoneName(name))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addSection(outp: var string, title: string) =
  if outp.len > 0:
    outp.add("\n")

  outp.add(&"== {title} ==\n\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showZones(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "Zones")

  for zoneName in sortedZoneNames(cfg):
    let zone = cfg.zones[zoneName]
    var exactIfaces: seq[string] = @[]
    var prefixIfaces: seq[string] = @[]

    for iface in zone.exactIfaces:
      exactIfaces.add($iface)

    for prefix in zone.prefixIfaces:
      prefixIfaces.add(prefix & "+")

    outp.add(&"{zoneName}\n")
    outp.add(&"  exact : {joinOrDash(exactIfaces)}\n")
    outp.add(&"  prefix: {joinOrDash(prefixIfaces)}\n\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showPolicies(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "Policies")

  if cfg.policies.len == 0:
    outp.add("  -\n")
    return

  for index, policy in cfg.policies:
    var parts: seq[string] = @[]

    let inPart = formatRawPolicySide("in", policy.inZones)
    let outPart = formatRawPolicySide("out", policy.outZones)

    if inPart.len > 0:
      parts.add(inPart)

    if outPart.len > 0:
      parts.add(outPart)

    parts.add("action=" & formatAction(policy.action))

    let line = parts.join(" ")
    outp.add(&"[{index}] {line}\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showForwardRuleOrder(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "Forward Rule Order")

  var count = 0

  for index, policy in cfg.policies:
    if not hasForwardEffect(policy.inZones, policy.outZones):
      continue

    outp.add(&"policy[{index}] {formatForwardSide(policy.inZones)} -> {formatForwardSide(policy.outZones)}  {formatAction(policy.action)}\n")
    count.inc()

  if count == 0:
    outp.add("  -\n")


# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showFilters(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "Filters")

  if cfg.filters.len == 0:
    outp.add("  -\n")
    return

  for index, filter in cfg.filters:
    outp.add(&"[{index}] {formatZones(filter.inZones)} -> {formatZones(filter.outZones)}  {formatAction(filter.action)}\n")
    outp.add(&"    match     : {formatMatches(filter.matches)}\n")

    if filter.connLimit.isSome:
      let limit = filter.connLimit.get()
      outp.add(&"    conn-limit: count={limit.count} interval={limit.interval}s\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showDnat(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "DNAT")

  if cfg.dnats.len == 0:
    outp.add("  -\n")
    return

  for index, dnat in cfg.dnats:
    outp.add(&"[{index}] in={formatZones(dnat.inZones)} to={dnat.toAddr}")

    if dnat.toPort.isSome:
      outp.add(&":{dnat.toPort.get()}")

    outp.add("\n")
    outp.add(&"    match: {formatMatches(dnat.matches)}\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showSnat(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "SNAT / Masquerade")

  if cfg.snats.len == 0:
    outp.add("  -\n")
    return

  for index, snat in cfg.snats:
    outp.add(&"[{index}] out={formatZones(snat.outZones)} action={formatNatAction(snat.action)}")

    if snat.toAddr.isSome:
      outp.add(&" to={snat.toAddr.get()}")

    if snat.toPort.isSome:
      outp.add(&":{snat.toPort.get()}")

    if snat.service.kind != sskNone:
      outp.add(&" service={formatServiceSpec(snat.service)}")

    outp.add("\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showClampMss(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "TCP MSS Clamp")

  if cfg.clampMssRules.len == 0:
    outp.add("  -\n")
    return

  for index, rule in cfg.clampMssRules:
    outp.add(&"[{index}] out={formatZones(rule.outZones)}\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showFlowtable(outp: var string, cfg: NormalizedConfig) =
  addSection(outp, "Flowtable")

  if cfg.flowtableRules.len == 0:
    outp.add("  -\n")
    return

  for index, rule in cfg.flowtableRules:
    outp.add(&"[{index}] {formatZones(rule.inZones)} -> {formatZones(rule.outZones)}\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showConfigText*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    topic: string
): AE[string] =
  let loaded = ?loadConfig(
    mainPath,
    privateDir,
    servicesPath
  ).trace("showConfigText.loadConfig")

  let normalized = ?normalizeConfig(
    loaded.config,
    loaded.services
  ).trace("showConfigText.normalizeConfig")

  let normalizedTopic = topic.toLowerAscii()
  var outp = ""

  case normalizedTopic
  of "all":
    showZones(outp, normalized)
    showPolicies(outp, normalized)
    showForwardRuleOrder(outp, normalized)
    showFilters(outp, normalized)
    showDnat(outp, normalized)
    showSnat(outp, normalized)
    showClampMss(outp, normalized)
    showFlowtable(outp, normalized)

  of "zones":
    showZones(outp, normalized)

  of "policies":
    showPolicies(outp, normalized)

  of "forward":
    showForwardRuleOrder(outp, normalized)

  of "filters":
    showFilters(outp, normalized)

  of "dnat":
    showDnat(outp, normalized)

  of "snat":
    showSnat(outp, normalized)

  of "clamp-mss":
    showClampMss(outp, normalized)

  of "flowtable":
    showFlowtable(outp, normalized)

  else:
    return fail[string](
      ekInvalid,
      "unknown show topic: " & topic
    )

  result = ok(outp)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showConfigCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    topic: string
): AE[void] =
  let text = ?showConfigText(
    mainPath,
    privateDir,
    servicesPath,
    topic
  ).trace("showConfigCommand.showConfigText")

  stdout.write(text)
  result = okVoid()
