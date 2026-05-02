import std/options

import ./errors
import ./types

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isSpecialZone(zone: ZoneName): bool =
  result = zone == ZoneFirewall

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneExists(cfg: AwallSubsetConfig, zone: ZoneName): bool =
  if isSpecialZone(zone):
    result = true
    return

  result = cfg.zones.hasKey(zone)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateZoneRef(
    cfg: AwallSubsetConfig,
    zone: ZoneName,
    where: string
): AE[void] =
  if zoneExists(cfg, zone):
    result = okVoid()
    return

  result = failVoid(
    ekUnknownZone,
    "unknown zone '" & $zone & "' in " & where
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateZoneRefs(
    cfg: AwallSubsetConfig,
    zones: seq[ZoneName],
    where: string
): AE[void] =
  for zone in zones:
    ?validateZoneRef(cfg, zone, where)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateDefinedZones(cfg: AwallSubsetConfig): AE[void] =
  for zoneName, zoneConfig in cfg.zones:
    if string(zoneName).len == 0:
      return failVoid(ekInvalidRule, "zone name must not be empty")

    if zoneName == ZoneFirewall:
      return failVoid(ekInvalidRule, "_fw must not be defined as a normal zone")

    if zoneConfig.ifaces.len == 0:
      return failVoid(
        ekInvalidInterface,
        "zone '" & $zoneName & "' has no interfaces"
      )

    for iface in zoneConfig.ifaces:
      if string(iface).len == 0:
        return failVoid(
          ekInvalidInterface,
          "zone '" & $zoneName & "' contains an empty interface name"
        )

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateServiceAtom(atom: ServiceAtom, where: string): AE[void] =
  case atom.proto
  of protoTcp, protoUdp:
    if atom.port.items.len == 0:
      return failVoid(
        ekInvalidRule,
        where & ": " & $atom.proto & " service requires at least one port"
      )

  of protoIcmp, protoIcmpv6, protoEsp, protoGre, protoOspf, protoIgmp:
    if atom.port.items.len > 0:
      return failVoid(
        ekInvalidRule,
        where & ": protocol " & $atom.proto & " must not have ports"
      )

  for port in atom.port.items:
    if port == 0:
      return failVoid(
        ekInvalidPort,
        where & ": port must be greater than 0"
      )

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateServiceSpec(service: ServiceSpec, where: string): AE[void] =
  case service.kind
  of sskNone:
    return failVoid(ekInvalidRule, where & ": service is required")

  of sskName:
    if service.name.len == 0:
      return failVoid(ekUnknownService, where & ": service name is empty")

  of sskInline:
    if service.atoms.len == 0:
      return failVoid(ekInvalidRule, where & ": inline service is empty")

    for atom in service.atoms:
      ?validateServiceAtom(atom, where)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validatePolicies(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for policy in cfg.policies:
    let where = "policy[" & $index & "]"

    ?validateZoneRefs(cfg, policy.inZones, where & ".in")
    ?validateZoneRefs(cfg, policy.outZones, where & ".out")

    if policy.inZones.len == 0 and policy.outZones.len == 0:
      return failVoid(
        ekInvalidRule,
        where & ": either in or out must be specified"
      )

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateFilters(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for filter in cfg.filters:
    let where = "filter[" & $index & "]"

    ?validateZoneRefs(cfg, filter.inZones, where & ".in")
    ?validateZoneRefs(cfg, filter.outZones, where & ".out")
    ?validateServiceSpec(filter.service, where & ".service")

    if filter.inZones.len == 0 and filter.outZones.len == 0:
      return failVoid(
        ekInvalidRule,
        where & ": either in or out must be specified"
      )

    if filter.connLimit.isSome:
      let limit = filter.connLimit.get()

      if limit.count == 0:
        return failVoid(
          ekInvalidRule,
          where & ".conn-limit.count must be greater than 0"
        )

      if limit.interval == 0:
        return failVoid(
          ekInvalidRule,
          where & ".conn-limit.interval must be greater than 0"
        )

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateDnats(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for dnat in cfg.dnats:
    let where = "dnat[" & $index & "]"

    ?validateZoneRefs(cfg, dnat.inZones, where & ".in")
    ?validateServiceSpec(dnat.service, where & ".service")

    if dnat.inZones.len == 0:
      return failVoid(ekInvalidRule, where & ": in zone is required")

    if string(dnat.toAddr).len == 0:
      return failVoid(ekInvalidRule, where & ": to-addr is required")

    if dnat.toPort.isSome and dnat.toPort.get() == 0:
      return failVoid(ekInvalidPort, where & ": to-port must be greater than 0")

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateSnats(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for snat in cfg.snats:
    let where = "snat[" & $index & "]"

    ?validateZoneRefs(cfg, snat.outZones, where & ".out")

    if snat.outZones.len == 0:
      return failVoid(ekInvalidRule, where & ": out zone is required")

    if snat.action == natExclude:
      return failVoid(
        ekUnsupported,
        where & ": action exclude is not supported by the initial nft backend"
      )

    if snat.toAddr.isSome:
      return failVoid(
        ekUnsupported,
        where & ": to-addr SNAT is not supported by the initial nft backend"
      )

    if snat.toPort.isSome:
      return failVoid(
        ekUnsupported,
        where & ": to-port SNAT is not supported by the initial nft backend"
      )

    if snat.service.kind != sskNone:
      return failVoid(
        ekUnsupported,
        where & ": service-scoped SNAT is not supported by the initial nft backend"
      )

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateClampMssRules(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for clampMss in cfg.clampMssRules:
    let where = "clamp-mss[" & $index & "]"

    ?validateZoneRefs(cfg, clampMss.outZones, where & ".out")

    if clampMss.outZones.len == 0:
      return failVoid(ekInvalidRule, where & ": out zone is required")

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateFlowtableRules(cfg: AwallSubsetConfig): AE[void] =
  var index = 0

  for flowtable in cfg.flowtableRules:
    let where = "flowtable[" & $index & "]"

    if flowtable.inZones.len == 0:
      return failVoid(ekInvalidRule, where & ": in zone is required")

    if flowtable.outZones.len == 0:
      return failVoid(ekInvalidRule, where & ": out zone is required")

    for zone in flowtable.inZones:
      if zone == ZoneFirewall:
        return failVoid(
          ekUnsupported,
          where & ": _fw is not supported in in zone"
        )

    for zone in flowtable.outZones:
      if zone == ZoneFirewall:
        return failVoid(
          ekUnsupported,
          where & ": _fw is not supported in out zone"
        )

    ?validateZoneRefs(cfg, flowtable.inZones, where & ".in")
    ?validateZoneRefs(cfg, flowtable.outZones, where & ".out")

    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateConfig*(cfg: AwallSubsetConfig): AE[void] =
  ?validateDefinedZones(cfg).trace("validateConfig.validateDefinedZones")
  ?validatePolicies(cfg).trace("validateConfig.validatePolicies")
  ?validateFilters(cfg).trace("validateConfig.validateFilters")
  ?validateDnats(cfg).trace("validateConfig.validateDnats")
  ?validateSnats(cfg).trace("validateConfig.validateSnats")
  ?validateClampMssRules(cfg).trace("validateConfig.validateClampMssRules")
  ?validateFlowtableRules(cfg).trace("validateConfig.validateFlowtableRules")

  result = okVoid()
