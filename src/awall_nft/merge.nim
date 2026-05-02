import std/[options, sets, tables]
import ./errors
import ./types

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toZoneNames(zones: ZoneList): seq[ZoneName] =
  result = @[]

  for zone in zones.items:
    result.add(ZoneName(zone))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toInterfaces(ifaces: InterfaceList): seq[InterfaceName] =
  result = @[]

  for iface in ifaces.items:
    result.add(InterfaceName(iface))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addDescription(dst: var AwallSubsetConfig, description: string) =
  if description.len == 0:
    return

  dst.descriptions.add(description)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeZones(dst: var AwallSubsetConfig, zones: Table[string, ZoneDto]): AE[void] =
  for zoneName, zoneDto in zones:
    let z = ZoneName(zoneName)

    if not dst.zones.hasKey(z):
      dst.zones[z] = ZoneConfig(ifaces: initHashSet[InterfaceName]())

    for iface in toInterfaces(zoneDto.iface):
      dst.zones[z].ifaces.incl(iface)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergePolicies(dst: var AwallSubsetConfig, policies: seq[PolicyDto]): AE[void] =
  for policy in policies:
    let rule = PolicyRule(
      inZones: toZoneNames(policy.inZones),
      outZones: toZoneNames(policy.outZones),
      action: policy.action,
    )

    dst.policies.add(rule)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeFilters(dst: var AwallSubsetConfig, filters: seq[FilterDto]): AE[void] =
  for filter in filters:
    let rule = FilterRule(
      inZones: toZoneNames(filter.inZones),
      outZones: toZoneNames(filter.outZones),
      service: filter.service,
      action: filter.action,
      connLimit: filter.connLimit,
    )

    dst.filters.add(rule)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeDnats(dst: var AwallSubsetConfig, dnats: seq[DnatDto]): AE[void] =
  for dnat in dnats:
    if dnat.toAddr.len == 0:
      return failVoid(ekInvalidRule, "dnat rule requires to-addr")

    let rule = DnatRule(
      inZones: toZoneNames(dnat.inZones),
      service: dnat.service,
      toAddr: IpAddress(dnat.toAddr),
      toPort: dnat.toPort,
    )

    dst.dnats.add(rule)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeSnats(dst: var AwallSubsetConfig, snats: seq[SnatDto]): AE[void] =
  for snat in snats:
    var toAddr = none(IpAddress)

    if snat.toAddr.len > 0:
      toAddr = some(IpAddress(snat.toAddr))

    let rule = SnatRule(
      outZones: toZoneNames(snat.outZones),
      toAddr: toAddr,
      toPort: snat.toPort,
      action: snat.action,
      service: snat.service,
    )

    dst.snats.add(rule)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeClampMssRules(
    dst: var AwallSubsetConfig,
    rules: seq[ClampMssDto]
): AE[void] =
  for clampMss in rules:
    let rule = ClampMssRule(
      outZones: toZoneNames(clampMss.outZones),
    )

    dst.clampMssRules.add(rule)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeInto*(dst: var AwallSubsetConfig, src: ConfigDto): AE[void] =
  addDescription(dst, src.description)

  ?mergeZones(dst, src.zone).trace("mergeInto.mergeZones")
  ?mergePolicies(dst, src.policy).trace("mergeInto.mergePolicies")
  ?mergeFilters(dst, src.filter).trace("mergeInto.mergeFilters")
  ?mergeDnats(dst, src.dnat).trace("mergeInto.mergeDnats")
  ?mergeSnats(dst, src.snat).trace("mergeInto.mergeSnats")
  ?mergeClampMssRules(dst, src.clampMss).trace("mergeInto.mergeClampMssRules")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc mergeConfigs*(configs: openArray[ConfigDto]): AE[AwallSubsetConfig] =
  var merged = initAwallSubsetConfig()

  for config in configs:
    ?mergeInto(merged, config).trace("mergeConfigs.mergeInto")

  result = ok(merged)
