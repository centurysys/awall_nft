import std/[options, strutils, tables]

import ./errors
import ./services
import ./types

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toNormalizedMatch(atom: ServiceAtom): NormalizedServiceMatch =
  result = NormalizedServiceMatch(
    family: atom.family,
    proto: atom.proto,
    ports: atom.port.items,
    icmpType: none(int),
    icmpReplyType: none(int),
    ctHelper: none(string),
  )

  if atom.`type` != 0:
    result.icmpType = some(atom.`type`)

  if atom.replyType != 0:
    result.icmpReplyType = some(atom.replyType)

  if atom.ctHelper.len > 0:
    result.ctHelper = some(atom.ctHelper)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveServiceSpec(
    services: ServiceDb,
    service: ServiceSpec,
    where: string
): AE[seq[NormalizedServiceMatch]] =
  var atoms: seq[ServiceAtom] = @[]

  case service.kind
  of sskNone:
    return fail[seq[NormalizedServiceMatch]](
      ekInvalidRule,
      where & ": service is required"
    )

  of sskName:
    let serviceName = ServiceName(service.name)
    let lookupRes = lookupService(services, serviceName)

    if lookupRes.isErr:
      return fail[seq[NormalizedServiceMatch]](
        lookupRes.error.kind,
        where & ": " & lookupRes.error.msg
      )

    atoms = lookupRes.get()

  of sskInline:
    atoms = service.atoms

  var matches: seq[NormalizedServiceMatch] = @[]

  for atom in atoms:
    matches.add(toNormalizedMatch(atom))

  result = ok(matches)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeZones(cfg: AwallSubsetConfig): Table[ZoneName, ZoneRuntime] =
  result = initTable[ZoneName, ZoneRuntime]()

  for zoneName, zoneConfig in cfg.zones:
    var runtime = ZoneRuntime(
      name: zoneName,
      exactIfaces: @[],
      prefixIfaces: @[],
    )

    for iface in zoneConfig.ifaces:
      let name = string(iface)

      if name.endsWith("+"):
        if name.len > 1:
          runtime.prefixIfaces.add(name[0 ..< name.high])
      else:
        runtime.exactIfaces.add(iface)

    result[zoneName] = runtime

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeFilters(
    cfg: AwallSubsetConfig,
    services: ServiceDb
): AE[seq[NormalizedFilterRule]] =
  var normalized: seq[NormalizedFilterRule] = @[]
  var index = 0

  for filter in cfg.filters:
    let where = "filter[" & $index & "]"
    let matches = ?resolveServiceSpec(
      services,
      filter.service,
      where & ".service"
    )

    let rule = NormalizedFilterRule(
      inZones: filter.inZones,
      outZones: filter.outZones,
      matches: matches,
      action: filter.action,
      connLimit: filter.connLimit,
    )

    normalized.add(rule)
    inc(index)

  result = ok(normalized)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeDnats(
    cfg: AwallSubsetConfig,
    services: ServiceDb
): AE[seq[NormalizedDnatRule]] =
  var normalized: seq[NormalizedDnatRule] = @[]
  var index = 0

  for dnat in cfg.dnats:
    let where = "dnat[" & $index & "]"
    let matches = ?resolveServiceSpec(
      services,
      dnat.service,
      where & ".service"
    )

    let rule = NormalizedDnatRule(
      inZones: dnat.inZones,
      srcAddrs: dnat.srcAddrs,
      matches: matches,
      toAddr: dnat.toAddr,
      toPort: dnat.toPort,
    )

    normalized.add(rule)
    inc(index)

  result = ok(normalized)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeFlowtableRules(
    rules: seq[FlowtableRule]
): AE[seq[NormalizedFlowtableRule]] =
  var normalized: seq[NormalizedFlowtableRule] = @[]

  for rule in rules:
    normalized.add(NormalizedFlowtableRule(
      inZones: rule.inZones,
      outZones: rule.outZones,
    ))

  result = ok(normalized)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeConfig*(
    cfg: AwallSubsetConfig,
    services: ServiceDb
): AE[NormalizedConfig] =
  let filters = ?normalizeFilters(cfg, services).trace("normalizeConfig.filters")
  let dnats = ?normalizeDnats(cfg, services).trace("normalizeConfig.dnats")
  let flowtableRules = ?normalizeFlowtableRules(
    cfg.flowtableRules
  ).trace("normalizeConfig.flowtableRules")

  result = ok(NormalizedConfig(
    zones: normalizeZones(cfg),
    policies: cfg.policies,
    filters: filters,
    dnats: dnats,
    snats: cfg.snats,
    clampMssRules: cfg.clampMssRules,
    flowtableRules: flowtableRules,
  ))
