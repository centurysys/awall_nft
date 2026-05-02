import std/[algorithm, os, strformat, strutils, tables]

import ./errors
import ./load_config
import ./nft_cmd
import ./normalize
import ./types

const
  NftFamily = "inet"
  NftTable = "awall_nft"
  FlowtableChain = "flowtable_forward"
  FlowtableName = "ft_forward"
  FlowtableHookPriority = "filter"

type
  FlowtableRulePlan = object
    index: int
    inZones: seq[ZoneName]
    outZones: seq[ZoneName]
    inIfaces: seq[string]
    outIfaces: seq[string]

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
proc formatList(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 0:
    result = ""
    return

  result = sorted.join(", ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc quoteNftString(value: string): string =
  result = "\"" & value.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatNftIfaceExpr(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 0:
    result = ""
    return

  if sorted.len == 1:
    result = quoteNftString(sorted[0])
    return

  var quoted: seq[string] = @[]

  for value in sorted:
    quoted.add(quoteNftString(value))

  result = "{ " & quoted.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatFlowtableDevicesExpr(values: seq[string]): string =
  let sorted = sortedStrings(values)

  result = "{ " & sorted.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectExistingNetIfaces(): seq[string] =
  let sysNetPath = "/sys/class/net"

  if not dirExists(sysNetPath):
    return @[]

  for kind, path in walkDir(sysNetPath):
    case kind
    of pcDir, pcLinkToDir:
      result.add(extractFilename(path))
    else:
      discard

  result = sortedStrings(result)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc containsName(values: seq[string], name: string): bool =
  for value in values:
    if value == name:
      result = true
      return

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addUnique(values: var seq[string], name: string) =
  if values.containsName(name):
    return

  values.add(name)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addUniqueAll(values: var seq[string], names: seq[string]) =
  for name in names:
    values.addUnique(name)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveZoneIfaces(
    cfg: NormalizedConfig,
    zoneName: ZoneName,
    existingIfaces: seq[string]
): AE[seq[string]] =
  if not cfg.zones.hasKey(zoneName):
    return fail[seq[string]](
      ekUnknownZone,
      "unknown zone in flowtable-sync: " & string(zoneName)
    )

  let zone = cfg.zones[zoneName]
  var ifaces: seq[string] = @[]

  for iface in zone.exactIfaces:
    let name = string(iface)

    if existingIfaces.containsName(name):
      ifaces.addUnique(name)

  for prefix in zone.prefixIfaces:
    for iface in existingIfaces:
      if iface.startsWith(prefix):
        ifaces.addUnique(iface)

  result = ok(sortedStrings(ifaces))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveRuleIfaces(
    cfg: NormalizedConfig,
    zones: seq[ZoneName],
    existingIfaces: seq[string]
): AE[seq[string]] =
  var ifaces: seq[string] = @[]

  for zone in zones:
    let zoneIfaces = ?resolveZoneIfaces(
      cfg,
      zone,
      existingIfaces
    ).trace("resolveRuleIfaces.resolveZoneIfaces")

    for iface in zoneIfaces:
      ifaces.addUnique(iface)

  result = ok(sortedStrings(ifaces))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildFlowAddRuleArgs(inIfaces: seq[string], outIfaces: seq[string]): seq[string] =
  result = @[
    "add",
    "rule",
    NftFamily,
    NftTable,
    FlowtableChain,
    "iifname",
    formatNftIfaceExpr(inIfaces),
    "oifname",
    formatNftIfaceExpr(outIfaces),
    "meta",
    "l4proto",
    "{ tcp, udp }",
    "flow",
    "add",
    "@" & FlowtableName
  ]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildAddFlowtableArgs(devices: seq[string]): seq[string] =
  result = @[
    "add",
    "flowtable",
    NftFamily,
    NftTable,
    FlowtableName,
    &"{{ hook ingress priority {FlowtableHookPriority}; devices = {formatFlowtableDevicesExpr(devices)}; }}"
  ]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc flowtableObjectExists(): AE[bool] =
  let res = runNftCommand([
    "list",
    "flowtable",
    NftFamily,
    NftTable,
    FlowtableName
  ])

  if res.isOk:
    result = ok(true)
    return

  let msg = res.error.msg

  if msg.contains("No such file") or msg.contains("No such file or directory"):
    result = ok(false)
    return

  result = err(res.error)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc flushFlowtableForwardChain(): AE[void] =
  discard ?runNftCommand([
    "flush",
    "chain",
    NftFamily,
    NftTable,
    FlowtableChain
  ]).trace("flushFlowtableForwardChain.runNftCommand")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc deleteFlowtableObject(): AE[void] =
  let exists = ?flowtableObjectExists().trace("deleteFlowtableObject.flowtableObjectExists")

  if not exists:
    result = okVoid()
    return

  discard ?runNftCommand([
    "delete",
    "flowtable",
    NftFamily,
    NftTable,
    FlowtableName
  ]).trace("deleteFlowtableObject.runNftCommand")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addFlowtableObject(devices: seq[string]): AE[void] =
  if devices.len == 0:
    result = okVoid()
    return

  discard ?runNftCommand(
    buildAddFlowtableArgs(devices)
  ).trace("addFlowtableObject.runNftCommand")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addFlowtableRule(inIfaces: seq[string], outIfaces: seq[string]): AE[void] =
  discard ?runNftCommand(
    buildFlowAddRuleArgs(
      inIfaces,
      outIfaces
    )
  ).trace("addFlowtableRule.runNftCommand")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildRulePlans(
    cfg: NormalizedConfig,
    existingIfaces: seq[string]
): AE[(seq[FlowtableRulePlan], int)] =
  var plans: seq[FlowtableRulePlan] = @[]
  var skippedRules = 0

  for index, rule in cfg.flowtableRules:
    let inIfaces = ?resolveRuleIfaces(
      cfg,
      rule.inZones,
      existingIfaces
    ).trace("buildRulePlans.resolveInIfaces")

    let outIfaces = ?resolveRuleIfaces(
      cfg,
      rule.outZones,
      existingIfaces
    ).trace("buildRulePlans.resolveOutIfaces")

    if inIfaces.len == 0 or outIfaces.len == 0:
      skippedRules.inc()
      continue

    plans.add(FlowtableRulePlan(
      index: index,
      inZones: rule.inZones,
      outZones: rule.outZones,
      inIfaces: inIfaces,
      outIfaces: outIfaces
    ))

  result = ok((plans, skippedRules))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectDesiredDevices(plans: seq[FlowtableRulePlan]): seq[string] =
  var devices: seq[string] = @[]

  for plan in plans:
    devices.addUniqueAll(plan.inIfaces)
    devices.addUniqueAll(plan.outIfaces)

  result = sortedStrings(devices)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc flowtableSyncCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string
): AE[void] =
  ## Synchronize the flowtable_forward chain and ft_forward object.
  ##
  ## The command resolves configured flowtable rules to currently existing
  ## interfaces, recreates the ft_forward flowtable object with the desired
  ## device set, and rebuilds the flow add rules.
  let loaded = ?loadConfig(
    mainPath,
    privateDir,
    servicesPath
  ).trace("flowtableSyncCommand.loadConfig")

  let normalized = ?normalizeConfig(
    loaded.config,
    loaded.services
  ).trace("flowtableSyncCommand.normalizeConfig")

  let existingIfaces = collectExistingNetIfaces()
  let (plans, skippedRules) = ?buildRulePlans(
    normalized,
    existingIfaces
  ).trace("flowtableSyncCommand.buildRulePlans")

  let desiredDevices = collectDesiredDevices(plans)

  ?flushFlowtableForwardChain().trace("flowtableSyncCommand.flushFlowtableForwardChain")
  ?deleteFlowtableObject().trace("flowtableSyncCommand.deleteFlowtableObject")
  ?addFlowtableObject(desiredDevices).trace("flowtableSyncCommand.addFlowtableObject")

  var addedRules = 0

  for plan in plans:
    ?addFlowtableRule(
      plan.inIfaces,
      plan.outIfaces
    ).trace("flowtableSyncCommand.addFlowtableRule")

    addedRules.inc()

  if desiredDevices.len == 0:
    echo &"flowtable-sync: synced {addedRules} rule(s), skipped {skippedRules} rule(s), no devices"
  else:
    echo &"flowtable-sync: synced {addedRules} rule(s), skipped {skippedRules} rule(s), devices: {formatList(desiredDevices)}"

  result = okVoid()
