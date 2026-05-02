import std/[algorithm, os, strformat, strutils, tables]

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
proc formatList(values: seq[string]): string =
  let sorted = sortedStrings(values)

  if sorted.len == 0:
    result = ""
    return

  result = sorted.join(", ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatZones(zones: seq[ZoneName]): string =
  var parts: seq[string] = @[]

  for zone in zones:
    parts.add(string(zone))

  result = formatList(parts)

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
proc flowtableSyncCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string
): AE[void] =
  ## Prepare the flowtable-sync command path without changing nftables state.
  ##
  ## This command intentionally has no nft side effects yet.  It verifies that
  ## configured flowtable zone directions can be resolved to currently existing
  ## network interfaces.
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

  echo &"flowtable-sync: loaded {normalized.flowtableRules.len} flowtable rule(s)"
  echo &"flowtable-sync: existing interfaces={{ {formatList(existingIfaces)} }}"

  for index, rule in normalized.flowtableRules:
    let inIfaces = ?resolveRuleIfaces(
      normalized,
      rule.inZones,
      existingIfaces
    ).trace("flowtableSyncCommand.resolveInIfaces")

    let outIfaces = ?resolveRuleIfaces(
      normalized,
      rule.outZones,
      existingIfaces
    ).trace("flowtableSyncCommand.resolveOutIfaces")

    echo &"flowtable-sync: rule[{index}]: zones: in={{ {formatZones(rule.inZones)} }} out={{ {formatZones(rule.outZones)} }}"
    echo &"flowtable-sync: rule[{index}]: ifaces: iif={{ {formatList(inIfaces)} }} oif={{ {formatList(outIfaces)} }}"

  echo "flowtable-sync: nft update is not implemented yet"

  result = okVoid()
