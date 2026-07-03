import std/[algorithm, strformat, strutils, tables]

import ./errors
import ./types

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc splitLxcDnatInZones*(value: string, where: string): AE[seq[string]] =
  let text = value.strip()

  if text.len == 0:
    return fail[seq[string]](ekInvalidRule, &"{where}: in must not be empty")

  var items: seq[string] = @[]
  for rawItem in text.split(','):
    let item = rawItem.strip()

    if item.len == 0:
      return fail[seq[string]](ekInvalidRule, &"{where}: in contains an empty zone")

    items.add(item)

  result = ok(items)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc normalizeRawLxcDnatInZone*(value: string, where: string): AE[string] =
  let zones = ?splitLxcDnatInZones(value, where)
  result = ok(zones.join(","))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sortedZoneNames(values: seq[ZoneName]): seq[ZoneName] =
  result = values
  result.sort(proc(a, b: ZoneName): int = cmp(string(a), string(b)))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveLxcDnatZoneName*(
    cfg: NormalizedConfig,
    rawZone: string,
    where: string
): AE[ZoneName] =
  let raw = rawZone.strip()

  if raw.len == 0:
    return fail[ZoneName](ekUnknownZone, &"{where}: zone must not be empty")

  let exact = ZoneName(raw)
  if exact == ZoneFirewall or cfg.zones.hasKey(exact):
    return ok(exact)

  let folded = raw.toLowerAscii()
  var matches: seq[ZoneName] = @[]

  if string(ZoneFirewall).toLowerAscii() == folded:
    matches.add(ZoneFirewall)

  for zone in cfg.zones.keys:
    if string(zone).toLowerAscii() == folded:
      matches.add(zone)

  if matches.len == 0:
    return fail[ZoneName](ekUnknownZone, &"{where}: unknown zone in lxc-dnat-sync: {raw}")

  if matches.len > 1:
    var names: seq[string] = @[]
    for zone in sortedZoneNames(matches):
      names.add(string(zone))

    return fail[ZoneName](
      ekUnknownZone,
      &"{where}: ambiguous zone name in lxc-dnat-sync: {raw} matches {names.join(\", \")}"
    )

  result = ok(matches[0])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveLxcDnatZones*(
    cfg: NormalizedConfig,
    inZone: string,
    where: string
): AE[seq[ZoneName]] =
  let rawZones = ?splitLxcDnatInZones(inZone, where)
  var seen = initTable[ZoneName, bool]()
  var zones: seq[ZoneName] = @[]

  for rawZone in rawZones:
    let zone = ?resolveLxcDnatZoneName(cfg, rawZone, where)
    if not seen.hasKey(zone):
      seen[zone] = true
      zones.add(zone)

  result = ok(sortedZoneNames(zones))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc canonicalLxcDnatInZone*(
    cfg: NormalizedConfig,
    inZone: string,
    where: string
): AE[string] =
  let zones = ?resolveLxcDnatZones(cfg, inZone, where)
  var names: seq[string] = @[]

  for zone in zones:
    names.add(string(zone))

  result = ok(names.join(","))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc lxcDnatZonesOverlap*(left: seq[ZoneName], right: seq[ZoneName]): bool =
  for a in left:
    for b in right:
      if a == b:
        return true

  result = false
