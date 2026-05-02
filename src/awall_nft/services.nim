import ./errors
import ./types

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc validateServiceAtomForDb(atom: ServiceAtom, where: string): AE[void] =
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
proc validateServiceEntries(
    name: string,
    entries: ServiceEntries
): AE[void] =
  if name.len == 0:
    return failVoid(ekUnknownService, "service name must not be empty")

  if entries.items.len == 0:
    return failVoid(
      ekInvalidRule,
      "service '" & name & "' must have at least one entry"
    )

  var index = 0

  for atom in entries.items:
    let where = "service '" & name & "'[" & $index & "]"
    ?validateServiceAtomForDb(atom, where)
    inc(index)

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildServiceDb*(catalog: ServiceCatalogDto): AE[ServiceDb] =
  result = ok(initTable[ServiceName, seq[ServiceAtom]]())

  var db = initTable[ServiceName, seq[ServiceAtom]]()

  for name, entries in catalog.service:
    ?validateServiceEntries(name, entries).trace("buildServiceDb.validateServiceEntries")

    let serviceName = ServiceName(name)

    if db.hasKey(serviceName):
      return fail[ServiceDb](
        ekUnknownService,
        "duplicated service name: " & name
      )

    db[serviceName] = entries.items

  result = ok(db)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc lookupService*(
    db: ServiceDb,
    name: ServiceName
): AE[seq[ServiceAtom]] =
  if db.hasKey(name):
    result = ok(db[name])
    return

  result = fail[seq[ServiceAtom]](
    ekUnknownService,
    "unknown service: " & $name
  )
