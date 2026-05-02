# tests/t_normalize.nim

import std/[os, tables]
import pretty
import sunny

import awall_nft/[errors, merge, normalize, services, types, validate]

proc readConfig(path: string): ConfigDto =
  let text = readFile(path)
  result = ConfigDto.fromJson(text)

proc readServiceCatalog(path: string): ServiceCatalogDto =
  let text = readFile(path)
  result = ServiceCatalogDto.fromJson(text)

proc main() =
  let dir = "testdata" / "awall"

  let base = readConfig(dir / "base.json")
  let zone = readConfig(dir / "zone.json")
  let filter = readConfig(dir / "filter.json")
  let dnat = readConfig(dir / "dnat.json")
  let snat = readConfig(dir / "snat.json")
  let serviceCatalog = readServiceCatalog(dir / "services.json")

  let mergedRes = mergeConfigs([base, zone, filter, dnat, snat])

  if mergedRes.isErr:
    echo "merge failed:"
    echo mergedRes.error
    quit(1)

  let merged = mergedRes.get()

  let validateRes = validateConfig(merged)

  if validateRes.isErr:
    echo "validate failed:"
    echo validateRes.error
    quit(1)

  let serviceDbRes = buildServiceDb(serviceCatalog)

  if serviceDbRes.isErr:
    echo "buildServiceDb failed:"
    echo serviceDbRes.error
    quit(1)

  let serviceDb = serviceDbRes.get()

  let normalizedRes = normalizeConfig(merged, serviceDb)

  if normalizedRes.isErr:
    echo "normalize failed:"
    echo normalizedRes.error
    quit(1)

  let normalized = normalizedRes.get()

  echo "normalize: ok"

  echo "== normalized zones =="
  print normalized.zones

  echo "== normalized filters =="
  print normalized.filters

  echo "== normalized dnats =="
  print normalized.dnats

when isMainModule:
  main()
