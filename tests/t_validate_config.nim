# tests/t_validate_config.nim

import std/[os, tables]
import pretty
import sunny

import awall_nft/[errors, merge, types, validate]

proc readConfig(path: string): ConfigDto =
  let text = readFile(path)
  result = ConfigDto.fromJson(text)

proc main() =
  let dir = "testdata" / "awall"

  let base = readConfig(dir / "base.json")
  let zone = readConfig(dir / "zone.json")
  let filter = readConfig(dir / "filter.json")
  let dnat = readConfig(dir / "dnat.json")
  let snat = readConfig(dir / "snat.json")

  let mergedRes = mergeConfigs([base, zone, filter, dnat, snat])

  if mergedRes.isErr:
    echo "merge failed:"
    echo mergedRes.error
    quit(1)

  let merged = mergedRes.get()

  echo "== merged =="
  print merged

  let validateRes = validateConfig(merged)

  if validateRes.isErr:
    echo "validate failed:"
    echo validateRes.error
    quit(1)

  echo "validate: ok"

when isMainModule:
  main()
