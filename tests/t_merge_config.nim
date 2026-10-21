# tests/t_merge_config.nim

import std/[os, tables]
import pretty
import sunny

import awall_nft/[errors, merge, types]

proc readConfig(path: string): ConfigDto =
  let text = readFile(path)
  result = ConfigDto.fromJson(text)

proc main() =
  let dir = getAppDir() / "testdata" / "awall"

  let base = readConfig(dir / "base.json")
  let zone = readConfig(dir / "zone.json")
  let filter = readConfig(dir / "filter.json")
  let dnat = readConfig(dir / "dnat.json")
  let snat = readConfig(dir / "snat.json")

  let mergedRes = mergeConfigs([base, zone, filter, dnat, snat])

  if mergedRes.isErr:
    echo mergedRes.error
    quit(1)

  let merged = mergedRes.get()
  print merged

when isMainModule:
  main()
