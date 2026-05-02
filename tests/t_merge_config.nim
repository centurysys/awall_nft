# tests/t_merge_config.nim

import std/tables
import pretty
import sunny

import awall_nft/[errors, merge, types]

proc readConfig(path: string): ConfigDto =
  let text = readFile(path)
  result = ConfigDto.fromJson(text)

proc main() =
  let base = readConfig("testdata/awall/base.json")
  let zone = readConfig("testdata/awall/zone.json")
  let filter = readConfig("testdata/awall/filter.json")
  let dnat = readConfig("testdata/awall/dnat.json")
  let snat = readConfig("testdata/awall/snat.json")

  let mergedRes = mergeConfigs([base, zone, filter, dnat, snat])

  if mergedRes.isErr:
    echo mergedRes.error
    quit(1)

  let merged = mergedRes.get()
  print merged

when isMainModule:
  main()
