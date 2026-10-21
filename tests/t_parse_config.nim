# tests/t_parse_config.nim

import std/os

import pretty
import sunny

import awall_nft/types

proc main() =
  let dir = getAppDir() / "testdata" / "awall"

  let baseText = readFile(dir / "base.json")
  let zoneText = readFile(dir / "zone.json")
  let filterText = readFile(dir / "filter.json")
  let dnatText = readFile(dir / "dnat.json")
  let snatText = readFile(dir / "snat.json")
  let servicesText = readFile(dir / "services.json")

  let base = ConfigDto.fromJson(baseText)
  let zone = ConfigDto.fromJson(zoneText)
  let filter = ConfigDto.fromJson(filterText)
  let dnat = ConfigDto.fromJson(dnatText)
  let snat = ConfigDto.fromJson(snatText)
  let services = ServiceCatalogDto.fromJson(servicesText)

  print base
  print zone
  print filter
  print dnat
  print snat
  print services

when isMainModule:
  main()
