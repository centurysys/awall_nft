# tests/t_parse_config.nim

import pretty
import sunny

import awall_nft/types

proc main() =
  let baseText = readFile("testdata/awall/base.json")
  let zoneText = readFile("testdata/awall/zone.json")
  let filterText = readFile("testdata/awall/filter.json")
  let dnatText = readFile("testdata/awall/dnat.json")
  let snatText = readFile("testdata/awall/snat.json")
  let servicesText = readFile("testdata/awall/services.json")

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
