# tests/t_nft_emit.nim

import std/[os, tables]
import sunny

import awall_nft/[errors, merge, nft_emit, normalize, services, types, validate]

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

  var opts = defaultNftEmitOptions()
  opts.cleanupMode = ncmFlushRuleset
  opts.inetTableName = "awall_nft_test"
  opts.natTableName = "awall_nft_test_nat"

  let nftRes = emitNft(normalized, opts)

  if nftRes.isErr:
    echo "emitNft failed:"
    echo nftRes.error
    quit(1)

  let nft = nftRes.get()

  createDir("out")

  let outPath = "out" / "awall_nft_test.nft"
  writeFile(outPath, nft)

  echo "emitNft: ok"
  echo "wrote: ", outPath
  echo ""
  echo nft

when isMainModule:
  main()
