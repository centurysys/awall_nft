# tests/t_services.nim

import std/[os, tables]
import pretty
import sunny

import awall_nft/[errors, services, types]

proc readServiceCatalog(path: string): ServiceCatalogDto =
  let text = readFile(path)
  result = ServiceCatalogDto.fromJson(text)

proc showService(db: ServiceDb, name: string) =
  let res = lookupService(db, ServiceName(name))

  if res.isErr:
    echo "lookup failed: ", name
    echo res.error
    return

  echo "== service: ", name, " =="
  print res.get()

proc main() =
  let dir = "testdata" / "awall"
  let catalog = readServiceCatalog(dir / "services.json")

  echo "== catalog =="
  print catalog

  let dbRes = buildServiceDb(catalog)

  if dbRes.isErr:
    echo "buildServiceDb failed:"
    echo dbRes.error
    quit(1)

  let db = dbRes.get()

  echo "buildServiceDb: ok"
  echo "service count: ", db.len

  showService(db, "ssh")
  showService(db, "dns")
  showService(db, "ipsec")
  showService(db, "ping")
  showService(db, "rdp")

when isMainModule:
  main()
