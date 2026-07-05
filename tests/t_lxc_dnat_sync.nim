# tests/t_lxc_dnat_sync.nim

import std/[json, os, strutils, tables]
import sunny

import awall_nft/[
  errors,
  lxc_dnat_request,
  lxc_dnat_sync_core,
  merge,
  normalize,
  services,
  types,
  validate,
]

proc requireOk[T](res: AE[T]): T =
  if res.isErr:
    echo res.error
    quit(1)

  result = res.get()

proc requireOkVoid(res: AE[void]) =
  if res.isErr:
    echo res.error
    quit(1)

proc readConfig(path: string): ConfigDto =
  result = ConfigDto.fromJson(readFile(path))

proc readServiceCatalog(path: string): ServiceCatalogDto =
  result = ServiceCatalogDto.fromJson(readFile(path))

proc loadNormalized(): NormalizedConfig =
  let dir = "testdata" / "awall"
  let base = readConfig(dir / "base.json")
  let zone = readConfig(dir / "zone.json")
  let filter = readConfig(dir / "filter.json")
  let dnat = readConfig(dir / "dnat.json")
  let snat = readConfig(dir / "snat.json")
  let serviceCatalog = readServiceCatalog(dir / "services.json")

  let merged = requireOk(mergeConfigs([base, zone, filter, dnat, snat]))
  requireOkVoid(validateConfig(merged))
  let serviceDb = requireOk(buildServiceDb(serviceCatalog))

  result = requireOk(normalizeConfig(merged, serviceDb))

proc testEmitDynamicDnat() =
  let cfg = loadNormalized()
  let req = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "alpine_hailo_demo",
  "address": "10.0.3.13",
  "dnat": [
    {
      "name": "web",
      "in": "Closed",
      "src": ["203.0.113.10/32"],
      "service": {
        "proto": "tcp",
        "port": 18880
      },
      "to-addr": "10.0.3.13",
      "to-port": 80
    }
  ]
}
""", "alpine_hailo_demo.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("alpine_hailo_demo.json", req)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 1
  doAssert plan.warnings.len == 0

  let nft = requireOk(emitLxcDnatNft(cfg, plan.rules))
  doAssert nft.contains("delete table ip awall_lxc_dnat")
  doAssert nft.contains("type nat hook prerouting priority -90; policy accept;")
  doAssert nft.contains("iifname")
  doAssert nft.contains("\"eth0\"")
  doAssert nft.contains("\"eth1\"")
  doAssert nft.contains("ip saddr 203.0.113.10/32 tcp dport 18880 dnat to 10.0.3.13:80")

proc testReservedPortSkipped() =
  let cfg = loadNormalized()
  let req = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "bad",
  "address": "10.0.3.14",
  "dnat": [
    {
      "name": "host-ssh",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 22
      },
      "to-addr": "10.0.3.14",
      "to-port": 22
    }
  ]
}
""", "bad.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("bad.json", req)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 0
  doAssert plan.warnings.len == 1
  doAssert plan.warnings[0].reason.contains("reserved host port")

proc testStaticDnatCollisionSkipped() =
  let cfg = loadNormalized()
  let req = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "collision",
  "address": "10.0.3.15",
  "dnat": [
    {
      "name": "web",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 8880
      },
      "to-addr": "10.0.3.15",
      "to-port": 80
    }
  ]
}
""", "collision.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("collision.json", req)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 0
  doAssert plan.warnings.len == 1
  doAssert plan.warnings[0].reason.contains("awall dnat")

proc testStatusNodes() =
  let cfg = loadNormalized()
  let activeReq = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "alpine_hailo_demo",
  "address": "10.0.3.13",
  "dnat": [
    {
      "name": "web",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 18880
      },
      "to-addr": "10.0.3.13",
      "to-port": 80
    }
  ]
}
""", "alpine_hailo_demo.json"))
  let badReq = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "bad",
  "address": "10.0.3.14",
  "dnat": [
    {
      "name": "host-ssh",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 22
      },
      "to-addr": "10.0.3.14",
      "to-port": 22
    }
  ]
}
""", "bad.json"))

  let requests = @[
    ("alpine_hailo_demo.json", activeReq),
    ("bad.json", badReq),
  ]
  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    requests,
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  let statuses = buildLxcDnatStatusNodes(requests, plan, updatedAt = "2026-07-02T00:00:00Z")

  doAssert statuses.hasKey("alpine_hailo_demo")
  doAssert statuses["alpine_hailo_demo"]["status"].getStr() == "active"
  doAssert statuses["alpine_hailo_demo"]["active"].getInt() == 1
  doAssert statuses["alpine_hailo_demo"]["skipped"].getInt() == 0
  doAssert statuses["alpine_hailo_demo"]["rules"][0]["status"].getStr() == "active"

  doAssert statuses.hasKey("bad")
  doAssert statuses["bad"]["status"].getStr() == "error"
  doAssert statuses["bad"]["active"].getInt() == 0
  doAssert statuses["bad"]["skipped"].getInt() == 1
  doAssert statuses["bad"]["rules"][0]["status"].getStr() == "skipped"
  doAssert statuses["bad"]["rules"][0]["reason"].getStr().contains("reserved host port")


proc testMultiZoneNormalizeAndEmit() =
  let cfg = loadNormalized()
  let req = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "multi_zone",
  "address": "10.0.3.16",
  "dnat": [
    {
      "name": "web",
      "in": "Lan, CLOSED, closed",
      "service": {
        "proto": "tcp",
        "port": 18881
      },
      "to-addr": "10.0.3.16",
      "to-port": 80
    }
  ]
}
""", "multi_zone.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("multi_zone.json", req)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 1
  doAssert plan.warnings.len == 0
  doAssert plan.rules[0].inZone == "Closed,LAN"

  let nft = requireOk(emitLxcDnatNft(cfg, plan.rules))
  doAssert nft.contains("iifname { \"eth0\", \"eth1\", \"ppp100\", \"ppp500\", \"ppp501\", \"ppp502\", \"ppp503\" } tcp dport 18881 dnat to 10.0.3.16:80")
  doAssert nft.contains("iifname \"br*\" tcp dport 18881 dnat to 10.0.3.16:80")
  doAssert nft.contains("iifname \"wg*\" tcp dport 18881 dnat to 10.0.3.16:80")

  let statuses = buildLxcDnatStatusNodes(@[("multi_zone.json", req)], plan, updatedAt = "2026-07-02T00:00:00Z")
  doAssert statuses["multi_zone"]["rules"][0]["in"].getStr() == "Closed,LAN"

proc testMultiZoneLxcCollisionSkipped() =
  let cfg = loadNormalized()
  let firstReq = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "first",
  "address": "10.0.3.17",
  "dnat": [
    {
      "name": "web",
      "in": "Closed,LAN",
      "service": {
        "proto": "tcp",
        "port": 18882
      },
      "to-addr": "10.0.3.17",
      "to-port": 80
    }
  ]
}
""", "first.json"))
  let secondReq = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "second",
  "address": "10.0.3.18",
  "dnat": [
    {
      "name": "web",
      "in": "lan",
      "service": {
        "proto": "tcp",
        "port": 18882
      },
      "to-addr": "10.0.3.18",
      "to-port": 80
    }
  ]
}
""", "second.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("first.json", firstReq), ("second.json", secondReq)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 1
  doAssert plan.warnings.len == 1
  doAssert plan.warnings[0].inZone == "LAN"
  doAssert plan.warnings[0].reason.contains("listen port conflict")

proc testUnknownZoneSkipped() =
  let cfg = loadNormalized()
  let req = requireOk(parseLxcDnatRequestJson("""
{
  "instance": "bad_zone",
  "address": "10.0.3.19",
  "dnat": [
    {
      "name": "web",
      "in": "Clsoed",
      "service": {
        "proto": "tcp",
        "port": 18883
      },
      "to-addr": "10.0.3.19",
      "to-port": 80
    }
  ]
}
""", "bad_zone.json"))

  let plan = requireOk(buildLxcDnatSyncPlan(
    cfg,
    @[("bad_zone.json", req)],
    checkHostListenPorts = false,
    checkReservedPorts = true
  ))

  doAssert plan.rules.len == 0
  doAssert plan.warnings.len == 1
  doAssert plan.warnings[0].reason.contains("unknown zone")

proc main() =
  testEmitDynamicDnat()
  testReservedPortSkipped()
  testStaticDnatCollisionSkipped()
  testStatusNodes()
  testMultiZoneNormalizeAndEmit()
  testMultiZoneLxcCollisionSkipped()
  testUnknownZoneSkipped()
  echo "lxc_dnat_sync: ok"

when isMainModule:
  main()
