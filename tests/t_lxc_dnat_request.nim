# tests/t_lxc_dnat_request.nim

import std/json

import awall_nft/[errors, lxc_dnat_decl, lxc_dnat_request]

proc requireOk[T](res: AE[T]): T =
  if res.isErr:
    echo res.error
    quit(1)

  result = res.get()

proc testRequestJson() =
  let decl = requireOk(parseLxcDnatDeclText("""
[web]
in = Closed, LAN
src = 203.0.113.10/32, 198.51.100.0/24
proto = tcp
port = 8880
to-port = 80

[disabled]
enabled = false
""", "/rootfs/etc/lxc-dnat.d/web.conf"))

  let request = requireOk(buildLxcDnatRequest(
    "alpine_hailo_demo",
    "10.0.3.13",
    @[decl]
  ))

  doAssert request.instance == "alpine_hailo_demo"
  doAssert request.address == "10.0.3.13"
  doAssert request.rules.len == 1

  let node = parseJson(request.toJsonText())
  doAssert node["instance"].getStr() == "alpine_hailo_demo"
  doAssert node["address"].getStr() == "10.0.3.13"
  doAssert node["dnat"].len == 1
  doAssert node["dnat"][0]["name"].getStr() == "web"
  doAssert node["dnat"][0]["in"].getStr() == "Closed,LAN"
  doAssert node["dnat"][0]["service"]["proto"].getStr() == "tcp"
  doAssert node["dnat"][0]["service"]["port"].getInt() == 8880
  doAssert node["dnat"][0]["to-addr"].getStr() == "10.0.3.13"
  doAssert node["dnat"][0]["to-port"].getInt() == 80
  doAssert node["dnat"][0]["src"].len == 2

proc testUnsafeInstanceName() =
  let decl = requireOk(parseLxcDnatDeclText("""
[web]
in = Closed
proto = tcp
port = 8880
to-port = 80
""", "web.conf"))

  let res = buildLxcDnatRequest("../bad", "10.0.3.13", @[decl])
  doAssert res.isErr
  doAssert res.error.kind == ekInvalid

proc main() =
  testRequestJson()
  testUnsafeInstanceName()
  echo "lxc_dnat_request: ok"

when isMainModule:
  main()
