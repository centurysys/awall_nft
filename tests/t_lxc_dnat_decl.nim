# tests/t_lxc_dnat_decl.nim

import awall_nft/[errors, lxc_dnat_decl, types]

proc requireOk[T](res: AE[T]): T =
  if res.isErr:
    echo res.error
    quit(1)

  result = res.get()

proc requireErr[T](res: AE[T], kind: ErrKind) =
  if res.isOk:
    echo "unexpected success"
    quit(1)

  if res.error.kind != kind:
    echo "unexpected error kind: ", res.error.kind
    echo res.error
    quit(1)

proc testValid() =
  let text = """
# /etc/lxc-dnat.d/hailo-web-demo.conf

[ssh]
in = Closed
proto = tcp
port = 8022
to-port = 22

[web]
in = Closed, LAN
src = 203.0.113.10/32, 198.51.100.0/24
proto = tcp
port = 8880
to-port = 80
enabled = true

[webrtc-udp]
in = Closed
proto = udp
port = 8189
to-port = 8189

[disabled]
enabled = false
"""

  let decl = requireOk(parseLxcDnatDeclText(text, "hailo.conf"))

  doAssert decl.path == "hailo.conf"
  doAssert decl.rules.len == 4

  doAssert decl.rules[0].name == "ssh"
  doAssert decl.rules[0].inZone == "Closed"
  doAssert decl.rules[0].proto == protoTcp
  doAssert decl.rules[0].port == uint16(8022)
  doAssert decl.rules[0].toPort == uint16(22)
  doAssert decl.rules[0].enabled

  doAssert decl.rules[1].name == "web"
  doAssert decl.rules[1].inZone == "Closed,LAN"
  doAssert decl.rules[1].srcAddrs == @["203.0.113.10/32", "198.51.100.0/24"]
  doAssert decl.rules[1].port == uint16(8880)
  doAssert decl.rules[1].toPort == uint16(80)

  doAssert decl.rules[2].name == "webrtc-udp"
  doAssert decl.rules[2].proto == protoUdp

  doAssert decl.rules[3].name == "disabled"
  doAssert not decl.rules[3].enabled

proc testInvalid() =
  requireErr(
    parseLxcDnatDeclText("""
[web]
in = Closed
proto = tcp
port = 0
to-port = 80
""", "bad.conf"),
    ekInvalidPort
  )

  requireErr(
    parseLxcDnatDeclText("""
[web]
in = Closed
proto = tcp
port = 8880
to-port = 80
unknown = value
""", "bad.conf"),
    ekInvalidRule
  )

  requireErr(
    parseLxcDnatDeclText("""
[web]
in = Closed
proto = tcp
port = 8880
to-port = 80

[web]
in = Closed
proto = tcp
port = 8881
to-port = 81
""", "bad.conf"),
    ekInvalidRule
  )

  requireErr(
    parseLxcDnatDeclText("""
[web]
in = Closed
proto = tcp
port = 8880
""", "bad.conf"),
    ekInvalidRule
  )

  requireErr(
    parseLxcDnatDeclText("""
[web]
in = Closed,,LAN
proto = tcp
port = 8880
to-port = 80
""", "bad.conf"),
    ekInvalidRule
  )

proc main() =
  testValid()
  testInvalid()
  echo "lxc_dnat_decl: ok"

when isMainModule:
  main()
