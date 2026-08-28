# tests/t_filter_src_validate.nim

import std/strutils
import sunny

import awall_nft/[errors, merge, types, validate]

proc validateText(text: string): AE[void] =
  let dto = ConfigDto.fromJson(text)
  let mergedRes = mergeConfigs([dto])

  if mergedRes.isErr:
    return failVoid(mergedRes.error.kind, mergedRes.error.msg)

  result = validateConfig(mergedRes.get())

proc expectOk(srcJson: string) =
  let text = """
{
  "zone": {
    "WAN": { "iface": "eth0" }
  },
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "src": SRC_VALUE,
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "action": "accept"
    }
  ]
}
""".replace("SRC_VALUE", srcJson)

  let res = validateText(text)

  if res.isErr:
    echo res.error
    quit(1)

proc expectError(srcJson: string, kind: ErrKind, messagePart: string) =
  let text = """
{
  "zone": {
    "WAN": { "iface": "eth0" }
  },
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "src": SRC_VALUE,
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "action": "accept"
    }
  ]
}
""".replace("SRC_VALUE", srcJson)

  let res = validateText(text)

  doAssert res.isErr
  doAssert res.error.kind == kind
  doAssert res.error.msg.contains(messagePart)

proc main() =
  let noSourceRes = validateText("""
{
  "zone": {
    "WAN": { "iface": "eth0" }
  },
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "action": "accept"
    }
  ]
}
""")

  if noSourceRes.isErr:
    echo noSourceRes.error
    quit(1)

  expectOk("\"10.0.0.1\"")
  expectOk("\"10.0.0.1/32\"")
  expectOk("\"0.0.0.0/0\"")
  expectOk("[\"192.0.2.10/32\", \"198.51.100.0/24\"]")

  expectError("\"2001:db8::1/128\"", ekUnsupported, "IPv6 source address")
  expectError("\"10.0.0.256/32\"", ekInvalidRule, "invalid IPv4 source address")
  expectError(
    "\"10.0.0.1/33\"",
    ekInvalidRule,
    "prefix length must be between 0 and 32"
  )
  expectError("\"10.0.0.1/foo\"", ekInvalidRule, "invalid IPv4 prefix length")
  expectError("\"10.0.0/24\"", ekInvalidRule, "invalid IPv4 source address")

  echo "filter src validation: ok"

when isMainModule:
  main()
