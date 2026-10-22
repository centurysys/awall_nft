import std/[strutils, tables]
import sunny

import awall_nft/[errors, merge, normalize, services, types, validate]

# ------------------------------------------------------------------------------
# Verify that omitted fields and explicit ICMP type zero remain distinguishable.
# ------------------------------------------------------------------------------
proc testCatalogParsing() =
  let catalog = ServiceCatalogDto.fromJson("""
{
  "service": {
    "missing": { "proto": "icmp" },
    "zero": { "proto": "icmp", "type": 0, "reply-type": 0 },
    "ping": { "proto": "icmp", "type": 8, "reply-type": 0 },
    "maximum": { "proto": "icmpv6", "type": 255, "reply-type": 255 }
  }
}
""")

  let missing = catalog.service["missing"].items[0]
  doAssert missing.`type`.isNone
  doAssert missing.replyType.isNone

  let zero = catalog.service["zero"].items[0]
  doAssert zero.`type` == some(0'u8)
  doAssert zero.replyType == some(0'u8)

  let ping = catalog.service["ping"].items[0]
  doAssert ping.`type` == some(8'u8)
  doAssert ping.replyType == some(0'u8)

  let maximum = catalog.service["maximum"].items[0]
  doAssert maximum.`type` == some(255'u8)
  doAssert maximum.replyType == some(255'u8)

  let encodedZero = sunny.toJson(zero)
  doAssert encodedZero.contains("\"type\":0")
  doAssert encodedZero.contains("\"reply-type\":0")

  let decodedZero = ServiceAtom.fromJson(encodedZero)
  doAssert decodedZero.`type` == some(0'u8)
  doAssert decodedZero.replyType == some(0'u8)

  let encodedMissing = sunny.toJson(missing)
  doAssert not encodedMissing.contains("\"type\":")
  doAssert not encodedMissing.contains("\"reply-type\":")

# ------------------------------------------------------------------------------
# Verify normalized matches retain type and reply-type for inline/named services.
# ------------------------------------------------------------------------------
proc testNormalization() =
  let dto = ConfigDto.fromJson("""
{
  "zone": { "WAN": { "iface": "eth0" } },
  "filter": [
    {
      "in": "WAN", "out": "_fw", "action": "accept",
      "service": { "proto": "icmp", "type": 0, "reply-type": 0 }
    },
    {
      "in": "WAN", "out": "_fw", "action": "accept",
      "service": "ping"
    },
    {
      "in": "WAN", "out": "_fw", "action": "accept",
      "service": { "proto": "icmp" }
    }
  ]
}
""")

  let catalog = ServiceCatalogDto.fromJson("""
{
  "service": {
    "ping": [
      { "proto": "icmp", "type": 8, "reply-type": 0 },
      { "proto": "icmpv6", "type": 128, "reply-type": 129 }
    ]
  }
}
""")

  let merged = mergeConfigs([dto])
  doAssert merged.isOk
  doAssert validateConfig(merged.get()).isOk

  let serviceDb = buildServiceDb(catalog)
  doAssert serviceDb.isOk

  let normalized = normalizeConfig(merged.get(), serviceDb.get())
  doAssert normalized.isOk

  let filters = normalized.get().filters
  doAssert filters.len == 3

  doAssert filters[0].matches.len == 1
  doAssert filters[0].matches[0].icmpType == some(0'u8)
  doAssert filters[0].matches[0].icmpReplyType == some(0'u8)

  doAssert filters[1].matches.len == 2
  doAssert filters[1].matches[0].icmpType == some(8'u8)
  doAssert filters[1].matches[0].icmpReplyType == some(0'u8)
  doAssert filters[1].matches[1].icmpType == some(128'u8)
  doAssert filters[1].matches[1].icmpReplyType == some(129'u8)

  doAssert filters[2].matches.len == 1
  doAssert filters[2].matches[0].icmpType.isNone
  doAssert filters[2].matches[0].icmpReplyType.isNone

# ------------------------------------------------------------------------------
# Verify malformed and out-of-range ICMP type values cannot be accepted.
# ------------------------------------------------------------------------------
proc testInvalidValues() =
  for field in ["type", "reply-type"]:
    for value in ["-1", "256", "1.5", "\"8\""]:
      var rejected = false

      try:
        discard ServiceAtom.fromJson(
          "{\"proto\":\"icmp\",\"" & field & "\":" & value & "}"
        )
      except Exception:
        rejected = true

      doAssert rejected, field & " must reject " & value

# ------------------------------------------------------------------------------
# Run the regression tests for optional ICMP type values.
# ------------------------------------------------------------------------------
proc main() =
  testCatalogParsing()
  testNormalization()
  testInvalidValues()
  echo "icmp type option: ok"

when isMainModule:
  main()
