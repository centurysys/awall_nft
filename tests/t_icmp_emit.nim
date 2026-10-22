import std/[options, strutils, tables]

import awall_nft/[errors, nft_emit, types]

# ------------------------------------------------------------------------------
# Create an ICMP match with either an explicit type or an omitted type.
# ------------------------------------------------------------------------------
proc makeIcmpMatch(proto: Protocol, icmpType: Option[uint8]): NormalizedServiceMatch =
  result = NormalizedServiceMatch(
    family: (if proto == protoIcmp: famInet else: famInet6),
    proto: proto,
    ports: @[],
    icmpType: icmpType,
    icmpReplyType: none(uint8),
    ctHelper: none(string),
  )

# ------------------------------------------------------------------------------
# Create a minimal WAN-to-router filter configuration for the requested match.
# ------------------------------------------------------------------------------
proc makeConfig(match: NormalizedServiceMatch): NormalizedConfig =
  var zones = initTable[ZoneName, ZoneRuntime]()
  zones[ZoneWan] = ZoneRuntime(
    name: ZoneWan,
    exactIfaces: @[InterfaceName("eth0")],
    prefixIfaces: @[],
  )

  result = NormalizedConfig(
    zones: zones,
    policies: @[],
    filters: @[
      NormalizedFilterRule(
        inZones: @[ZoneWan],
        outZones: @[ZoneFirewall],
        srcAddrs: @[],
        matches: @[match],
        action: actAccept,
        connLimit: none(ConnLimit),
      )
    ],
    dnats: @[],
    snats: @[],
    clampMssRules: @[],
    flowtableRules: @[],
  )

# ------------------------------------------------------------------------------
# Emit a ruleset without routing ICMP shortcuts or host-dependent flowtables.
# ------------------------------------------------------------------------------
proc emitForTest(match: NormalizedServiceMatch): string =
  var opts = defaultNftEmitOptions()
  opts.cleanupMode = ncmNone
  opts.allowRoutingIcmp = false
  opts.flowtableMode = ftOff

  let emitRes = emitNft(makeConfig(match), opts)
  doAssert emitRes.isOk, $emitRes.error
  result = emitRes.get()

# ------------------------------------------------------------------------------
# Check that omitting the type matches the whole ICMP protocol, not bare syntax.
# ------------------------------------------------------------------------------
proc testIcmpWithoutType() =
  let nft4 = emitForTest(makeIcmpMatch(protoIcmp, none(uint8)))
  doAssert nft4.contains("iifname @if_wan ip protocol icmp accept")
  doAssert not nft4.contains("iifname @if_wan icmp accept")

  let nft6 = emitForTest(makeIcmpMatch(protoIcmpv6, none(uint8)))
  doAssert nft6.contains(
    "iifname @if_wan meta nfproto ipv6 meta l4proto ipv6-icmp accept"
  )
  doAssert not nft6.contains("iifname @if_wan icmpv6 accept")

# ------------------------------------------------------------------------------
# Check that type zero remains a real match instead of being treated as omitted.
# ------------------------------------------------------------------------------
proc testExplicitZero() =
  let nft4 = emitForTest(makeIcmpMatch(protoIcmp, some(0'u8)))
  doAssert nft4.contains("iifname @if_wan icmp type 0 accept")
  doAssert not nft4.contains("iifname @if_wan ip protocol icmp accept")

  let nft6 = emitForTest(makeIcmpMatch(protoIcmpv6, some(0'u8)))
  doAssert nft6.contains("iifname @if_wan icmpv6 type 0 accept")
  doAssert not nft6.contains("iifname @if_wan meta nfproto ipv6 meta l4proto ipv6-icmp accept")

# ------------------------------------------------------------------------------
# Check that the existing IPv4/IPv6 PING type expressions are unchanged.
# ------------------------------------------------------------------------------
proc testPingTypes() =
  let nft4 = emitForTest(makeIcmpMatch(protoIcmp, some(8'u8)))
  doAssert nft4.contains("iifname @if_wan icmp type 8 accept")

  let nft6 = emitForTest(makeIcmpMatch(protoIcmpv6, some(128'u8)))
  doAssert nft6.contains("iifname @if_wan icmpv6 type 128 accept")

# ------------------------------------------------------------------------------
# Run the ICMP nftables emission regression tests.
# ------------------------------------------------------------------------------
proc main() =
  testIcmpWithoutType()
  testExplicitZero()
  testPingTypes()
  echo "icmp nft emit: ok"

when isMainModule:
  main()
