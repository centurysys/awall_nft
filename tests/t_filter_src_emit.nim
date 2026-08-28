# tests/t_filter_src_emit.nim

import std/[options, strutils, tables]

import awall_nft/[errors, nft_emit, types]

proc makeZone(name: ZoneName, iface: string): ZoneRuntime =
  result = ZoneRuntime(
    name: name,
    exactIfaces: @[InterfaceName(iface)],
    prefixIfaces: @[],
  )

proc makeTcpMatch(port: uint16): NormalizedServiceMatch =
  result = NormalizedServiceMatch(
    family: famAny,
    proto: protoTcp,
    ports: @[port],
    icmpType: none(int),
    icmpReplyType: none(int),
    ctHelper: none(string),
  )

proc makeConfig(
    srcAddrs: seq[IpAddress],
    connLimit = none(ConnLimit)
): NormalizedConfig =
  var zones = initTable[ZoneName, ZoneRuntime]()
  zones[ZoneWan] = makeZone(ZoneWan, "eth0")

  result = NormalizedConfig(
    zones: zones,
    policies: @[],
    filters: @[
      NormalizedFilterRule(
        inZones: @[ZoneWan],
        outZones: @[ZoneFirewall],
        srcAddrs: srcAddrs,
        matches: @[makeTcpMatch(8022'u16)],
        action: actAccept,
        connLimit: connLimit,
      )
    ],
    dnats: @[],
    snats: @[],
    clampMssRules: @[],
    flowtableRules: @[],
  )

proc emitForTest(cfg: NormalizedConfig): string =
  var opts = defaultNftEmitOptions()
  opts.cleanupMode = ncmNone
  opts.allowRoutingIcmp = false
  opts.flowtableMode = ftOff

  let emitRes = emitNft(cfg, opts)

  doAssert emitRes.isOk, $emitRes.error
  result = emitRes.get()

proc testSingleSource() =
  let nft = emitForTest(makeConfig(@[
    IpAddress("10.0.0.1/32"),
  ]))

  doAssert nft.contains(
    "iifname @if_wan ip saddr 10.0.0.1/32 tcp dport 8022 accept"
  )

proc testMultipleSources() =
  let nft = emitForTest(makeConfig(@[
    IpAddress("192.168.10.0/24"),
    IpAddress("10.0.0.1/32"),
  ]))

  doAssert nft.contains(
    "iifname @if_wan ip saddr { 10.0.0.1/32, 192.168.10.0/24 } " &
    "tcp dport 8022 accept"
  )

proc testNoSource() =
  let nft = emitForTest(makeConfig(@[]))

  doAssert nft.contains(
    "iifname @if_wan tcp dport 8022 accept"
  )
  doAssert not nft.contains(
    "iifname @if_wan ip saddr"
  )

proc testConnLimitIncludesSource() =
  let nft = emitForTest(makeConfig(
    @[IpAddress("10.0.0.1/32")],
    some(ConnLimit(
      count: 3,
      interval: 20,
    ))
  ))

  var foundMeter = false

  for line in nft.splitLines():
    if line.contains("limit_filter_input_0"):
      foundMeter = true
      doAssert line.contains("ip saddr 10.0.0.1/32")

  doAssert foundMeter

proc main() =
  testSingleSource()
  testMultipleSources()
  testNoSource()
  testConnLimitIncludesSource()

  echo "filter src nft emit: ok"

when isMainModule:
  main()
