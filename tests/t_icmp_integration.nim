import std/[os, strutils]

import sunny

import awall_nft/[cli_commands, errors, merge, nft_cmd, nft_emit, types, validate]

# ------------------------------------------------------------------------------
# Generate a ruleset through the same load/validate/normalize path as the CLI.
# ------------------------------------------------------------------------------
proc generateIntegrationRuleset(): string =
  let fixtureDir = getAppDir() / "testdata" / "icmp"
  let privateDir = fixtureDir / "private"
  let mainPath = fixtureDir / "main.json"
  let servicesPath = privateDir / "services.json"

  var opts = defaultNftEmitOptions()
  opts.cleanupMode = ncmNone
  opts.allowRoutingIcmp = false
  opts.flowtableMode = ftOff
  opts.inetTableName = "awall_nft_icmp_test"
  opts.natTableName = "awall_nft_icmp_test_nat"

  let generated = generateNftText(mainPath, privateDir, servicesPath, opts)
  doAssert generated.isOk, $generated.error
  result = generated.get()

# ------------------------------------------------------------------------------
# Check ICMP, PING, TCP/UDP, DNAT, and masquerade in one complete ruleset.
# ------------------------------------------------------------------------------
proc testIcmpAndMasquerade(nft: string) =
  doAssert nft.contains("table inet awall_nft_icmp_test {")
  doAssert nft.contains("table ip awall_nft_icmp_test_nat {")

  # Named ICMP service without a type, and IPv6 ICMP without a type.
  doAssert nft.contains("iifname @if_wan ip protocol icmp accept")
  doAssert nft.contains(
    "iifname @if_wan meta nfproto ipv6 meta l4proto ipv6-icmp accept"
  )
  doAssert not nft.contains("iifname @if_wan icmp accept")
  doAssert not nft.contains("iifname @if_wan icmpv6 accept")

  # Named PING service and an explicit ICMP type zero.
  doAssert nft.contains("iifname @if_wan icmp type 8 accept")
  doAssert nft.contains("iifname @if_wan icmpv6 type 128 accept")
  doAssert nft.contains("iifname @if_wan icmp type 0 accept")

  # Existing TCP/UDP matches must remain unchanged.
  doAssert nft.contains("iifname @if_wan tcp dport 443 accept")
  doAssert nft.contains("iifname @if_wan udp dport 53 accept")

  # The original failure also prevented the NAT table from being updated.
  doAssert nft.contains("oifname \"eth0\" masquerade")
  doAssert nft.count("masquerade") == 1

  # The same service-match emitter is used in DNAT and forward accept rules.
  doAssert nft.contains(
    "iifname \"eth0\" ip protocol icmp dnat to 192.0.2.10"
  )
  doAssert nft.contains(
    "ct status dnat ip daddr 192.0.2.10 ip protocol icmp accept"
  )
  doAssert nft.contains(
    "iifname \"eth0\" tcp dport 8080 dnat to 192.0.2.11:80"
  )
  doAssert nft.contains("ct status dnat ip daddr 192.0.2.11 tcp dport 80 accept")

# ------------------------------------------------------------------------------
# Confirm that ICMP cannot carry ports and TCP still requires a port.
# ------------------------------------------------------------------------------
proc testProtocolValidation() =
  for serviceJson in [
    """{ "proto": "icmp", "port": 8 }""",
    """{ "proto": "tcp" }""",
  ]:
    let text = """
{
  "zone": { "WAN": { "iface": "eth0" } },
  "filter": [
    { "in": "WAN", "out": "_fw", "action": "accept", "service": SERVICE_JSON }
  ]
}
""".replace("SERVICE_JSON", serviceJson)

    let dto = ConfigDto.fromJson(text)
    let merged = mergeConfigs([dto])
    doAssert merged.isOk, $merged.error

    let checked = validateConfig(merged.get())
    doAssert checked.isErr
    doAssert checked.error.kind == ekInvalidRule

# ------------------------------------------------------------------------------
# Write the generated ruleset and optionally run nft syntax checking only.
# ------------------------------------------------------------------------------
proc checkGeneratedRuleset(nft: string) =
  let path = getTempDir() / (
    "awall_nft_icmp_integration_" & $getCurrentProcessId() & ".nft"
  )
  writeFile(path, nft)
  echo "generated ruleset: ", path

  if getEnv("AWALL_NFT_RUN_NFT_CHECK") == "1":
    let checked = checkNft(path)
    doAssert checked.isOk, $checked.error
    echo "nft -c: ok (ruleset was not applied)"
  else:
    echo "nft -c: skipped (set AWALL_NFT_RUN_NFT_CHECK=1 to enable)"

# ------------------------------------------------------------------------------
# Execute the ICMP and masquerade end-to-end regression tests.
# ------------------------------------------------------------------------------
proc main() =
  let nft = generateIntegrationRuleset()
  testIcmpAndMasquerade(nft)
  testProtocolValidation()
  checkGeneratedRuleset(nft)
  echo "icmp integration: ok"

when isMainModule:
  main()
