# tests/t_filter_src_normalize.nim

import std/tables
import sunny

import awall_nft/[errors, merge, normalize, types]

proc main() =
  let text = """
{
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "src": "10.0.0.1/32",
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "action": "accept"
    },
    {
      "in": "WAN",
      "out": "_fw",
      "src": [
        "192.0.2.10/32",
        "198.51.100.0/24"
      ],
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "action": "accept"
    },
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
"""

  let dto = ConfigDto.fromJson(text)
  let mergedRes = mergeConfigs([dto])

  if mergedRes.isErr:
    echo mergedRes.error
    quit(1)

  let serviceDb = initTable[ServiceName, seq[ServiceAtom]]()
  let normalizedRes = normalizeConfig(mergedRes.get(), serviceDb)

  if normalizedRes.isErr:
    echo normalizedRes.error
    quit(1)

  let normalized = normalizedRes.get()

  doAssert normalized.filters.len == 3
  doAssert normalized.filters[0].srcAddrs == @[
    IpAddress("10.0.0.1/32"),
  ]
  doAssert normalized.filters[1].srcAddrs == @[
    IpAddress("192.0.2.10/32"),
    IpAddress("198.51.100.0/24"),
  ]
  doAssert normalized.filters[2].srcAddrs.len == 0

  echo "filter src normalize: ok"

when isMainModule:
  main()
