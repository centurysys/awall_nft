# tests/t_filter_src_merge.nim

import sunny

import awall_nft/[errors, merge, types]

proc main() =
  let text = """
{
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "src": "10.0.0.1/32",
      "service": "ssh",
      "action": "accept"
    },
    {
      "in": "WAN",
      "out": "_fw",
      "src": [
        "192.0.2.10/32",
        "198.51.100.0/24"
      ],
      "service": "ssh",
      "action": "accept"
    }
  ]
}
"""

  let dto = ConfigDto.fromJson(text)

  doAssert dto.filter.len == 2
  doAssert dto.filter[0].srcAddrs.items == @["10.0.0.1/32"]
  doAssert dto.filter[1].srcAddrs.items == @[
    "192.0.2.10/32",
    "198.51.100.0/24",
  ]

  let mergedRes = mergeConfigs([dto])

  if mergedRes.isErr:
    echo mergedRes.error
    quit(1)

  let merged = mergedRes.get()

  doAssert merged.filters.len == 2
  doAssert merged.filters[0].srcAddrs == @[
    IpAddress("10.0.0.1/32"),
  ]
  doAssert merged.filters[1].srcAddrs == @[
    IpAddress("192.0.2.10/32"),
    IpAddress("198.51.100.0/24"),
  ]

  echo "filter src merge: ok"

when isMainModule:
  main()
