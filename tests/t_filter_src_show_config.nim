# tests/t_filter_src_show_config.nim

import std/[os, strutils]

import awall_nft/[errors, show_config]

proc main() =
  let workDir = "out" / "filter-src-show-config"
  let mainPath = workDir / "main.json"
  let privateDir = workDir / "private"
  let configPath = privateDir / "filter-src.json"
  let servicesPath = "testdata" / "awall" / "services.json"

  createDir("out")
  createDir(workDir)
  createDir(privateDir)

  writeFile(
    mainPath,
    """
{
  "import": [ "filter-src" ]
}
"""
  )

  writeFile(
    configPath,
    """
{
  "zone": {
    "WAN": {
      "iface": [ "eth0" ]
    }
  },
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "src": [
        "192.168.10.0/24",
        "10.0.0.1/32"
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
        "port": 22
      },
      "action": "accept"
    }
  ]
}
"""
  )

  let showRes = showConfigText(
    mainPath,
    privateDir,
    servicesPath,
    "filters"
  )

  if showRes.isErr:
    echo "showConfigText failed:"
    echo showRes.error
    quit(1)

  let text = showRes.get()

  doAssert text.contains(
    "src       : 10.0.0.1/32, 192.168.10.0/24"
  )
  doAssert text.count("src       :") == 1
  doAssert text.contains(
    "family=any proto=tcp ports=8022"
  )
  doAssert text.contains(
    "family=any proto=tcp ports=22"
  )

  echo "filter src show config: ok"

when isMainModule:
  main()
