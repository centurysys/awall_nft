import std/[options]
import argparse

import awall_nft/[errors, lxc_dnat_sync_core]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc exitWithResult(res: AE[void]) =
  if res.isErr:
    stderr.writeLine(res.error)
    quit(1)

  quit(0)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main() =
  var p = newParser:
    help("Synchronize LXC dynamic DNAT requests into nftables")

    option(
      "--main",
      default = some("/etc/awall/optional/main.json"),
      help = "Path to awall optional/main.json"
    )

    option(
      "--private-dir",
      default = some("/etc/awall/private"),
      help = "Directory containing awall private JSON files"
    )

    option(
      "--services",
      default = some("/usr/share/awall/mandatory/services.json"),
      help = "Path to awall services.json"
    )

    option(
      "--request-dir",
      default = some("/run/lxc/dnat-requests.d"),
      help = "Runtime DNAT request directory"
    )

    option(
      "--runtime-nft",
      default = some("/run/awall_nft/lxc-dnat-sync.nft"),
      help = "Generated nft script path"
    )

    flag(
      "--check-only",
      help = "Generate and check the nft script, but do not apply it"
    )

    flag(
      "--dry-run",
      help = "Print the generated nft script, but do not check or apply it"
    )

    flag(
      "--skip-host-listen-check",
      help = "Do not reject ports already listened by host processes"
    )

    flag(
      "--skip-reserved-port-check",
      help = "Do not reject reserved host management ports"
    )

    run:
      var syncOpts = defaultLxcDnatSyncOptions()
      syncOpts.mainPath = opts.main
      syncOpts.privateDir = opts.privateDir
      syncOpts.servicesPath = opts.services
      syncOpts.requestDir = opts.requestDir
      syncOpts.runtimeNftPath = opts.runtimeNft
      syncOpts.checkOnly = opts.checkOnly
      syncOpts.dryRun = opts.dryRun
      syncOpts.skipHostListenCheck = opts.skipHostListenCheck
      syncOpts.skipReservedPortCheck = opts.skipReservedPortCheck

      exitWithResult(lxcDnatSyncCommand(syncOpts))

  try:
    p.run()
  except UsageError:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

when isMainModule:
  main()
