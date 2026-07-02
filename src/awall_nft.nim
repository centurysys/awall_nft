import std/options
import argparse

import awall_nft/[cli_commands, errors, nft_emit]

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
proc exitWithValue[T](res: AE[T]): T =
  if res.isErr:
    stderr.writeLine(res.error)
    quit(1)

  result = res.get()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc selectCleanupMode(
    flushRuleset: bool,
    noFlushRuleset: bool,
    noReplaceManagedTables: bool
): AE[NftCleanupMode] =
  if flushRuleset and (noFlushRuleset or noReplaceManagedTables):
    return fail[NftCleanupMode](
      ekInvalid,
      "--flush-ruleset cannot be used with --no-flush-ruleset or --no-replace-managed-tables"
    )

  if flushRuleset:
    return ok(ncmFlushRuleset)

  if noFlushRuleset or noReplaceManagedTables:
    return ok(ncmNone)

  result = ok(ncmReplaceManagedTables)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main() =
  var p = newParser:
    command("generate"):
      help("Generate an nftables ruleset from awall-subset JSON files")

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
        "-o", "--output",
        default = some("awall_nft.nft"),
        help = "Output nftables ruleset path"
      )

      flag(
        "--flush-ruleset",
        help = "Emit 'flush ruleset' at the beginning; this removes all nftables tables"
      )

      flag(
        "--no-replace-managed-tables",
        help = "Do not emit the default 'destroy table ...' prelude for awall_nft-managed tables"
      )

      flag(
        "--no-flush-ruleset",
        help = "Compatibility alias for --no-replace-managed-tables"
      )

      run:
        let cleanupMode = exitWithValue(selectCleanupMode(
          opts.flushRuleset,
          opts.noFlushRuleset,
          opts.noReplaceManagedTables
        ))
        exitWithResult(generateCommand(
          opts.main,
          opts.privateDir,
          opts.services,
          opts.output,
          cleanupMode
        ))

    command("check"):
      help("Run 'nft -c -f FILE' without applying the ruleset")

      arg("file")

      run:
        exitWithResult(checkCommand(opts.file))

    command("apply"):
      help("Apply an existing nftables ruleset with 'nft -f FILE'")

      arg("file")

      flag(
        "--no-check",
        help = "Apply without running nft check first"
      )

      run:
        exitWithResult(applyCommand(
          opts.file,
          not opts.noCheck
        ))

    command("show"):
      help("Show normalized awall-nft configuration")

      arg("topic")

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

      run:
        exitWithResult(showCommand(
          opts.main,
          opts.privateDir,
          opts.services,
          opts.topic
        ))

    command("flowtable-sync"):
      help("Synchronize nftables flowtable rules for existing interfaces")

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

      run:
        exitWithResult(syncFlowtableCommand(
          opts.main,
          opts.privateDir,
          opts.services
        ))

    command("build-check"):
      help("Generate a ruleset and immediately check it with 'nft -c -f'")

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
        "-o", "--output",
        default = some("/tmp/awall_nft.nft"),
        help = "Output nftables ruleset path"
      )

      flag(
        "--flush-ruleset",
        help = "Emit 'flush ruleset' at the beginning; this removes all nftables tables"
      )

      flag(
        "--no-replace-managed-tables",
        help = "Do not emit the default 'destroy table ...' prelude for awall_nft-managed tables"
      )

      flag(
        "--no-flush-ruleset",
        help = "Compatibility alias for --no-replace-managed-tables"
      )

      run:
        let cleanupMode = exitWithValue(selectCleanupMode(
          opts.flushRuleset,
          opts.noFlushRuleset,
          opts.noReplaceManagedTables
        ))
        exitWithResult(buildCheckCommand(
          opts.main,
          opts.privateDir,
          opts.services,
          opts.output,
          cleanupMode
        ))

  try:
    p.run()
  except UsageError:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

when isMainModule:
  main()
