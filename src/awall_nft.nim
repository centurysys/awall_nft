import std/options
import argparse

import awall_nft/[cli_commands, errors]

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
        "--no-flush-ruleset",
        help = "Do not emit 'flush ruleset' at the beginning"
      )

      run:
        exitWithResult(generateCommand(
          opts.main,
          opts.privateDir,
          opts.services,
          opts.output,
          not opts.noFlushRuleset
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
        "--no-flush-ruleset",
        help = "Do not emit 'flush ruleset' at the beginning"
      )

      run:
        exitWithResult(buildCheckCommand(
          opts.main,
          opts.privateDir,
          opts.services,
          opts.output,
          not opts.noFlushRuleset
        ))

  try:
    p.run()
  except UsageError:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

when isMainModule:
  main()
