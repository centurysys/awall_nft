# tests/t_argparse_cli_mock.nim
#
# CLI mock for nim-argparse v4.x.
#
# This program only parses command line options and prints parsed values.
# It does not read awall JSON files and does not call nft.

import std/options
import argparse

proc cmdGenerate(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    outPath: string,
    flushRuleset: bool
): int =
  echo "command      : generate"
  echo "main         : ", mainPath
  echo "private-dir  : ", privateDir
  echo "services     : ", servicesPath
  echo "output       : ", outPath
  echo "flush-ruleset: ", flushRuleset
  result = 0

proc cmdCheck(filePath: string): int =
  echo "command: check"
  echo "file   : ", filePath
  result = 0

proc cmdApply(filePath: string, checkFirst: bool): int =
  echo "command    : apply"
  echo "file       : ", filePath
  echo "check-first: ", checkFirst
  result = 0

proc cmdBuildCheck(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    outPath: string,
    flushRuleset: bool
): int =
  echo "command      : build-check"
  echo "main         : ", mainPath
  echo "private-dir  : ", privateDir
  echo "services     : ", servicesPath
  echo "output       : ", outPath
  echo "flush-ruleset: ", flushRuleset
  result = 0

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
        quit(cmdGenerate(
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
        quit(cmdCheck(opts.file))

    command("apply"):
      help("Apply an existing nftables ruleset with 'nft -f FILE'")

      arg("file")

      flag(
        "--no-check",
        help = "Apply without running nft check first"
      )

      run:
        quit(cmdApply(
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
        quit(cmdBuildCheck(
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
