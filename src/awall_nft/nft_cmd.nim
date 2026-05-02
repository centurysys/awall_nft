import std/[osproc, strformat, strutils]

import ./errors

type
  CmdResult* = object
    command*: string
    exitCode*: int
    output*: string

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc shellQuote(path: string): string =
  ## Quote one shell argument for execCmdEx.
  ##
  ## This is intentionally small because nft_cmd only passes file paths.
  result = "'"

  for ch in path:
    if ch == '\'':
      result.add("'\\''")
    else:
      result.add(ch)

  result.add("'")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc runCommand(command: string): AE[CmdResult] =
  let (output, exitCode) = execCmdEx(command)

  let cmdResult = CmdResult(
    command: command,
    exitCode: exitCode,
    output: output,
  )

  if exitCode != 0:
    return fail[CmdResult](
      ekOther,
      &"command failed: {command}\nexitCode: {exitCode}\n{output}"
    )

  result = ok(cmdResult)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkNft*(path: string): AE[void] =
  if path.len == 0:
    return failVoid(ekInvalid, "nft ruleset path must not be empty")

  let command = "nft -c -f " & shellQuote(path)
  let res = ?runCommand(command).trace("checkNft.runCommand")

  if res.output.strip.len > 0:
    echo res.output

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc applyNft*(path: string): AE[void] =
  if path.len == 0:
    return failVoid(ekInvalid, "nft ruleset path must not be empty")

  let command = "nft -f " & shellQuote(path)
  let res = ?runCommand(command).trace("applyNft.runCommand")

  if res.output.strip.len > 0:
    echo res.output

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkThenApplyNft*(path: string): AE[void] =
  ?checkNft(path).trace("checkThenApplyNft.checkNft")
  ?applyNft(path).trace("checkThenApplyNft.applyNft")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkNftVerbose*(path: string): AE[CmdResult] =
  if path.len == 0:
    return fail[CmdResult](ekInvalid, "nft ruleset path must not be empty")

  let command = "nft -c -f " & shellQuote(path)
  result = runCommand(command)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc applyNftVerbose*(path: string): AE[CmdResult] =
  if path.len == 0:
    return fail[CmdResult](ekInvalid, "nft ruleset path must not be empty")

  let command = "nft -f " & shellQuote(path)
  result = runCommand(command)
