import std/[os, strformat]

import ./errors
import ./load_config
import ./nft_cmd
import ./flowtable_sync
import ./show_config
import ./nft_emit
import ./normalize

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeTextFile(path: string, text: string): AE[void] =
  if path.len == 0:
    return failVoid(ekInvalid, "output path must not be empty")

  try:
    let parent = parentDir(path)

    if parent.len > 0 and not dirExists(parent):
      createDir(parent)

    writeFile(path, text)
    result = okVoid()

  except CatchableError as e:
    result = failVoid(ekIO, &"failed to write '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc generateNftText*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    opts: NftEmitOptions
): AE[string] =
  let loaded = ?loadConfig(
    mainPath,
    privateDir,
    servicesPath
  ).trace("generateNftText.loadConfig")

  let normalized = ?normalizeConfig(
    loaded.config,
    loaded.services
  ).trace("generateNftText.normalizeConfig")

  result = emitNft(normalized, opts).trace("generateNftText.emitNft")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc generateCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    outPath: string,
    flushRuleset: bool
): AE[void] =
  var opts = defaultNftEmitOptions()
  opts.includeFlushRuleset = flushRuleset

  let text = ?generateNftText(
    mainPath,
    privateDir,
    servicesPath,
    opts
  ).trace("generateCommand.generateNftText")

  ?writeTextFile(outPath, text).trace("generateCommand.writeTextFile")

  echo "generated: ", outPath
  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkCommand*(path: string): AE[void] =
  ?checkNft(path).trace("checkCommand.checkNft")
  echo "nft check: ok"
  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc applyCommand*(path: string, checkFirst: bool): AE[void] =
  if checkFirst:
    ?checkNft(path).trace("applyCommand.checkNft")

  ?applyNft(path).trace("applyCommand.applyNft")
  echo "nft apply: ok"
  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildCheckCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    outPath: string,
    flushRuleset: bool
): AE[void] =
  ?generateCommand(
    mainPath,
    privateDir,
    servicesPath,
    outPath,
    flushRuleset
  ).trace("buildCheckCommand.generateCommand")

  ?checkCommand(outPath).trace("buildCheckCommand.checkCommand")

  result = okVoid()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc syncFlowtableCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string
): AE[void] =
  result = flowtableSyncCommand(
    mainPath,
    privateDir,
    servicesPath
  ).trace("syncFlowtableCommand.flowtableSyncCommand")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc showCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string,
    topic: string
): AE[void] =
  result = showConfigCommand(
    mainPath,
    privateDir,
    servicesPath,
    topic
  ).trace("showCommand.showConfigCommand")
