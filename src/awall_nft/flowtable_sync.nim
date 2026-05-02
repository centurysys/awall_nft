import std/strformat

import ./errors
import ./load_config
import ./normalize

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc flowtableSyncCommand*(
    mainPath: string,
    privateDir: string,
    servicesPath: string
): AE[void] =
  ## Prepare the flowtable-sync command path without changing nftables state.
  ##
  ## This command intentionally has no nft side effects yet.  It only verifies
  ## that the same load/validate/normalize path used by ruleset generation can be
  ## reached from the new CLI command.
  let loaded = ?loadConfig(
    mainPath,
    privateDir,
    servicesPath
  ).trace("flowtableSyncCommand.loadConfig")

  let normalized = ?normalizeConfig(
    loaded.config,
    loaded.services
  ).trace("flowtableSyncCommand.normalizeConfig")

  echo &"flowtable-sync: loaded {normalized.flowtableRules.len} flowtable rule(s)"
  echo "flowtable-sync: nft update is not implemented yet"

  result = okVoid()
