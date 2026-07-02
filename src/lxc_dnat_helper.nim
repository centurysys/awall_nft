import std/[json, options, os, strformat, strutils]
import argparse

import awall_nft/[errors, lxc_dnat_decl, lxc_dnat_request]

type
  HelperCommand = enum
    hcSetup
    hcCleanup

  HelperOptions = object
    command: HelperCommand
    instance: string
    rootfs: string
    address: string
    configDir: string
    requestDir: string
    stagingDir: string
    syncCommand: string
    noSync: bool
    instanceJson: string
    configFile: string

const
  DefaultConfigRelDir = "etc/lxc-dnat.d"
  DefaultRequestDir = "/run/lxc/dnat-requests.d"
  DefaultStagingDir = "/run/lxc/dnat-requests.staging"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc envValue(name: string): string =
  if existsEnv(name):
    result = getEnv(name)
  else:
    result = ""

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc defaultHelperOptions(command: HelperCommand): HelperOptions =
  result = HelperOptions(
    command: command,
    configDir: DefaultConfigRelDir,
    requestDir: DefaultRequestDir,
    stagingDir: DefaultStagingDir,
    syncCommand: "",
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc finalizeOptions(opts: var HelperOptions, legacyArgs: seq[string]): AE[void] =
  if opts.instance.len == 0:
    opts.instance = envValue("LXC_NAME")

  if opts.instance.len == 0 and legacyArgs.len > 0:
    ## Legacy LXC hook invocations may append the container name as the first
    ## extra positional argument. Keep this fallback so the helper does not
    ## depend on one specific hook argument version.
    opts.instance = legacyArgs[0]

  if opts.instance.len == 0:
    return failVoid(ekInvalid, "missing instance name")

  if not isSafeName(opts.instance):
    return failVoid(ekInvalid, &"unsafe instance name: {opts.instance}")

  if opts.rootfs.len == 0:
    opts.rootfs = envValue("LXC_ROOTFS_MOUNT")

  if opts.rootfs.len == 0:
    opts.rootfs = "/var/lib/lxc" / opts.instance / "rootfs"

  if opts.instanceJson.len == 0:
    opts.instanceJson = envValue("LXC_INSTANCE_JSON")

  if opts.instanceJson.len == 0:
    opts.instanceJson = "/var/lib/lxc" / opts.instance / "instance.json"

  if opts.configFile.len == 0:
    opts.configFile = envValue("LXC_CONFIG_FILE")

  if opts.configFile.len == 0:
    opts.configFile = "/var/lib/lxc" / opts.instance / "config"

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc stripCidr(address: string): string =
  let slash = address.find('/')
  if slash < 0:
    result = address.strip()
  else:
    result = address[0 ..< slash].strip()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseAddressFromInstanceJson(path: string): AE[string] =
  if path.len == 0 or not fileExists(path):
    return fail[string](ekNotFound, &"instance.json not found: {path}")

  try:
    let node = parseFile(path)
    if node.kind != JObject or not node.hasKey("ipv4"):
      return fail[string](ekNotFound, &"ipv4 is missing in instance.json: {path}")

    let ipAddr = stripCidr(node["ipv4"].getStr().strip())
    if ipAddr.len == 0 or ipAddr == "0.0.0.0":
      return fail[string](ekInvalid, &"invalid ipv4 in instance.json: {path}")

    result = ok(ipAddr)
  except CatchableError as e:
    result = fail[string](ekIO, &"failed to read instance.json '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseAddressFromConfig(path: string): AE[string] =
  if path.len == 0 or not fileExists(path):
    return fail[string](ekNotFound, &"LXC config not found: {path}")

  try:
    for rawLine in lines(path):
      let line = rawLine.strip()
      if line.len == 0 or line.startsWith("#"):
        continue

      let eqPos = line.find('=')
      if eqPos < 0:
        continue

      let key = line[0 ..< eqPos].strip()
      let value = line[eqPos + 1 .. ^1].strip()

      if key.endsWith(".ipv4.address") or key == "lxc.network.ipv4":
        let ipAddr = stripCidr(value)
        if ipAddr.len > 0 and ipAddr != "0.0.0.0":
          return ok(ipAddr)

    result = fail[string](ekNotFound, &"no static IPv4 address found in LXC config: {path}")
  except CatchableError as e:
    result = fail[string](ekIO, &"failed to read LXC config '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveConfigDir(opts: HelperOptions): string =
  if opts.configDir.isAbsolute:
    result = opts.configDir
  else:
    result = opts.rootfs / opts.configDir

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc runSync(opts: HelperOptions): AE[void] =
  if opts.noSync or opts.syncCommand.strip.len == 0:
    return okVoid()

  let exitCode = execShellCmd(opts.syncCommand)
  if exitCode != 0:
    return failVoid(
      ekOther,
      &"sync command failed: {opts.syncCommand} exitCode={exitCode}"
    )

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc resolveAddress(opts: HelperOptions): AE[string] =
  if opts.address.strip.len > 0:
    return ok(stripCidr(opts.address))

  let fromInstanceJson = parseAddressFromInstanceJson(opts.instanceJson)
  if fromInstanceJson.isOk:
    return fromInstanceJson

  let fromConfig = parseAddressFromConfig(opts.configFile)
  if fromConfig.isOk:
    return fromConfig

  result = fail[string](
    ekNotFound,
    &"failed to resolve instance IPv4 address: {fromInstanceJson.error}; {fromConfig.error}"
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setup(opts: HelperOptions): AE[void] =
  let configDir = opts.resolveConfigDir()
  let declFiles = ?parseLxcDnatDeclDir(configDir).trace("setup.parseDeclDir")

  if declFiles.len == 0:
    discard ?removeLxcDnatRequest(opts.requestDir, opts.instance).trace("setup.removeEmptyRequest")
    ?runSync(opts).trace("setup.runSyncAfterEmpty")
    return okVoid()

  let address = ?resolveAddress(opts).trace("setup.resolveAddress")

  let request = ?buildLxcDnatRequest(
    opts.instance,
    address,
    declFiles
  ).trace("setup.buildRequest")

  if request.rules.len == 0:
    discard ?removeLxcDnatRequest(opts.requestDir, opts.instance).trace("setup.removeDisabledRequest")
    ?runSync(opts).trace("setup.runSyncAfterDisabled")
    return okVoid()

  discard ?writeLxcDnatRequest(
    request,
    opts.requestDir,
    opts.stagingDir
  ).trace("setup.writeRequest")

  ?runSync(opts).trace("setup.runSync")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc cleanup(opts: HelperOptions): AE[void] =
  discard ?removeLxcDnatRequest(opts.requestDir, opts.instance).trace("cleanup.removeRequest")
  ?runSync(opts).trace("cleanup.runSync")

  result = okVoid()

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
proc setupFromCli(
    instance: string,
    rootfs: string,
    address: string,
    configDir: string,
    requestDir: string,
    stagingDir: string,
    instanceJson: string,
    configFile: string,
    syncCommand: string,
    noSync: bool,
    legacyArgs: seq[string]
) =
  var helperOpts = defaultHelperOptions(hcSetup)
  helperOpts.instance = instance
  helperOpts.rootfs = rootfs
  helperOpts.address = address
  helperOpts.configDir = configDir
  helperOpts.requestDir = requestDir
  helperOpts.stagingDir = stagingDir
  helperOpts.instanceJson = instanceJson
  helperOpts.configFile = configFile
  helperOpts.syncCommand = syncCommand
  helperOpts.noSync = noSync

  let finalized = finalizeOptions(helperOpts, legacyArgs)
  if finalized.isErr:
    stderr.writeLine(finalized.error)
    quit(1)

  exitWithResult(setup(helperOpts))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc cleanupFromCli(
    instance: string,
    rootfs: string,
    address: string,
    configDir: string,
    requestDir: string,
    stagingDir: string,
    instanceJson: string,
    configFile: string,
    syncCommand: string,
    noSync: bool,
    legacyArgs: seq[string]
) =
  var helperOpts = defaultHelperOptions(hcCleanup)
  helperOpts.instance = instance
  helperOpts.rootfs = rootfs
  helperOpts.address = address
  helperOpts.configDir = configDir
  helperOpts.requestDir = requestDir
  helperOpts.stagingDir = stagingDir
  helperOpts.instanceJson = instanceJson
  helperOpts.configFile = configFile
  helperOpts.syncCommand = syncCommand
  helperOpts.noSync = noSync

  let finalized = finalizeOptions(helperOpts, legacyArgs)
  if finalized.isErr:
    stderr.writeLine(finalized.error)
    quit(1)

  exitWithResult(cleanup(helperOpts))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main() =
  var p = newParser:
    help("Generate and remove runtime LXC DNAT request files from LXC hooks")

    command("setup"):
      help("Generate a runtime DNAT request from the container declaration files")

      option(
        "--instance",
        default = some(""),
        help = "LXC instance name. Defaults to LXC_NAME or legacy hook arg"
      )

      option(
        "--rootfs",
        default = some(""),
        help = "Mounted rootfs path. Defaults to LXC_ROOTFS_MOUNT or /var/lib/lxc/<name>/rootfs"
      )

      option(
        "--address",
        default = some(""),
        help = "Instance IPv4 address. Overrides instance.json lookup"
      )

      option(
        "--config-dir",
        default = some(DefaultConfigRelDir),
        help = "Container-side declaration directory relative to rootfs or absolute"
      )

      option(
        "--request-dir",
        default = some(DefaultRequestDir),
        help = "Runtime request directory"
      )

      option(
        "--staging-dir",
        default = some(DefaultStagingDir),
        help = "Temporary directory for atomic request file installation"
      )

      option(
        "--instance-json",
        default = some(""),
        help = "Instance metadata path. Default: /var/lib/lxc/<name>/instance.json"
      )

      option(
        "--config-file",
        default = some(""),
        help = "LXC config path for fallback address lookup"
      )

      option(
        "--sync-command",
        default = some(""),
        help = "Command to run after setup. Empty means no sync"
      )

      flag(
        "--no-sync",
        help = "Do not run sync-command"
      )

      arg("legacyArgs", nargs = -1)

      run:
        setupFromCli(
          opts.instance,
          opts.rootfs,
          opts.address,
          opts.configDir,
          opts.requestDir,
          opts.stagingDir,
          opts.instanceJson,
          opts.configFile,
          opts.syncCommand,
          opts.noSync,
          opts.legacyArgs
        )

    command("cleanup"):
      help("Remove this instance's runtime DNAT request")

      option(
        "--instance",
        default = some(""),
        help = "LXC instance name. Defaults to LXC_NAME or legacy hook arg"
      )

      option(
        "--rootfs",
        default = some(""),
        help = "Mounted rootfs path. Defaults to LXC_ROOTFS_MOUNT or /var/lib/lxc/<name>/rootfs"
      )

      option(
        "--address",
        default = some(""),
        help = "Instance IPv4 address. Overrides instance.json lookup"
      )

      option(
        "--config-dir",
        default = some(DefaultConfigRelDir),
        help = "Container-side declaration directory relative to rootfs or absolute"
      )

      option(
        "--request-dir",
        default = some(DefaultRequestDir),
        help = "Runtime request directory"
      )

      option(
        "--staging-dir",
        default = some(DefaultStagingDir),
        help = "Temporary directory for atomic request file installation"
      )

      option(
        "--instance-json",
        default = some(""),
        help = "Instance metadata path. Default: /var/lib/lxc/<name>/instance.json"
      )

      option(
        "--config-file",
        default = some(""),
        help = "LXC config path for fallback address lookup"
      )

      option(
        "--sync-command",
        default = some(""),
        help = "Command to run after cleanup. Empty means no sync"
      )

      flag(
        "--no-sync",
        help = "Do not run sync-command"
      )

      arg("legacyArgs", nargs = -1)

      run:
        cleanupFromCli(
          opts.instance,
          opts.rootfs,
          opts.address,
          opts.configDir,
          opts.requestDir,
          opts.stagingDir,
          opts.instanceJson,
          opts.configFile,
          opts.syncCommand,
          opts.noSync,
          opts.legacyArgs
        )

  try:
    p.run()
  except UsageError:
    stderr.writeLine(getCurrentExceptionMsg())
    quit(1)

when isMainModule:
  main()
