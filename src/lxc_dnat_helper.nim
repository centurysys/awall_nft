import std/[json, os, osproc, strformat, strutils]

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
proc printUsage() =
  stderr.writeLine("""
usage:
  lxc-dnat-helper setup [options]
  lxc-dnat-helper cleanup [options]

options:
  --instance=<name>       LXC instance name. Defaults to LXC_NAME or legacy hook arg.
  --rootfs=<path>         Mounted rootfs path. Defaults to LXC_ROOTFS_MOUNT or /var/lib/lxc/<name>/rootfs.
  --address=<addr>        Instance IPv4 address. Overrides instance.json lookup.
  --config-dir=<path>     Container-side declaration directory relative to rootfs or absolute.
                          Default: etc/lxc-dnat.d
  --request-dir=<path>    Runtime request directory. Default: /run/lxc/dnat-requests.d
  --staging-dir=<path>    Temporary directory for atomic request file installation.
                          Default: /run/lxc/dnat-requests.staging
  --instance-json=<path>  Instance metadata path. Default: /var/lib/lxc/<name>/instance.json.
  --config-file=<path>    LXC config path for fallback address lookup.
  --sync-command=<cmd>    Command to run after setup/cleanup. Empty means no sync.
  --no-sync               Do not run sync-command.
  -h, --help              Show this help.
""")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc optValue(arg: string, name: string): string =
  let prefix = name & "="
  if arg.startsWith(prefix):
    result = arg[prefix.len .. ^1]
  else:
    result = ""

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
proc parseOptions(): AE[HelperOptions] =
  var opts = HelperOptions(
    configDir: DefaultConfigRelDir,
    requestDir: DefaultRequestDir,
    stagingDir: DefaultStagingDir,
    syncCommand: "",
  )
  var commandSet = false
  var positional: seq[string] = @[]

  for i in 1 .. paramCount():
    let arg = paramStr(i)

    if arg == "-h" or arg == "--help":
      printUsage()
      quit(0)

    if arg == "setup" and not commandSet:
      opts.command = hcSetup
      commandSet = true
      continue

    if arg == "cleanup" and not commandSet:
      opts.command = hcCleanup
      commandSet = true
      continue

    if arg == "--no-sync":
      opts.noSync = true
      continue

    var value: string

    value = optValue(arg, "--instance")
    if value.len > 0:
      opts.instance = value
      continue

    value = optValue(arg, "--rootfs")
    if value.len > 0:
      opts.rootfs = value
      continue

    value = optValue(arg, "--address")
    if value.len > 0:
      opts.address = value
      continue

    value = optValue(arg, "--config-dir")
    if value.len > 0:
      opts.configDir = value
      continue

    value = optValue(arg, "--request-dir")
    if value.len > 0:
      opts.requestDir = value
      continue

    value = optValue(arg, "--staging-dir")
    if value.len > 0:
      opts.stagingDir = value
      continue

    value = optValue(arg, "--instance-json")
    if value.len > 0:
      opts.instanceJson = value
      continue

    value = optValue(arg, "--config-file")
    if value.len > 0:
      opts.configFile = value
      continue

    value = optValue(arg, "--sync-command")
    if value.len > 0:
      opts.syncCommand = value
      continue

    if arg.startsWith("-"):
      return fail[HelperOptions](ekInvalid, &"unknown option: {arg}")

    positional.add(arg)

  if not commandSet:
    return fail[HelperOptions](ekInvalid, "missing command: setup or cleanup")

  if opts.instance.len == 0:
    opts.instance = envValue("LXC_NAME")

  if opts.instance.len == 0 and positional.len > 0:
    ## Legacy LXC hook invocations may append the container name as the first
    ## extra positional argument. Keep this fallback so the helper does not
    ## depend on one specific hook argument version.
    opts.instance = positional[0]

  if opts.instance.len == 0:
    return fail[HelperOptions](ekInvalid, "missing instance name")

  if not isSafeName(opts.instance):
    return fail[HelperOptions](ekInvalid, &"unsafe instance name: {opts.instance}")

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

  result = ok(opts)

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
proc main() =
  let opts = parseOptions()
  if opts.isErr:
    stderr.writeLine(opts.error)
    printUsage()
    quit(1)

  case opts.get().command
  of hcSetup:
    exitWithResult(setup(opts.get()))
  of hcCleanup:
    exitWithResult(cleanup(opts.get()))

when isMainModule:
  main()
