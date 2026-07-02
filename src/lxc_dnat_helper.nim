import std/[json, options, os, osproc, strformat, strutils, times]
import argparse

import awall_nft/[errors, lxc_dnat_decl, lxc_dnat_request]

type
  HelperCommand = enum
    hcSetup
    hcCleanup
    hcSchedule
    hcSetupRunning

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
    workerDir: string
    logFile: string
    token: string
    retries: int
    intervalMs: int

const
  DefaultConfigRelDir = "etc/lxc-dnat.d"
  DefaultRequestDir = "/run/lxc/dnat-requests.d"
  DefaultStagingDir = "/run/lxc/dnat-requests.staging"
  DefaultSyncCommand = "/usr/local/bin/lxc-dnat-sync"
  DefaultWorkerDir = "/run/lxc/dnat-workers"
  DefaultWorkerRetries = 100
  DefaultWorkerIntervalMs = 100

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
    syncCommand: DefaultSyncCommand,
    workerDir: DefaultWorkerDir,
    retries: DefaultWorkerRetries,
    intervalMs: DefaultWorkerIntervalMs,
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseBoundedInt(name: string, value: string, minValue: int, maxValue: int): AE[int] =
  try:
    let v = parseInt(value.strip())
    if v < minValue or v > maxValue:
      return fail[int](
        ekInvalid,
        &"{name} must be in range {minValue}..{maxValue}: {value}"
      )

    result = ok(v)
  except ValueError:
    result = fail[int](ekInvalid, &"{name} must be an integer: {value}")

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

  if opts.workerDir.len == 0:
    opts.workerDir = DefaultWorkerDir

  if opts.logFile.len == 0:
    opts.logFile = opts.workerDir / (opts.instance & ".log")

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
proc ensureDir(path: string): AE[void] =
  if path.len == 0:
    return failVoid(ekInvalid, "directory path must not be empty")

  if dirExists(path):
    return okVoid()

  try:
    createDir(path)
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, &"failed to create directory '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc appendLog(path: string, msg: string) =
  if path.len == 0:
    return

  try:
    let dir = splitFile(path).dir
    if dir.len > 0 and not dirExists(dir):
      createDir(dir)

    var f = open(path, fmAppend)
    defer: f.close()
    f.writeLine(&"{now()} {msg}")
  except CatchableError:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc workerTokenPath(opts: HelperOptions): string =
  result = opts.workerDir / (opts.instance & ".token")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeWorkerToken(opts: HelperOptions): AE[string] =
  ?ensureDir(opts.workerDir).trace("writeWorkerToken.ensureDir")

  let token = &"{getCurrentProcessId()}-{epochTime()}"
  let path = opts.workerTokenPath()

  try:
    writeFile(path, token & "\n")
    result = ok(token)
  except CatchableError as e:
    result = fail[string](ekIO, &"failed to write worker token '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc tokenIsCurrent(opts: HelperOptions): bool =
  if opts.token.len == 0:
    return true

  let path = opts.workerTokenPath()
  if not fileExists(path):
    return false

  try:
    result = readFile(path).strip() == opts.token
  except CatchableError:
    result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc removeWorkerToken(opts: HelperOptions) =
  let path = opts.workerTokenPath()

  try:
    if fileExists(path):
      removeFile(path)
  except CatchableError:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc cleanup(opts: HelperOptions): AE[void] =
  removeWorkerToken(opts)

  discard ?removeLxcDnatRequest(opts.requestDir, opts.instance).trace("cleanup.removeRequest")
  ?runSync(opts).trace("cleanup.runSync")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc shellQuote(s: string): string =
  result = "'"
  for ch in s:
    if ord(ch) == 39:
      result.add("'\\''")
    else:
      result.add(ch)
  result.add("'")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addShellOpt(parts: var seq[string], name: string, value: string) =
  parts.add(name)
  parts.add(shellQuote(value))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc schedule(opts: var HelperOptions): AE[void] =
  let token = ?writeWorkerToken(opts).trace("schedule.writeWorkerToken")
  opts.token = token

  var parts: seq[string] = @[
    "setsid",
    shellQuote(getAppFilename()),
    "setup-running",
  ]

  parts.addShellOpt("--instance", opts.instance)
  parts.addShellOpt("--config-dir", opts.configDir)
  parts.addShellOpt("--request-dir", opts.requestDir)
  parts.addShellOpt("--staging-dir", opts.stagingDir)
  parts.addShellOpt("--instance-json", opts.instanceJson)
  parts.addShellOpt("--config-file", opts.configFile)
  parts.addShellOpt("--sync-command", opts.syncCommand)
  parts.addShellOpt("--worker-dir", opts.workerDir)
  parts.addShellOpt("--log-file", opts.logFile)
  parts.addShellOpt("--token", opts.token)
  parts.addShellOpt("--retries", $opts.retries)
  parts.addShellOpt("--interval-ms", $opts.intervalMs)

  if opts.address.strip.len > 0:
    parts.addShellOpt("--address", opts.address)

  if opts.noSync:
    parts.add("--no-sync")

  let command = parts.join(" ") &
    " </dev/null >> " & shellQuote(opts.logFile) & " 2>&1 &"

  let exitCode = execShellCmd(command)
  if exitCode != 0:
    removeWorkerToken(opts)
    return failVoid(
      ekOther,
      &"failed to schedule setup-running worker: exitCode={exitCode} command={command}"
    )

  appendLog(opts.logFile, &"scheduled setup-running worker for {opts.instance}")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parsePidOutput(output: string): AE[int] =
  for token in output.splitWhitespace():
    try:
      let pid = parseInt(token)
      if pid > 0:
        return ok(pid)
    except ValueError:
      discard

  result = fail[int](ekNotFound, &"no running LXC PID in output: {output.strip()}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc readLxcPid(instance: string): AE[int] =
  try:
    let output = execProcess(
      "lxc-info",
      args = ["-n", instance, "-pH"],
      options = {poUsePath, poStdErrToStdOut}
    )

    result = parsePidOutput(output)
  except CatchableError as e:
    result = fail[int](ekOther, &"failed to run lxc-info for {instance}: {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc procRootPath(pid: int): string =
  result = "/proc" / $pid / "root"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setupRunning(opts: HelperOptions): AE[void] =
  var lastError = "container PID is not available yet"

  for _ in 0 ..< opts.retries:
    if not opts.tokenIsCurrent():
      appendLog(opts.logFile, &"setup-running canceled for {opts.instance}: stale token")
      return okVoid()

    let pidRes = readLxcPid(opts.instance)
    if pidRes.isOk:
      let rootfs = procRootPath(pidRes.get())
      if dirExists(rootfs):
        var runningOpts = opts
        runningOpts.rootfs = rootfs

        appendLog(
          opts.logFile,
          &"setup-running reads declarations for {opts.instance} from {runningOpts.resolveConfigDir()}"
        )

        let setupRes = setup(runningOpts)
        if setupRes.isErr:
          appendLog(opts.logFile, &"setup-running failed for {opts.instance}: {setupRes.error}")
          return setupRes

        if not opts.tokenIsCurrent():
          appendLog(opts.logFile, &"setup-running cleanup after stale token for {opts.instance}")
          discard cleanup(runningOpts)
          return okVoid()

        appendLog(opts.logFile, &"setup-running completed for {opts.instance}")
        return okVoid()

      lastError = &"{rootfs} is not visible yet"
    else:
      lastError = $pidRes.error

    sleep(opts.intervalMs)

  result = failVoid(
    ekNotFound,
    &"failed to locate running rootfs for {opts.instance} after {opts.retries} retries: {lastError}"
  )

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
proc applyWorkerCliOptions(
    opts: var HelperOptions,
    workerDir: string,
    logFile: string,
    token: string,
    retriesText: string,
    intervalMsText: string
): AE[void] =
  opts.workerDir = workerDir
  opts.logFile = logFile
  opts.token = token

  if retriesText.strip.len > 0:
    opts.retries = ?parseBoundedInt("--retries", retriesText, 1, 36000)

  if intervalMsText.strip.len > 0:
    opts.intervalMs = ?parseBoundedInt("--interval-ms", intervalMsText, 10, 60000)

  result = okVoid()

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
    workerDir: string,
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
  helperOpts.workerDir = workerDir
  helperOpts.noSync = noSync

  let finalized = finalizeOptions(helperOpts, legacyArgs)
  if finalized.isErr:
    stderr.writeLine(finalized.error)
    quit(1)

  exitWithResult(cleanup(helperOpts))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc scheduleFromCli(
    instance: string,
    rootfs: string,
    address: string,
    configDir: string,
    requestDir: string,
    stagingDir: string,
    instanceJson: string,
    configFile: string,
    syncCommand: string,
    workerDir: string,
    logFile: string,
    retriesText: string,
    intervalMsText: string,
    noSync: bool,
    legacyArgs: seq[string]
) =
  var helperOpts = defaultHelperOptions(hcSchedule)
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

  let workerOpts = applyWorkerCliOptions(
    helperOpts,
    workerDir,
    logFile,
    "",
    retriesText,
    intervalMsText
  )
  if workerOpts.isErr:
    stderr.writeLine(workerOpts.error)
    quit(1)

  let finalized = finalizeOptions(helperOpts, legacyArgs)
  if finalized.isErr:
    stderr.writeLine(finalized.error)
    quit(1)

  exitWithResult(schedule(helperOpts))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setupRunningFromCli(
    instance: string,
    rootfs: string,
    address: string,
    configDir: string,
    requestDir: string,
    stagingDir: string,
    instanceJson: string,
    configFile: string,
    syncCommand: string,
    workerDir: string,
    logFile: string,
    token: string,
    retriesText: string,
    intervalMsText: string,
    noSync: bool,
    legacyArgs: seq[string]
) =
  var helperOpts = defaultHelperOptions(hcSetupRunning)
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

  let workerOpts = applyWorkerCliOptions(
    helperOpts,
    workerDir,
    logFile,
    token,
    retriesText,
    intervalMsText
  )
  if workerOpts.isErr:
    stderr.writeLine(workerOpts.error)
    quit(1)

  let finalized = finalizeOptions(helperOpts, legacyArgs)
  if finalized.isErr:
    stderr.writeLine(finalized.error)
    quit(1)

  let res = setupRunning(helperOpts)
  if res.isErr:
    appendLog(helperOpts.logFile, &"setup-running exits with error: {res.error}")

  exitWithResult(res)

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
        default = some(DefaultSyncCommand),
        help = "Command to run after setup. Use --no-sync to disable"
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

    command("schedule"):
      help("Schedule a detached setup-running worker and return immediately")

      option(
        "--instance",
        default = some(""),
        help = "LXC instance name. Defaults to LXC_NAME or legacy hook arg"
      )

      option(
        "--rootfs",
        default = some(""),
        help = "Ignored by setup-running. Kept for hook compatibility"
      )

      option(
        "--address",
        default = some(""),
        help = "Instance IPv4 address. Overrides instance.json lookup"
      )

      option(
        "--config-dir",
        default = some(DefaultConfigRelDir),
        help = "Container-side declaration directory relative to /proc/<pid>/root or absolute"
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
        default = some(DefaultSyncCommand),
        help = "Command to run after setup-running. Use --no-sync to disable"
      )

      option(
        "--worker-dir",
        default = some(DefaultWorkerDir),
        help = "Directory for setup-running worker token and default log file"
      )

      option(
        "--log-file",
        default = some(""),
        help = "Worker log file. Default: /run/lxc/dnat-workers/<instance>.log"
      )

      option(
        "--retries",
        default = some($DefaultWorkerRetries),
        help = "Number of setup-running PID lookup retries"
      )

      option(
        "--interval-ms",
        default = some($DefaultWorkerIntervalMs),
        help = "Delay between setup-running retries in milliseconds"
      )

      flag(
        "--no-sync",
        help = "Do not run sync-command"
      )

      arg("legacyArgs", nargs = -1)

      run:
        scheduleFromCli(
          opts.instance,
          opts.rootfs,
          opts.address,
          opts.configDir,
          opts.requestDir,
          opts.stagingDir,
          opts.instanceJson,
          opts.configFile,
          opts.syncCommand,
          opts.workerDir,
          opts.logFile,
          opts.retries,
          opts.intervalMs,
          opts.noSync,
          opts.legacyArgs
        )

    command("setup-running"):
      help("Read declarations from the running container via /proc/<pid>/root")

      option(
        "--instance",
        default = some(""),
        help = "LXC instance name. Defaults to LXC_NAME or legacy hook arg"
      )

      option(
        "--rootfs",
        default = some(""),
        help = "Ignored. setup-running resolves /proc/<pid>/root from lxc-info"
      )

      option(
        "--address",
        default = some(""),
        help = "Instance IPv4 address. Overrides instance.json lookup"
      )

      option(
        "--config-dir",
        default = some(DefaultConfigRelDir),
        help = "Container-side declaration directory relative to /proc/<pid>/root or absolute"
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
        default = some(DefaultSyncCommand),
        help = "Command to run after setup-running. Use --no-sync to disable"
      )

      option(
        "--worker-dir",
        default = some(DefaultWorkerDir),
        help = "Directory containing setup-running worker token"
      )

      option(
        "--log-file",
        default = some(""),
        help = "Worker log file. Default: /run/lxc/dnat-workers/<instance>.log"
      )

      option(
        "--token",
        default = some(""),
        help = "Worker token used to cancel stale delayed setup"
      )

      option(
        "--retries",
        default = some($DefaultWorkerRetries),
        help = "Number of PID lookup retries"
      )

      option(
        "--interval-ms",
        default = some($DefaultWorkerIntervalMs),
        help = "Delay between retries in milliseconds"
      )

      flag(
        "--no-sync",
        help = "Do not run sync-command"
      )

      arg("legacyArgs", nargs = -1)

      run:
        setupRunningFromCli(
          opts.instance,
          opts.rootfs,
          opts.address,
          opts.configDir,
          opts.requestDir,
          opts.stagingDir,
          opts.instanceJson,
          opts.configFile,
          opts.syncCommand,
          opts.workerDir,
          opts.logFile,
          opts.token,
          opts.retries,
          opts.intervalMs,
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
        default = some(DefaultSyncCommand),
        help = "Command to run after cleanup. Use --no-sync to disable"
      )

      option(
        "--worker-dir",
        default = some(DefaultWorkerDir),
        help = "Directory containing delayed setup token"
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
          opts.workerDir,
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
