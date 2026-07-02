import std/[algorithm, hashes, json, os, options, strformat, strutils, tables, times]

import ./errors
import ./load_config
import ./lxc_dnat_request
import ./nft_cmd
import ./normalize
import ./process_lock
import ./types

const
  LxcDnatFamily = "ip"
  LxcDnatTable = "awall_lxc_dnat"
  LxcDnatPreroutingChain = "prerouting"
  LxcDnatDynamicChain = "lxc_dnat_dynamic"
  LxcDnatPriority = "-90"
  LxcDnatSyncLockPath = "/run/lock/awall_nft/lxc-dnat-sync.lock"
  DefaultRuntimeNftPath = "/run/awall_nft/lxc-dnat-sync.nft"
  DefaultStatusDir = "/run/lxc/dnat-status.d"

  ReservedTcpPorts = [22'u16, 53'u16, 67'u16, 80'u16, 443'u16]
  ReservedUdpPorts = [53'u16, 67'u16]

type
  LxcDnatSyncOptions* = object
    mainPath*: string
    privateDir*: string
    servicesPath*: string
    requestDir*: string
    runtimeNftPath*: string
    statusDir*: string
    checkOnly*: bool
    dryRun*: bool
    skipHostListenCheck*: bool
    skipReservedPortCheck*: bool

  LxcDnatKey = object
    proto: Protocol
    inZone: string
    port: uint16

  LxcDnatPlannedRule* = object
    requestPath*: string
    instance*: string
    name*: string
    inZone*: string
    srcAddrs*: seq[string]
    proto*: Protocol
    port*: uint16
    toAddr*: string
    toPort*: uint16

  LxcDnatSyncWarning* = object
    requestPath*: string
    instance*: string
    rule*: string
    reason*: string
    inZone*: string
    srcAddrs*: seq[string]
    proto*: Protocol
    port*: uint16
    toAddr*: string
    toPort*: uint16

  LxcDnatSyncPlan* = object
    rules*: seq[LxcDnatPlannedRule]
    warnings*: seq[LxcDnatSyncWarning]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sortedStrings(values: seq[string]): seq[string] =
  result = values
  result.sort(proc(a, b: string): int = cmp(a, b))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc protoText(proto: Protocol): string =
  case proto
  of protoTcp:
    result = "tcp"
  of protoUdp:
    result = "udp"
  else:
    result = $proto

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc q(value: string): string =
  result = "\""
  for ch in value:
    case ch
    of '\\': result.add("\\\\")
    of '"': result.add("\\\"")
    else: result.add(ch)
  result.add("\"")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc combineConds(a: string, b: string): string =
  if a.len == 0:
    result = b
  elif b.len == 0:
    result = a
  else:
    result = a & " " & b

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc joinQuotedSet(values: seq[string]): string =
  if values.len == 1:
    result = q(values[0])
    return

  var quoted: seq[string] = @[]
  for value in sortedStrings(values):
    quoted.add(q(value))

  result = "{ " & quoted.join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc joinAddressSet(values: seq[string]): string =
  if values.len == 1:
    result = values[0]
    return

  result = "{ " & sortedStrings(values).join(", ") & " }"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isReservedPort(proto: Protocol, port: uint16): bool =
  case proto
  of protoTcp:
    result = port in ReservedTcpPorts
  of protoUdp:
    result = port in ReservedUdpPorts
  else:
    result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc keyText(key: LxcDnatKey): string =
  result = &"{protoText(key.proto)}/{key.inZone}/{key.port}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hash(key: LxcDnatKey): Hash =
  result = hash(protoText(key.proto)) !& hash(key.inZone) !& hash(int(key.port))
  result = !$result

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc requestRuleKey(rule: LxcDnatRequestRule): LxcDnatKey =
  result = LxcDnatKey(
    proto: rule.proto,
    inZone: rule.inZone,
    port: rule.port,
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc addWarning(
    plan: var LxcDnatSyncPlan,
    requestPath: string,
    instance: string,
    rule: LxcDnatRequestRule,
    reason: string
) =
  plan.warnings.add(LxcDnatSyncWarning(
    requestPath: requestPath,
    instance: instance,
    rule: rule.name,
    reason: reason,
    inZone: rule.inZone,
    srcAddrs: rule.srcAddrs,
    proto: rule.proto,
    port: rule.port,
    toAddr: rule.toAddr,
    toPort: rule.toPort,
  ))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseProtocol(text: string, where: string): AE[Protocol] =
  case text.strip().toLowerAscii()
  of "tcp":
    result = ok(protoTcp)
  of "udp":
    result = ok(protoUdp)
  else:
    result = fail[Protocol](ekUnknownProtocol, &"{where}: proto must be tcp or udp")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseUint16Port(node: JsonNode, where: string): AE[uint16] =
  if node.kind != JInt:
    return fail[uint16](ekInvalidPort, &"{where}: port must be an integer")

  let value = node.getInt()
  if value < 1 or value > 65535:
    return fail[uint16](ekInvalidPort, &"{where}: port must be in range 1..65535")

  result = ok(uint16(value))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseOptionalStringArray(node: JsonNode, where: string): AE[seq[string]] =
  var values: seq[string] = @[]

  case node.kind
  of JString:
    let value = node.getStr().strip()
    if value.len > 0:
      values.add(value)
  of JArray:
    for i in 0 ..< node.len:
      let item = node[i]
      if item.kind != JString:
        return fail[seq[string]](ekJson, &"{where}[{i}]: expected string")

      let value = item.getStr().strip()
      if value.len == 0:
        return fail[seq[string]](ekJson, &"{where}[{i}]: must not be empty")

      values.add(value)
  of JNull:
    discard
  else:
    return fail[seq[string]](ekJson, &"{where}: expected string or array of strings")

  result = ok(values)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc requireKey(node: JsonNode, key: string, where: string): AE[JsonNode] =
  if node.kind != JObject:
    return fail[JsonNode](ekJson, &"{where}: expected object")

  if not node.hasKey(key):
    return fail[JsonNode](ekJson, &"{where}: missing '{key}'")

  result = ok(node[key])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseRequestRule(node: JsonNode, requestPath: string, index: int): AE[LxcDnatRequestRule] =
  let where = &"{requestPath}:dnat[{index}]"

  if node.kind != JObject:
    return fail[LxcDnatRequestRule](ekJson, &"{where}: expected object")

  let svc = ?requireKey(node, "service", where)
  if svc.kind != JObject:
    return fail[LxcDnatRequestRule](ekJson, &"{where}.service: expected object")

  let srcAddrs =
    if node.hasKey("src"):
      ?parseOptionalStringArray(node["src"], where & ".src")
    else:
      newSeq[string]()

  result = ok(LxcDnatRequestRule(
    name: (?requireKey(node, "name", where)).getStr(),
    inZone: (?requireKey(node, "in", where)).getStr(),
    srcAddrs: srcAddrs,
    proto: ?parseProtocol((?requireKey(svc, "proto", where & ".service")).getStr(), where & ".service.proto"),
    port: ?parseUint16Port(?requireKey(svc, "port", where & ".service"), where & ".service.port"),
    toAddr: (?requireKey(node, "to-addr", where)).getStr(),
    toPort: ?parseUint16Port(?requireKey(node, "to-port", where), where & ".to-port"),
    sourcePath:
      if node.hasKey("source-path"):
        node["source-path"].getStr()
      else:
        "",
    sourceLine:
      if node.hasKey("source-line") and node["source-line"].kind == JInt:
        node["source-line"].getInt()
      else:
        0,
  ))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseLxcDnatRequestJson*(text: string, requestPath = ""): AE[LxcDnatRequestFile] =
  var node: JsonNode

  try:
    node = parseJson(text)
  except CatchableError as e:
    return fail[LxcDnatRequestFile](ekJson, &"failed to parse request JSON '{requestPath}': {e.msg}")

  if node.kind != JObject:
    return fail[LxcDnatRequestFile](ekJson, &"{requestPath}: expected object")

  var rules: seq[LxcDnatRequestRule] = @[]
  let dnat = ?requireKey(node, "dnat", requestPath)

  if dnat.kind != JArray:
    return fail[LxcDnatRequestFile](ekJson, &"{requestPath}: dnat must be an array")

  for i in 0 ..< dnat.len:
    let ruleNode = dnat[i]
    rules.add(?parseRequestRule(ruleNode, requestPath, i))

  result = ok(LxcDnatRequestFile(
    instance: (?requireKey(node, "instance", requestPath)).getStr(),
    address: (?requireKey(node, "address", requestPath)).getStr(),
    rules: rules,
  ))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseLxcDnatRequestFile*(path: string): AE[LxcDnatRequestFile] =
  try:
    result = parseLxcDnatRequestJson(readFile(path), path)
  except CatchableError as e:
    result = fail[LxcDnatRequestFile](ekIO, &"failed to read request file '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc loadLxcDnatRequests*(requestDir: string): AE[seq[(string, LxcDnatRequestFile)]] =
  if requestDir.len == 0:
    return fail[seq[(string, LxcDnatRequestFile)]](ekInvalid, "request directory must not be empty")

  if not dirExists(requestDir):
    return ok(newSeq[(string, LxcDnatRequestFile)]())

  var paths: seq[string] = @[]
  for kind, path in walkDir(requestDir):
    if kind == pcFile and path.endsWith(".json"):
      paths.add(path)

  paths.sort()

  var requests: seq[(string, LxcDnatRequestFile)] = @[]
  for path in paths:
    requests.add((path, ?parseLxcDnatRequestFile(path)))

  result = ok(requests)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneRuntime(cfg: NormalizedConfig, zone: ZoneName): AE[ZoneRuntime] =
  if cfg.zones.hasKey(zone):
    result = ok(cfg.zones[zone])
    return

  result = fail[ZoneRuntime](ekUnknownZone, "unknown zone in lxc-dnat-sync: " & string(zone))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc zoneMatchConditions(cfg: NormalizedConfig, zoneName: string): AE[seq[string]] =
  let zone = ZoneName(zoneName)

  if zone == ZoneFirewall:
    return ok(@[""])

  let runtime = ?zoneRuntime(cfg, zone)
  var conditions: seq[string] = @[]

  var exacts: seq[string] = @[]
  for iface in runtime.exactIfaces:
    exacts.add(string(iface))

  if exacts.len > 0:
    conditions.add("iifname " & joinQuotedSet(exacts))

  for prefix in sortedStrings(runtime.prefixIfaces):
    conditions.add("iifname " & q(prefix & "*"))

  if conditions.len == 0:
    return fail[seq[string]](ekInvalidInterface, &"zone has no interfaces: {zoneName}")

  result = ok(conditions)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatRuleSourceMatch(rule: LxcDnatPlannedRule): string =
  if rule.srcAddrs.len == 0:
    return ""

  for addr in rule.srcAddrs:
    if addr.contains(":"):
      return "# unsupported IPv6 src in lxc-dnat-sync"

  result = "ip saddr " & joinAddressSet(rule.srcAddrs)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dnatRuleToText(rule: LxcDnatPlannedRule, cfg: NormalizedConfig): AE[seq[string]] =
  if rule.toAddr.contains(":"):
    return fail[seq[string]](ekUnsupported, &"IPv6 DNAT destination is not supported: {rule.toAddr}")

  let inConds = ?zoneMatchConditions(cfg, rule.inZone)
  let srcCond = dnatRuleSourceMatch(rule)
  if srcCond.startsWith("#"):
    return fail[seq[string]](ekUnsupported, &"{rule.instance}:{rule.name}: IPv6 src is not supported")

  let svcCond = &"{protoText(rule.proto)} dport {rule.port}"
  let dnatExpr = &"dnat to {rule.toAddr}:{rule.toPort}"
  var lines: seq[string] = @[]

  for baseCond in inConds:
    let condition = combineConds(combineConds(baseCond, srcCond), svcCond)
    lines.add(combineConds(condition, dnatExpr))

  result = ok(lines)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc staticDnatCollides(staticRule: NormalizedDnatRule, requestRule: LxcDnatRequestRule): bool =
  var zoneMatches = false

  if staticRule.inZones.len == 0:
    zoneMatches = true
  else:
    for zone in staticRule.inZones:
      if string(zone) == requestRule.inZone:
        zoneMatches = true
        break

  if not zoneMatches:
    return false

  for match in staticRule.matches:
    if match.proto != requestRule.proto:
      continue

    for port in match.ports:
      if port == requestRule.port:
        return true

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc existingStaticDnatCollision(
    cfg: NormalizedConfig,
    requestRule: LxcDnatRequestRule
): Option[string] =
  for index, rule in cfg.dnats:
    if staticDnatCollides(rule, requestRule):
      return some(&"awall dnat[{index}]")

  result = none(string)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseProcNetPort(line: string): Option[uint16] =
  let cols = line.splitWhitespace()
  if cols.len < 4:
    return none(uint16)

  let local = cols[1]
  let colon = local.rfind(':')
  if colon < 0 or colon == local.high:
    return none(uint16)

  let localAddr = local[0 ..< colon]
  let portHex = local[colon + 1 .. ^1]

  if localAddr == "0100007F" or localAddr == "00000000000000000000000001000000":
    return none(uint16)

  try:
    let port = parseHexInt(portHex)
    if port >= 1 and port <= 65535:
      result = some(uint16(port))
    else:
      result = none(uint16)
  except ValueError:
    result = none(uint16)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectProcNetListenPorts(path: string, proto: Protocol, tcpOnlyListenState: bool): seq[LxcDnatKey] =
  if not fileExists(path):
    return @[]

  var first = true
  for rawLine in lines(path):
    if first:
      first = false
      continue

    let line = rawLine.strip()
    if line.len == 0:
      continue

    let cols = line.splitWhitespace()
    if cols.len < 4:
      continue

    if tcpOnlyListenState and cols[3] != "0A":
      continue

    let portOpt = parseProcNetPort(line)
    if portOpt.isSome:
      result.add(LxcDnatKey(proto: proto, inZone: "*", port: portOpt.get()))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc collectHostListenPorts(): seq[LxcDnatKey] =
  result.add(collectProcNetListenPorts("/proc/net/tcp", protoTcp, true))
  result.add(collectProcNetListenPorts("/proc/net/tcp6", protoTcp, true))
  result.add(collectProcNetListenPorts("/proc/net/udp", protoUdp, false))
  result.add(collectProcNetListenPorts("/proc/net/udp6", protoUdp, false))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hostListensOn(hostPorts: seq[LxcDnatKey], proto: Protocol, port: uint16): bool =
  for entry in hostPorts:
    if entry.proto == proto and entry.port == port:
      return true

  result = false

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toPlannedRule(path: string, request: LxcDnatRequestFile, rule: LxcDnatRequestRule): LxcDnatPlannedRule =
  result = LxcDnatPlannedRule(
    requestPath: path,
    instance: request.instance,
    name: rule.name,
    inZone: rule.inZone,
    srcAddrs: rule.srcAddrs,
    proto: rule.proto,
    port: rule.port,
    toAddr: rule.toAddr,
    toPort: rule.toPort,
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildLxcDnatSyncPlan*(
    cfg: NormalizedConfig,
    requests: seq[(string, LxcDnatRequestFile)],
    checkHostListenPorts = true,
    checkReservedPorts = true
): AE[LxcDnatSyncPlan] =
  var plan = LxcDnatSyncPlan(rules: @[], warnings: @[])
  var seen = initTable[LxcDnatKey, string]()
  let hostPorts =
    if checkHostListenPorts:
      collectHostListenPorts()
    else:
      @[]

  for pair in requests:
    let path = pair[0]
    let request = pair[1]

    for rule in request.rules:
      let key = requestRuleKey(rule)
      let label = &"{request.instance}:{rule.name}"

      if checkReservedPorts and isReservedPort(rule.proto, rule.port):
        plan.addWarning(path, request.instance, rule, &"reserved host port: {protoText(rule.proto)}/{rule.port}")
        continue

      if seen.hasKey(key):
        plan.addWarning(path, request.instance, rule, &"listen port conflict with {seen[key]}: {keyText(key)}")
        continue

      let staticCollision = existingStaticDnatCollision(cfg, rule)
      if staticCollision.isSome:
        plan.addWarning(path, request.instance, rule, &"listen port conflict with {staticCollision.get()}: {keyText(key)}")
        continue

      if checkHostListenPorts and hostListensOn(hostPorts, rule.proto, rule.port):
        plan.addWarning(path, request.instance, rule, &"host listen port conflict: {protoText(rule.proto)}/{rule.port}")
        continue

      seen[key] = label
      plan.rules.add(toPlannedRule(path, request, rule))

  result = ok(plan)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc emitLxcDnatNft*(cfg: NormalizedConfig, rules: seq[LxcDnatPlannedRule]): AE[string] =
  var outp = ""

  proc addLine(indent: int, line: string) =
    for _ in 0 ..< indent:
      outp.add("\t")
    outp.add(line)
    outp.add("\n")

  addLine(0, &"destroy table {LxcDnatFamily} {LxcDnatTable}")
  addLine(0, &"table {LxcDnatFamily} {LxcDnatTable} {{")
  addLine(1, &"chain {LxcDnatPreroutingChain} {{")
  addLine(2, &"type nat hook prerouting priority {LxcDnatPriority}; policy accept;")
  addLine(2, &"jump {LxcDnatDynamicChain}")
  addLine(1, "}")
  addLine(0, "")
  addLine(1, &"chain {LxcDnatDynamicChain} {{")

  for rule in rules:
    let lines = ?dnatRuleToText(rule, cfg)
    for line in lines:
      addLine(2, line)

  addLine(1, "}")
  addLine(0, "}")

  result = ok(outp)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc ensureParentDir(path: string): AE[void] =
  let dir = parentDir(path)
  if dir.len == 0 or dirExists(dir):
    return okVoid()

  try:
    createDir(dir)
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, &"failed to create directory '{dir}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeRuntimeNft(path: string, nft: string): AE[void] =
  ?ensureParentDir(path).trace("writeRuntimeNft.ensureParentDir")

  try:
    writeFile(path, nft)
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, &"failed to write '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc nowIso8601Utc(): string =
  result = $now()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc statusFilePath(statusDir: string, instance: string): AE[string] =
  if statusDir.len == 0:
    return fail[string](ekInvalid, "status directory must not be empty")

  if not isSafeName(instance):
    return fail[string](ekInvalid, &"unsafe instance name: {instance}")

  result = ok(statusDir / (instance & ".json"))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc statusRuleKey(instance: string, rule: LxcDnatRequestRule): string =
  result = &"{instance}\x00{rule.name}\x00{protoText(rule.proto)}\x00{rule.port}\x00{rule.toAddr}\x00{rule.toPort}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc statusRuleKey(rule: LxcDnatPlannedRule): string =
  result = &"{rule.instance}\x00{rule.name}\x00{protoText(rule.proto)}\x00{rule.port}\x00{rule.toAddr}\x00{rule.toPort}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc statusRuleKey(warning: LxcDnatSyncWarning): string =
  result = &"{warning.instance}\x00{warning.rule}\x00{protoText(warning.proto)}\x00{warning.port}\x00{warning.toAddr}\x00{warning.toPort}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc ruleToStatusNode(rule: LxcDnatRequestRule, status: string, reason = ""): JsonNode =
  result = newJObject()
  result["name"] = %rule.name
  result["in"] = %rule.inZone

  if rule.srcAddrs.len > 0:
    result["src"] = %rule.srcAddrs

  result["service"] = %*{
    "proto": protoText(rule.proto),
    "port": int(rule.port),
  }
  result["to-addr"] = %rule.toAddr
  result["to-port"] = %int(rule.toPort)
  result["status"] = %status

  if reason.len > 0:
    result["reason"] = %reason
  if rule.sourcePath.len > 0:
    result["source-path"] = %rule.sourcePath
  if rule.sourceLine > 0:
    result["source-line"] = %rule.sourceLine

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildLxcDnatStatusNodes*(
    requests: seq[(string, LxcDnatRequestFile)],
    plan: LxcDnatSyncPlan,
    updatedAt = ""
): Table[string, JsonNode] =
  var active = initTable[string, bool]()
  var warnings = initTable[string, LxcDnatSyncWarning]()
  let timestamp =
    if updatedAt.len > 0:
      updatedAt
    else:
      nowIso8601Utc()

  for rule in plan.rules:
    active[statusRuleKey(rule)] = true

  for warning in plan.warnings:
    warnings[statusRuleKey(warning)] = warning

  var statuses = initTable[string, JsonNode]()

  for pair in requests:
    let request = pair[1]
    var node = newJObject()
    var rulesNode = newJArray()
    var activeCount = 0
    var skippedCount = 0

    for rule in request.rules:
      let key = statusRuleKey(request.instance, rule)
      if active.hasKey(key):
        inc(activeCount)
        rulesNode.add(ruleToStatusNode(rule, "active"))
      elif warnings.hasKey(key):
        inc(skippedCount)
        rulesNode.add(ruleToStatusNode(rule, "skipped", warnings[key].reason))
      else:
        inc(skippedCount)
        rulesNode.add(ruleToStatusNode(rule, "skipped", "rule was not selected for synchronization"))

    let status =
      if skippedCount == 0 and activeCount > 0:
        "active"
      elif skippedCount == 0 and activeCount == 0:
        "empty"
      elif activeCount > 0:
        "partial"
      else:
        "error"

    node["instance"] = %request.instance
    node["address"] = %request.address
    node["status"] = %status
    node["updatedAt"] = %timestamp
    node["active"] = %activeCount
    node["skipped"] = %skippedCount
    node["rules"] = rulesNode
    statuses[request.instance] = node

  result = statuses

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeStatusJson(path: string, node: JsonNode): AE[void] =
  try:
    writeFile(path, node.pretty() & "\n")
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, &"failed to write '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeLxcDnatStatusFiles*(
    statusDir: string,
    requests: seq[(string, LxcDnatRequestFile)],
    plan: LxcDnatSyncPlan
): AE[void] =
  ?ensureParentDir(statusDir / ".keep").trace("writeLxcDnatStatusFiles.ensureStatusDir")

  let statuses = buildLxcDnatStatusNodes(requests, plan)
  var expected = initTable[string, bool]()

  for instance, node in statuses:
    let path = ?statusFilePath(statusDir, instance)
    expected[path] = true
    ?writeStatusJson(path, node).trace("writeLxcDnatStatusFiles.writeStatusJson")

  if dirExists(statusDir):
    for kind, path in walkDir(statusDir):
      if kind == pcFile and path.endsWith(".json") and not expected.hasKey(path):
        try:
          removeFile(path)
        except CatchableError as e:
          return failVoid(ekIO, &"failed to remove stale DNAT status file '{path}': {e.msg}")

  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc lxcDnatSyncCommandImpl*(opts: LxcDnatSyncOptions): AE[void] =
  let loaded = ?loadConfig(opts.mainPath, opts.privateDir, opts.servicesPath).trace("lxcDnatSync.loadConfig")
  let normalized = ?normalizeConfig(loaded.config, loaded.services).trace("lxcDnatSync.normalizeConfig")
  let requests = ?loadLxcDnatRequests(opts.requestDir).trace("lxcDnatSync.loadRequests")
  let plan = ?buildLxcDnatSyncPlan(
    normalized,
    requests,
    checkHostListenPorts = not opts.skipHostListenCheck,
    checkReservedPorts = not opts.skipReservedPortCheck
  ).trace("lxcDnatSync.buildPlan")
  let nft = ?emitLxcDnatNft(normalized, plan.rules).trace("lxcDnatSync.emitNft")

  for warning in plan.warnings:
    stderr.writeLine(&"lxc-dnat-sync: warning: {warning.instance}:{warning.rule}: {warning.reason}")

  if opts.dryRun:
    stdout.write(nft)
    return okVoid()

  ?writeRuntimeNft(opts.runtimeNftPath, nft).trace("lxcDnatSync.writeRuntimeNft")

  if opts.checkOnly:
    ?checkNft(opts.runtimeNftPath).trace("lxcDnatSync.checkNft")
  else:
    ?checkThenApplyNft(opts.runtimeNftPath).trace("lxcDnatSync.checkThenApplyNft")
    ?writeLxcDnatStatusFiles(opts.statusDir, requests, plan).trace("lxcDnatSync.writeStatus")

  echo &"lxc-dnat-sync: synced {plan.rules.len} rule(s), skipped {plan.warnings.len} rule(s)"
  result = okVoid()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc logLxcDnatSyncLockWait(path: string) =
  echo "lxc-dnat-sync: another instance is running, waiting for lock: " & path

proc logLxcDnatSyncLockAcquiredAfterWait(path: string) =
  echo "lxc-dnat-sync: acquired lock after waiting: " & path

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc lxcDnatSyncCommand*(opts: LxcDnatSyncOptions): AE[void] =
  result = withProcessLock(
    LxcDnatSyncLockPath,
    proc(): AE[void] =
      result = lxcDnatSyncCommandImpl(opts),
    onWait = logLxcDnatSyncLockWait,
    onAcquiredAfterWait = logLxcDnatSyncLockAcquiredAfterWait
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc defaultLxcDnatSyncOptions*(): LxcDnatSyncOptions =
  result = LxcDnatSyncOptions(
    mainPath: "/etc/awall/main.json",
    privateDir: "/etc/awall/private",
    servicesPath: "/etc/awall/mandatory/services.json",
    requestDir: "/run/lxc/dnat-requests.d",
    runtimeNftPath: DefaultRuntimeNftPath,
    statusDir: DefaultStatusDir,
    checkOnly: false,
    dryRun: false,
    skipHostListenCheck: false,
    skipReservedPortCheck: false,
  )
