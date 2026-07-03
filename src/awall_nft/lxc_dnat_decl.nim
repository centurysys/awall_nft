import std/[algorithm, options, os, strformat, strutils, tables]

import ./errors
import ./lxc_dnat_zones
import ./types

type
  LxcDnatDeclRule* = object
    ## One section in /etc/lxc-dnat.d/*.conf.
    ##
    ## This is a human-facing declaration. The DNAT target address is not part
    ## of this data; lxc-dnat-helper must fill it from the running instance.
    name*: string
    inZone*: string
    srcAddrs*: seq[string]
    proto*: Protocol
    port*: uint16
    toPort*: uint16
    enabled*: bool
    sourcePath*: string
    line*: int

  LxcDnatDeclFile* = object
    path*: string
    rules*: seq[LxcDnatDeclRule]

  LxcDnatSection = object
    name: string
    line: int
    values: Table[string, string]
    valueLines: Table[string, int]

const
  AllowedKeys = ["in", "src", "proto", "port", "to-port", "enabled"]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isValidRuleName(name: string): bool =
  if name.len == 0:
    return false

  for ch in name:
    if ch in {'a'..'z'} or
       ch in {'A'..'Z'} or
       ch in {'0'..'9'} or
       ch in {'_', '-', '.'}:
      continue

    return false

  result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc where(path: string, line: int): string =
  if path.len == 0:
    result = &"line {line}"
  else:
    result = &"{path}:{line}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseBool(value: string, path: string, line: int): AE[bool] =
  let normalized = value.strip().toLowerAscii()

  case normalized
  of "true":
    result = ok(true)
  of "false":
    result = ok(false)
  else:
    result = fail[bool](
      ekParse,
      &"{where(path, line)}: enabled must be true or false"
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parsePort(value: string, key: string, path: string, line: int): AE[uint16] =
  let text = value.strip()

  if text.len == 0:
    return fail[uint16](ekInvalidPort, &"{where(path, line)}: {key} must not be empty")

  var port: int

  try:
    port = parseInt(text)
  except ValueError:
    return fail[uint16](ekInvalidPort, &"{where(path, line)}: invalid {key}: {text}")

  if port < 1 or port > 65535:
    return fail[uint16](
      ekInvalidPort,
      &"{where(path, line)}: {key} must be in range 1..65535"
    )

  result = ok(uint16(port))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseProto(value: string, path: string, line: int): AE[Protocol] =
  let normalized = value.strip().toLowerAscii()

  case normalized
  of "tcp":
    result = ok(protoTcp)
  of "udp":
    result = ok(protoUdp)
  else:
    result = fail[Protocol](
      ekUnknownProtocol,
      &"{where(path, line)}: proto must be tcp or udp"
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc splitList(value: string, path: string, line: int, key: string): AE[seq[string]] =
  let text = value.strip()

  if text.len == 0:
    return ok(newSeq[string]())

  var items: seq[string] = @[]

  for rawItem in text.split(','):
    let item = rawItem.strip()

    if item.len == 0:
      return fail[seq[string]](
        ekParse,
        &"{where(path, line)}: {key} contains an empty item"
      )

    items.add(item)

  result = ok(items)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc requireValue(
    section: LxcDnatSection,
    key: string,
    path: string
): AE[string] =
  if section.values.hasKey(key):
    result = ok(section.values[key])
    return

  result = fail[string](
    ekInvalidRule,
    &"{where(path, section.line)}: section [{section.name}] requires '{key}'"
  )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc valueLine(section: LxcDnatSection, key: string): int =
  if section.valueLines.hasKey(key):
    result = section.valueLines[key]
  else:
    result = section.line

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseSection(section: LxcDnatSection, path: string): AE[LxcDnatDeclRule] =
  var rule = LxcDnatDeclRule(
    name: section.name,
    enabled: true,
    sourcePath: path,
    line: section.line,
  )

  if section.values.hasKey("enabled"):
    rule.enabled = ?parseBool(
      section.values["enabled"],
      path,
      section.valueLine("enabled")
    )

  if not rule.enabled:
    if section.values.hasKey("in"):
      rule.inZone = section.values["in"].strip()
    if section.values.hasKey("src"):
      rule.srcAddrs = ?splitList(
        section.values["src"],
        path,
        section.valueLine("src"),
        "src"
      )
    if section.values.hasKey("proto"):
      rule.proto = ?parseProto(
        section.values["proto"],
        path,
        section.valueLine("proto")
      )
    if section.values.hasKey("port"):
      rule.port = ?parsePort(
        section.values["port"],
        "port",
        path,
        section.valueLine("port")
      )
    if section.values.hasKey("to-port"):
      rule.toPort = ?parsePort(
        section.values["to-port"],
        "to-port",
        path,
        section.valueLine("to-port")
      )

    result = ok(rule)
    return

  rule.inZone = ?normalizeRawLxcDnatInZone(
    ?requireValue(section, "in", path),
    where(path, section.valueLine("in"))
  )

  if section.values.hasKey("src"):
    rule.srcAddrs = ?splitList(
      section.values["src"],
      path,
      section.valueLine("src"),
      "src"
    )

  rule.proto = ?parseProto(
    ?requireValue(section, "proto", path),
    path,
    section.valueLine("proto")
  )
  rule.port = ?parsePort(
    ?requireValue(section, "port", path),
    "port",
    path,
    section.valueLine("port")
  )
  rule.toPort = ?parsePort(
    ?requireValue(section, "to-port", path),
    "to-port",
    path,
    section.valueLine("to-port")
  )

  result = ok(rule)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseLxcDnatDeclText*(text: string, path = ""): AE[LxcDnatDeclFile] =
  var sections: seq[LxcDnatSection] = @[]
  var current: Option[LxcDnatSection] = none(LxcDnatSection)
  var seenSections = initTable[string, int]()
  var lineNo = 0

  proc finishCurrent(): AE[void] =
    if current.isSome:
      sections.add(current.get())
      current = none(LxcDnatSection)

    result = okVoid()

  for rawLine in text.splitLines():
    inc(lineNo)

    let line = rawLine.strip()

    if line.len == 0:
      continue

    if line.startsWith("#") or line.startsWith(";"):
      continue

    if line.startsWith("["):
      if not line.endsWith("]"):
        return fail[LxcDnatDeclFile](
          ekParse,
          &"{where(path, lineNo)}: invalid section header"
        )

      ?finishCurrent()

      let name =
        if line.len <= 2:
          ""
        else:
          line[1 .. ^2].strip()

      if not isValidRuleName(name):
        return fail[LxcDnatDeclFile](
          ekInvalidRule,
          &"{where(path, lineNo)}: invalid section name '{name}'"
        )

      if seenSections.hasKey(name):
        return fail[LxcDnatDeclFile](
          ekInvalidRule,
          &"{where(path, lineNo)}: duplicate section [{name}] first defined at line {seenSections[name]}"
        )

      seenSections[name] = lineNo
      current = some(LxcDnatSection(
        name: name,
        line: lineNo,
        values: initTable[string, string](),
        valueLines: initTable[string, int](),
      ))
      continue

    if current.isNone:
      return fail[LxcDnatDeclFile](
        ekParse,
        &"{where(path, lineNo)}: key-value line appears before any section"
      )

    let eqPos = line.find('=')

    if eqPos < 0:
      return fail[LxcDnatDeclFile](
        ekParse,
        &"{where(path, lineNo)}: expected 'key = value'"
      )

    let key = line[0 ..< eqPos].strip().toLowerAscii()
    let value =
      if eqPos == line.high:
        ""
      else:
        line[eqPos + 1 .. ^1].strip()

    if key.len == 0:
      return fail[LxcDnatDeclFile](ekParse, &"{where(path, lineNo)}: key must not be empty")

    if key notin AllowedKeys:
      return fail[LxcDnatDeclFile](
        ekInvalidRule,
        &"{where(path, lineNo)}: unknown key '{key}'"
      )

    var section = current.get()

    if section.values.hasKey(key):
      return fail[LxcDnatDeclFile](
        ekInvalidRule,
        &"{where(path, lineNo)}: duplicate key '{key}' in section [{section.name}]"
      )

    section.values[key] = value
    section.valueLines[key] = lineNo
    current = some(section)

  ?finishCurrent()

  var decl = LxcDnatDeclFile(path: path, rules: @[])

  for section in sections:
    decl.rules.add(?parseSection(section, path))

  result = ok(decl)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseLxcDnatDeclFile*(path: string): AE[LxcDnatDeclFile] =
  if path.len == 0:
    return fail[LxcDnatDeclFile](ekInvalid, "path must not be empty")

  try:
    let text = readFile(path)
    result = parseLxcDnatDeclText(text, path)
  except CatchableError as e:
    result = fail[LxcDnatDeclFile](ekIO, &"failed to read '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseLxcDnatDeclDir*(dir: string): AE[seq[LxcDnatDeclFile]] =
  if dir.len == 0:
    return fail[seq[LxcDnatDeclFile]](ekInvalid, "directory path must not be empty")

  if not dirExists(dir):
    return ok(newSeq[LxcDnatDeclFile]())

  var paths: seq[string] = @[]

  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".conf"):
      paths.add(path)

  paths.sort()

  var files: seq[LxcDnatDeclFile] = @[]

  for path in paths:
    files.add(?parseLxcDnatDeclFile(path))

  result = ok(files)
