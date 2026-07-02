import std/[json, os, strformat, strutils]

import ./errors
import ./lxc_dnat_decl
import ./types

proc cRename(oldpath: cstring, newpath: cstring): cint {.importc: "rename", header: "<stdio.h>".}

type
  LxcDnatRequestRule* = object
    ## One runtime DNAT request generated from /etc/lxc-dnat.d/*.conf.
    ##
    ## This is a host-side intermediate format. Unlike the container-side
    ## declaration, the target address is already resolved to the running
    ## instance address.
    name*: string
    inZone*: string
    srcAddrs*: seq[string]
    proto*: Protocol
    port*: uint16
    toAddr*: string
    toPort*: uint16
    sourcePath*: string
    sourceLine*: int

  LxcDnatRequestFile* = object
    instance*: string
    address*: string
    rules*: seq[LxcDnatRequestRule]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isSafeName*(name: string): bool =
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
proc requestFilePath*(requestDir: string, instance: string): AE[string] =
  if requestDir.len == 0:
    return fail[string](ekInvalid, "request directory must not be empty")

  if not isSafeName(instance):
    return fail[string](ekInvalid, &"unsafe instance name: {instance}")

  result = ok(requestDir / (instance & ".json"))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc buildLxcDnatRequest*(
    instance: string,
    address: string,
    declFiles: openArray[LxcDnatDeclFile]
): AE[LxcDnatRequestFile] =
  if not isSafeName(instance):
    return fail[LxcDnatRequestFile](ekInvalid, &"unsafe instance name: {instance}")

  if address.strip.len == 0:
    return fail[LxcDnatRequestFile](ekInvalid, "instance address must not be empty")

  var request = LxcDnatRequestFile(
    instance: instance,
    address: address.strip,
    rules: @[],
  )

  for declFile in declFiles:
    for rule in declFile.rules:
      if not rule.enabled:
        continue

      request.rules.add(LxcDnatRequestRule(
        name: rule.name,
        inZone: rule.inZone,
        srcAddrs: rule.srcAddrs,
        proto: rule.proto,
        port: rule.port,
        toAddr: request.address,
        toPort: rule.toPort,
        sourcePath: rule.sourcePath,
        sourceLine: rule.line,
      ))

  result = ok(request)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJsonNode*(rule: LxcDnatRequestRule): JsonNode =
  var node = newJObject()

  node["name"] = %rule.name
  node["in"] = %rule.inZone

  if rule.srcAddrs.len > 0:
    node["src"] = %rule.srcAddrs

  node["service"] = %*{
    "proto": $rule.proto,
    "port": int(rule.port),
  }
  node["to-addr"] = %rule.toAddr
  node["to-port"] = %int(rule.toPort)

  if rule.sourcePath.len > 0:
    node["source-path"] = %rule.sourcePath
  if rule.sourceLine > 0:
    node["source-line"] = %rule.sourceLine

  result = node

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJsonNode*(request: LxcDnatRequestFile): JsonNode =
  var node = newJObject()
  var dnat = newJArray()

  for rule in request.rules:
    dnat.add(rule.toJsonNode())

  node["instance"] = %request.instance
  node["address"] = %request.address
  node["dnat"] = dnat

  result = node

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJsonText*(request: LxcDnatRequestFile): string =
  result = request.toJsonNode().pretty()
  result.add("\n")

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
proc writeTextFile(path: string, text: string): AE[void] =
  try:
    writeFile(path, text)
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, &"failed to write '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc writeLxcDnatRequest*(
    request: LxcDnatRequestFile,
    requestDir: string,
    stagingDir: string
): AE[string] =
  let dest = ?requestFilePath(requestDir, request.instance)
  let tmpName = request.instance & ".json.tmp." & $getCurrentProcessId()
  let tmp = stagingDir / tmpName

  ?ensureDir(requestDir).trace("writeLxcDnatRequest.ensureRequestDir")
  ?ensureDir(stagingDir).trace("writeLxcDnatRequest.ensureStagingDir")
  ?writeTextFile(tmp, request.toJsonText()).trace("writeLxcDnatRequest.writeTmp")

  if cRename(tmp.cstring, dest.cstring) == 0:
    return ok(dest)

  let errMsg = osErrorMsg(osLastError())
  try:
    if fileExists(tmp):
      removeFile(tmp)
  except CatchableError:
    discard

  result = fail[string](ekIO, &"failed to install '{dest}': {errMsg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc removeLxcDnatRequest*(requestDir: string, instance: string): AE[bool] =
  let path = ?requestFilePath(requestDir, instance)

  try:
    if fileExists(path):
      removeFile(path)
      result = ok(true)
    else:
      result = ok(false)
  except CatchableError as e:
    result = fail[bool](ekIO, &"failed to remove '{path}': {e.msg}")
