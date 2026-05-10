import std/[os, strformat, strutils]

import sunny

import ./errors
import ./merge
import ./services
import ./types
import ./validate

type
  LoadedConfig* = object
    main*: MainDto
    config*: AwallSubsetConfig
    services*: ServiceDb

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc readTextFile(path: string): AE[string] =
  if path.len == 0:
    return fail[string](ekInvalid, "path must not be empty")

  try:
    result = ok(readFile(path))
  except CatchableError as e:
    result = fail[string](ekIO, &"failed to read '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseMainDto*(path: string): AE[MainDto] =
  let text = ?readTextFile(path).trace("parseMainDto.readTextFile")

  try:
    result = ok(MainDto.fromJson(text))
  except CatchableError as e:
    result = fail[MainDto](ekJson, &"failed to parse main JSON '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseConfigDto*(path: string): AE[ConfigDto] =
  let text = ?readTextFile(path).trace("parseConfigDto.readTextFile")

  try:
    result = ok(ConfigDto.fromJson(text))
  except CatchableError as e:
    result = fail[ConfigDto](ekJson, &"failed to parse config JSON '{path}': {e.msg}")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseServiceCatalogDto*(path: string): AE[ServiceCatalogDto] =
  let text = ?readTextFile(path).trace("parseServiceCatalogDto.readTextFile")

  try:
    result = ok(ServiceCatalogDto.fromJson(text))
  except CatchableError as e:
    result = fail[ServiceCatalogDto](
      ekJson,
      &"failed to parse services JSON '{path}': {e.msg}"
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc importPath(privateDir: string, importName: string): AE[string] =
  if importName.len == 0:
    return fail[string](ekInvalid, "import name must not be empty")

  if importName.contains(DirSep) or importName.contains(AltSep):
    return fail[string](
      ekUnsupported,
      "nested import paths are not supported: " & importName
    )

  if importName.endsWith(".json"):
    result = ok(privateDir / importName)
    return

  result = ok(privateDir / (importName & ".json"))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc loadImportedConfigs*(
    main: MainDto,
    privateDir: string
): AE[AwallSubsetConfig] =
  var merged = initAwallSubsetConfig()

  for importName in main.imports:
    let path = ?importPath(privateDir, importName).trace("loadImportedConfigs.importPath")
    let dto = ?parseConfigDto(path).trace("loadImportedConfigs.parseConfigDto")
    ?mergeInto(merged, dto).trace("loadImportedConfigs.mergeInto")

  ?validateConfig(merged).trace("loadImportedConfigs.validateConfig")

  result = ok(merged)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc defaultServicePaths*(
    servicesPath: string,
    privateDir: string
): seq[string] =
  var paths: seq[string] = @[]

  proc addUnique(path: string) =
    if path.len == 0:
      return

    if path notin paths:
      paths.add(path)

  addUnique(servicesPath)
  addUnique("/etc/awall/mandatory/services.json")
  addUnique(privateDir / "services.json")

  result = paths

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc loadServiceDb*(
    servicesPath: string,
    privateDir: string
): AE[ServiceDb] =
  let paths = defaultServicePaths(servicesPath, privateDir)
  var db = initTable[ServiceName, seq[ServiceAtom]]()
  var loadedCount = 0

  for path in paths:
    if not fileExists(path):
      continue

    let catalog = ?parseServiceCatalogDto(path).trace("loadServiceDb.parseServiceCatalogDto")
    let sourceDb = ?buildServiceDb(catalog).trace("loadServiceDb.buildServiceDb")
    mergeServiceDb(db, sourceDb)
    inc(loadedCount)

  if loadedCount == 0:
    return fail[ServiceDb](
      ekIO,
      &"no services.json found; checked {serviceDbSourceSummary(paths)}"
    )

  result = ok(db)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc loadConfig*(
    mainPath: string,
    privateDir: string,
    servicesPath: string
): AE[LoadedConfig] =
  let main = ?parseMainDto(mainPath).trace("loadConfig.parseMainDto")
  let cfg = ?loadImportedConfigs(main, privateDir).trace("loadConfig.loadImportedConfigs")
  let serviceDb = ?loadServiceDb(servicesPath, privateDir).trace("loadConfig.loadServiceDb")

  result = ok(LoadedConfig(
    main: main,
    config: cfg,
    services: serviceDb,
  ))
