import std/strformat
import results
export results

type
  ErrKind* = enum
    ekSuccess = "Succeeded"
    ekIO = "IO Error"
    ekJson = "JSON Error"
    ekParse = "Parse Error"
    ekValidate = "Validation Error"
    ekNormalize = "Normalize Error"
    ekEmit = "Emit Error"
    ekInvalid = "Invalid Argument"
    ekUnsupported = "Unsupported"
    ekNotFound = "Not Found"
    ekUnknownZone = "Unknown Zone"
    ekUnknownService = "Unknown Service"
    ekUnknownProtocol = "Unknown Protocol"
    ekUnknownFamily = "Unknown Family"
    ekInvalidPort = "Invalid Port"
    ekInvalidInterface = "Invalid Interface"
    ekInvalidRule = "Invalid Rule"
    ekType = "Type Error"
    ekLength = "Length Error"
    ekOther = "Other Error"

  Error* = ref object
    kind*: ErrKind
    msg*: string
    #trace*: seq[string]

  AE*[T] = Result[T, Error]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(err: Error): string =
  if err.isNil:
    result = "Error: nil"
  else:
    result = &"Error: {err.kind}: {err.msg}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc makeError*(kind: ErrKind, msg: string): Error =
  result = Error(kind: kind, msg: msg)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc withTrace(err: Error, where: static[string]): Error {.inline.} =
  result = err
  #result.trace.add(where)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc trace*[T](res: AE[T], where: static[string]): AE[T] {.inline.} =
  if res.isErr:
    result = err(res.error.withTrace(where))
  else:
    result = res

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc errKind*[T](res: AE[T]): ErrKind =
  if res.isErr:
    result = res.error.kind
  else:
    result = ekSuccess

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc errMsg*[T](res: AE[T]): string =
  if res.isErr:
    result = res.error.msg
  else:
    result = "No Error"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc okVoid*(): AE[void] =
  result = ok()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fail*[T](kind: ErrKind, msg: string): AE[T] =
  result = err(makeError(kind, msg))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc failVoid*(kind: ErrKind, msg: string): AE[void] =
  result = err(makeError(kind, msg))
