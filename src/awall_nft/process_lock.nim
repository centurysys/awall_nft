import std/os
import ./errors

const
  OpenReadWrite = 0o2.cint
  OpenCreate = 0o100.cint
  OpenCloseOnExec = 0o2000000.cint
  LockExclusive = 2.cint
  LockNonblock = 4.cint
  LockUnlock = 8.cint

type
  LockWaitCallback* = proc(path: string) {.closure.}
  LockAcquiredAfterWaitCallback* = proc(path: string) {.closure.}

proc cOpen(path: cstring, flags: cint, mode: cint): cint {.importc: "open", header: "<fcntl.h>".}
proc cClose(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
proc cFlock(fd: cint, operation: cint): cint {.importc: "flock", header: "<sys/file.h>".}

proc currentOsErrorMessage(): string =
  result = $osErrorMsg(osLastError())

proc join5(a: string, b: string, c: string, d: string, e: string): string =
  result = newStringOfCap(a.len + b.len + c.len + d.len + e.len)
  result.add(a)
  result.add(b)
  result.add(c)
  result.add(d)
  result.add(e)

proc ensureLockDir(path: string): AE[void] =
  let dir = parentDir(path)
  if dir.len == 0 or dirExists(dir):
    result = okVoid()
    return

  try:
    createDir(dir)
    result = okVoid()
  except CatchableError as e:
    result = failVoid(ekIO, join5("failed to create lock directory '", dir, "': ", e.msg, ""))

proc withProcessLock*[T](
  path: string,
  body: proc(): AE[T] {.closure.},
  onWait: LockWaitCallback = nil,
  onAcquiredAfterWait: LockAcquiredAfterWaitCallback = nil
): AE[T] =
  ?ensureLockDir(path).trace("withProcessLock.ensureLockDir")

  let fd = cOpen(path.cstring, OpenReadWrite or OpenCreate or OpenCloseOnExec, 0o644.cint)
  if fd < 0:
    let errMsg = currentOsErrorMessage()
    result = fail[T](ekIO, join5("failed to open lock file '", path, "': ", errMsg, ""))
    return

  var locked = false
  try:
    if cFlock(fd, LockExclusive or LockNonblock) == 0:
      locked = true
      result = body()
      return

    if onWait != nil:
      onWait(path)

    if cFlock(fd, LockExclusive) != 0:
      let errMsg = currentOsErrorMessage()
      result = fail[T](ekIO, join5("failed to lock '", path, "': ", errMsg, ""))
      return

    locked = true

    if onAcquiredAfterWait != nil:
      onAcquiredAfterWait(path)

    result = body()
  finally:
    if locked:
      discard cFlock(fd, LockUnlock)
    discard cClose(fd)
