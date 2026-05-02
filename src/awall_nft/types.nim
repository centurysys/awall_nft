import std/[hashes, options, sets, strutils, tables]
export options, sets, tables

import sunny

type
  Family* = enum
    famAny = ""
    famInet = "inet"
    famInet6 = "inet6"

  Protocol* = enum
    protoTcp = "tcp"
    protoUdp = "udp"
    protoIcmp = "icmp"
    protoIcmpv6 = "icmpv6"
    protoEsp = "esp"
    protoGre = "gre"
    protoOspf = "ospf"
    protoIgmp = "igmp"

  Action* = enum
    actAccept = "accept"
    actDrop = "drop"
    actReject = "reject"

  NatAction* = enum
    natInclude = "include"
    natExclude = "exclude"

  ZoneName* = distinct string
  ServiceName* = distinct string
  InterfaceName* = distinct string
  IpAddress* = distinct string

  PortList* = object
    items*: seq[uint16]

  ZoneList* = object
    ## DTO-only helper.
    ##
    ## Keep this as string instead of ZoneName to avoid Sunny hook ambiguity with
    ## distinct string types.
    items*: seq[string]

  InterfaceList* = object
    ## DTO-only helper.
    ##
    ## Keep this as string instead of InterfaceName to avoid Sunny hook ambiguity
    ## with distinct string types.
    items*: seq[string]

  ServiceAtom* = object
    family* {.json: ",omitempty".}: Family
    proto* {.json: ",required".}: Protocol
    port* {.json: ",omitempty".}: PortList
    `type`* {.json: "type,omitempty".}: int
    replyType* {.json: "reply-type,omitempty".}: int
    ctHelper* {.json: "ct-helper,omitempty".}: string

  ServiceEntries* = object
    items*: seq[ServiceAtom]

  ServiceSpecKind* = enum
    sskNone
    sskName
    sskInline

  ServiceSpec* = object
    ## DTO-compatible service spec.
    ##
    ## For service name, keep the value as string. It is converted to
    ## ServiceName when ConfigDto is merged into AwallSubsetConfig.
    case kind*: ServiceSpecKind
    of sskNone:
      discard
    of sskName:
      name*: string
    of sskInline:
      atoms*: seq[ServiceAtom]

  ConnLimit* = object
    count* {.json: ",required".}: uint32
    interval* {.json: ",required".}: uint32

  ZoneDto* = object
    iface* {.json: ",required".}: InterfaceList

  PolicyDto* = object
    inZones* {.json: "in,omitempty".}: ZoneList
    outZones* {.json: "out,omitempty".}: ZoneList
    action* {.json: ",required".}: Action

  FilterDto* = object
    inZones* {.json: "in,omitempty".}: ZoneList
    outZones* {.json: "out,omitempty".}: ZoneList
    service* {.json: ",omitempty".}: ServiceSpec
    action* {.json: ",required".}: Action
    connLimit* {.json: "conn-limit,omitempty".}: Option[ConnLimit]

  DnatDto* = object
    inZones* {.json: "in,omitempty".}: ZoneList
    service* {.json: ",required".}: ServiceSpec
    toAddr* {.json: "to-addr,required".}: string
    toPort* {.json: "to-port,omitempty".}: Option[uint16]

  SnatDto* = object
    outZones* {.json: "out,required".}: ZoneList
    toAddr* {.json: "to-addr,omitempty".}: string
    toPort* {.json: "to-port,omitempty".}: Option[uint16]
    action* {.json: ",omitempty".}: NatAction
    service* {.json: ",omitempty".}: ServiceSpec

  ClampMssDto* = object
    outZones* {.json: "out,required".}: ZoneList

  FlowtableDto* = object
    ## awall_nft extension.
    ##
    ## This is not an awall permission rule. It only marks explicit zone-to-zone
    ## forward directions that may be accelerated through nftables flowtable.
    inZones* {.json: "in,required".}: ZoneList
    outZones* {.json: "out,required".}: ZoneList

  ConfigDto* = object
    description* {.json: ",omitempty".}: string
    zone* {.json: ",omitempty".}: Table[string, ZoneDto]
    policy* {.json: ",omitempty".}: seq[PolicyDto]
    filter* {.json: ",omitempty".}: seq[FilterDto]
    dnat* {.json: ",omitempty".}: seq[DnatDto]
    snat* {.json: ",omitempty".}: seq[SnatDto]
    clampMss* {.json: "clamp-mss,omitempty".}: seq[ClampMssDto]
    flowtable* {.json: ",omitempty".}: seq[FlowtableDto]

  MainDto* = object
    description* {.json: ",omitempty".}: string
    imports* {.json: "import,required".}: seq[string]

  ServiceCatalogDto* = object
    before* {.json: ",omitempty".}: string
    service* {.json: ",required".}: Table[string, ServiceEntries]

  ZoneConfig* = object
    ifaces*: HashSet[InterfaceName]

  PolicyRule* = object
    inZones*: seq[ZoneName]
    outZones*: seq[ZoneName]
    action*: Action

  FilterRule* = object
    inZones*: seq[ZoneName]
    outZones*: seq[ZoneName]
    service*: ServiceSpec
    action*: Action
    connLimit*: Option[ConnLimit]

  DnatRule* = object
    inZones*: seq[ZoneName]
    service*: ServiceSpec
    toAddr*: IpAddress
    toPort*: Option[uint16]

  SnatRule* = object
    outZones*: seq[ZoneName]
    toAddr*: Option[IpAddress]
    toPort*: Option[uint16]
    action*: NatAction
    service*: ServiceSpec

  ClampMssRule* = object
    outZones*: seq[ZoneName]

  FlowtableRule* = object
    ## awall_nft extension.
    ##
    ## Flowtable rules are optimization hints, not firewall permissions.
    ## The normal policy/filter/DNAT rules must still allow the traffic.
    inZones*: seq[ZoneName]
    outZones*: seq[ZoneName]

  AwallSubsetConfig* = object
    descriptions*: seq[string]
    zones*: Table[ZoneName, ZoneConfig]
    policies*: seq[PolicyRule]
    filters*: seq[FilterRule]
    dnats*: seq[DnatRule]
    snats*: seq[SnatRule]
    clampMssRules*: seq[ClampMssRule]
    flowtableRules*: seq[FlowtableRule]

  ServiceDb* = Table[ServiceName, seq[ServiceAtom]]

  IfaceMatchKind* = enum
    imkExact
    imkPrefix

  IfaceMatch* = object
    case kind*: IfaceMatchKind
    of imkExact:
      name*: InterfaceName
    of imkPrefix:
      prefix*: string

  ZoneRuntime* = object
    name*: ZoneName
    exactIfaces*: seq[InterfaceName]
    prefixIfaces*: seq[string]

  NormalizedServiceMatch* = object
    family*: Family
    proto*: Protocol
    ports*: seq[uint16]
    icmpType*: Option[int]
    icmpReplyType*: Option[int]
    ctHelper*: Option[string]

  NormalizedFilterRule* = object
    inZones*: seq[ZoneName]
    outZones*: seq[ZoneName]
    matches*: seq[NormalizedServiceMatch]
    action*: Action
    connLimit*: Option[ConnLimit]

  NormalizedDnatRule* = object
    inZones*: seq[ZoneName]
    matches*: seq[NormalizedServiceMatch]
    toAddr*: IpAddress
    toPort*: Option[uint16]

  NormalizedFlowtableRule* = object
    inZones*: seq[ZoneName]
    outZones*: seq[ZoneName]

  NormalizedConfig* = object
    zones*: Table[ZoneName, ZoneRuntime]
    policies*: seq[PolicyRule]
    filters*: seq[NormalizedFilterRule]
    dnats*: seq[NormalizedDnatRule]
    snats*: seq[SnatRule]
    clampMssRules*: seq[ClampMssRule]
    flowtableRules*: seq[NormalizedFlowtableRule]

const
  ZoneFirewall* = ZoneName("_fw")
  ZoneLan* = ZoneName("LAN")
  ZoneWan* = ZoneName("WAN")
  ZoneClosed* = ZoneName("Closed")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(z: ZoneName): string =
  result = string(z)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(s: ServiceName): string =
  result = string(s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(i: InterfaceName): string =
  result = string(i)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(ip: IpAddress): string =
  result = string(ip)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `==`*(a, b: ZoneName): bool =
  result = string(a) == string(b)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `==`*(a, b: ServiceName): bool =
  result = string(a) == string(b)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `==`*(a, b: InterfaceName): bool =
  result = string(a) == string(b)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `==`*(a, b: IpAddress): bool =
  result = string(a) == string(b)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hash*(z: ZoneName): Hash =
  result = hash(string(z))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hash*(s: ServiceName): Hash =
  result = hash(string(s))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hash*(i: InterfaceName): Hash =
  result = hash(string(i))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hash*(ip: IpAddress): Hash =
  result = hash(string(ip))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toZoneName*(s: string): ZoneName =
  result = ZoneName(s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toServiceName*(s: string): ServiceName =
  result = ServiceName(s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toInterfaceName*(s: string): InterfaceName =
  result = InterfaceName(s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toIpAddress*(s: string): IpAddress =
  result = IpAddress(s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var Family, value: JsonValue, input: string) =
  var s: string
  sunny.fromJson(s, value, input)

  if s.len == 0:
    v = famAny
    return

  try:
    v = parseEnum[Family](s)
  except ValueError:
    raise newException(CatchableError, "Unknown family: " & s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: Family, s: var string) =
  sunny.toJson($src, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var Protocol, value: JsonValue, input: string) =
  var s: string
  sunny.fromJson(s, value, input)

  try:
    v = parseEnum[Protocol](s)
  except ValueError:
    raise newException(CatchableError, "Unknown protocol: " & s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: Protocol, s: var string) =
  sunny.toJson($src, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var Action, value: JsonValue, input: string) =
  var s: string
  sunny.fromJson(s, value, input)

  try:
    v = parseEnum[Action](s)
  except ValueError:
    raise newException(CatchableError, "Unknown action: " & s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: Action, s: var string) =
  sunny.toJson($src, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var NatAction, value: JsonValue, input: string) =
  var s: string
  sunny.fromJson(s, value, input)

  if s.len == 0:
    v = natInclude
    return

  try:
    v = parseEnum[NatAction](s)
  except ValueError:
    raise newException(CatchableError, "Unknown NAT action: " & s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: NatAction, s: var string) =
  sunny.toJson($src, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var PortList, value: JsonValue, input: string) =
  case value.kind
  of NullValue:
    v.items.setLen(0)

  of NumberValue:
    var port: uint16
    sunny.fromJson(port, value, input)
    v.items = @[port]

  of ArrayValue:
    sunny.fromJson(v.items, value, input)

  else:
    raise newException(
      CatchableError,
      "Expected port to be a number or array at " & $value.start &
        ", got " & $value.kind
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: PortList, s: var string) =
  if src.items.len == 1:
    sunny.toJson(src.items[0], s)
    return

  sunny.toJson(src.items, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var ZoneList, value: JsonValue, input: string) =
  case value.kind
  of NullValue:
    v.items.setLen(0)

  of StringValue:
    var zone: string
    sunny.fromJson(zone, value, input)
    v.items = @[zone]

  of ArrayValue:
    sunny.fromJson(v.items, value, input)

  else:
    raise newException(
      CatchableError,
      "Expected zone to be a string or array at " & $value.start &
        ", got " & $value.kind
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: ZoneList, s: var string) =
  if src.items.len == 1:
    sunny.toJson(src.items[0], s)
    return

  sunny.toJson(src.items, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var InterfaceList, value: JsonValue, input: string) =
  case value.kind
  of NullValue:
    v.items.setLen(0)

  of StringValue:
    var iface: string
    sunny.fromJson(iface, value, input)
    v.items = @[iface]

  of ArrayValue:
    sunny.fromJson(v.items, value, input)

  else:
    raise newException(
      CatchableError,
      "Expected interface to be a string or array at " & $value.start &
        ", got " & $value.kind
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: InterfaceList, s: var string) =
  if src.items.len == 1:
    sunny.toJson(src.items[0], s)
    return

  sunny.toJson(src.items, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var ServiceEntries, value: JsonValue, input: string) =
  case value.kind
  of NullValue:
    v.items.setLen(0)

  of ObjectValue:
    var atom: ServiceAtom
    sunny.fromJson(atom, value, input)
    v.items = @[atom]

  of ArrayValue:
    sunny.fromJson(v.items, value, input)

  else:
    raise newException(
      CatchableError,
      "Expected service definition to be an object or array at " &
        $value.start & ", got " & $value.kind
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: ServiceEntries, s: var string) =
  if src.items.len == 1:
    sunny.toJson(src.items[0], s)
    return

  sunny.toJson(src.items, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc fromJson*(v: var ServiceSpec, value: JsonValue, input: string) =
  case value.kind
  of NullValue:
    v = ServiceSpec(kind: sskNone)

  of StringValue:
    var name: string
    sunny.fromJson(name, value, input)
    v = ServiceSpec(kind: sskName, name: name)

  of ObjectValue:
    var atom: ServiceAtom
    sunny.fromJson(atom, value, input)
    v = ServiceSpec(kind: sskInline, atoms: @[atom])

  of ArrayValue:
    var atoms: seq[ServiceAtom]
    sunny.fromJson(atoms, value, input)
    v = ServiceSpec(kind: sskInline, atoms: atoms)

  else:
    raise newException(
      CatchableError,
      "Expected service to be a string, object, or array at " &
        $value.start & ", got " & $value.kind
    )

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toJson*(src: ServiceSpec, s: var string) =
  case src.kind
  of sskNone:
    sunny.toJson("", s)

  of sskName:
    sunny.toJson(src.name, s)

  of sskInline:
    if src.atoms.len == 1:
      sunny.toJson(src.atoms[0], s)
      return

    sunny.toJson(src.atoms, s)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc initAwallSubsetConfig*(): AwallSubsetConfig =
  result.descriptions = @[]
  result.zones = initTable[ZoneName, ZoneConfig]()
  result.policies = @[]
  result.filters = @[]
  result.dnats = @[]
  result.snats = @[]
  result.clampMssRules = @[]
  result.flowtableRules = @[]
