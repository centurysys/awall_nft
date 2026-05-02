# awall-nft

`awall-nft` は、Alpine Wall (awall) 風の小さな実用subset JSON設定を、
native nftables ruleset へ変換する軽量generatorです。

iptables/nftablesを直接書くと事故りやすく、一方でFirewallDのような大きな
firewall manager は組み込みLinux機器には重い、という用途を想定しています。

このプロジェクトは awall の完全再実装ではありません。現行製品で使っている
実用範囲に絞っています。

- zone
- base policy
- filter
- DNAT
- SNAT masquerade
- TCP MSS clamp
- service定義
- SSH向けのような接続頻度制限

生成したrulesetは、適用前に `nft -c -f` でチェックできます。

## 背景

既存システムでは、WebUIがawall風JSONを生成し、awallがiptablesルールを
生成・適用していました。

この方式は実用上うまく動いていましたが、iptablesは徐々にlegacyになりつつ
あります。また、awall自体はnative nftables rulesetを直接生成する仕組みでは
ありません。

一方でnftablesを直書きすると、次のような事故が起きやすくなります。

- hookやpriorityを間違える
- `input`, `forward`, `output` の対応を間違える
- NATとfilterの関係を忘れる
- 意図しないinterfaceを許可してしまう
- IPv4/IPv6の片方だけ穴が開く
- インターネット側のdropログが大量に出る

`awall-nft` は、小さな宣言的JSONモデルを維持しつつ、native nftables ruleset
を直接生成します。

## 設計方針

- 設定モデルを小さく保つ
- JSON設定を唯一の正とする
- iptablesではなくnative nftablesを生成する
- 適用前に必ず検証できるようにする
- 安全側に倒す
  - `input`, `forward`, `output` は `policy drop`
  - 明示的にzoneへ登録されたinterfaceだけを許可対象にする
  - 未定義interfaceは信用しない
- インターネット向けdropでログを溢れさせない
- 組み込みLinuxでも使いやすい軽量実装にする

## 現在の状態

現在の実装では、次の処理ができます。

- `sunny` による awall風JSONのparse
- `optional/main.json` の import list 読み込み
- `base`, `zone`, `filter`, `dnat`, `snat` JSONのmerge
- awall service定義の読み込み
- merge後設定のvalidate
- `ssh`, `dns`, `rdp` などのservice名解決
- `br+`, `wg+` のようなinterface prefix表現のnormalize
- nftables ruleset生成
- `nft -c -f` による生成rulesetのcheck
- check済みrulesetのapply

生成されたnftables rulesetは、実際に `nft -c` を通過するところまで確認済みです。

## 設定ファイル構成

想定するawall風の配置は次の通りです。

```text
/etc/awall/
  optional/
    main.json
  private/
    base.json
    zone.json
    filter.json
    dnat.json
    snat.json
```

典型的な `optional/main.json` は次のような内容です。

```json
{
  "description": "Main firewall",
  "import": [
    "base",
    "zone",
    "filter",
    "dnat",
    "snat"
  ]
}
```

`awall-nft` は `main.json` を読み、`private` ディレクトリからimport対象の
JSONを順に読み込み、merge、validate、service解決、nftables生成を行います。

## 対応しているawall subset

### Zones

例:

```json
{
  "zone": {
    "LAN": {
      "iface": ["ppp100", "br+"]
    },
    "WAN": {
      "iface": ["ppp0", "ppp1", "wlan0", "wwan0"]
    },
    "Closed": {
      "iface": ["eth0", "eth1"]
    }
  }
}
```

`+` で終わるinterface名は、nftablesのprefix matchに変換します。

```text
br+ -> iifname "br*"
wg+ -> iifname "wg*"
```

### Policies

例:

```json
{
  "policy": [
    { "in": "_fw", "out": "WAN", "action": "accept" },
    { "in": "LAN", "action": "accept" },
    { "out": "LAN", "action": "accept" },
    { "in": "WAN", "action": "drop" },
    { "in": "Closed", "action": "accept" },
    { "out": "Closed", "action": "accept" }
  ]
}
```

生成されるnftablesのfilter chainは `policy drop` です。  
その上で、設定されたzone interfaceに対してだけ明示的に許可・拒否ルールを
生成します。

これにより、USB NICなどの予期しないinterfaceが追加されても、自動的には
許可されません。

### Filter rules

例:

```json
{
  "filter": [
    {
      "in": "WAN",
      "out": "_fw",
      "service": "ssh",
      "action": "accept",
      "conn-limit": {
        "count": 3,
        "interval": 20
      }
    }
  ]
}
```

`service` 名は `services.json` により解決されます。

### DNAT

例:

```json
{
  "dnat": [
    {
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 8022
      },
      "to-addr": "192.168.253.5",
      "to-port": 22
    },
    {
      "in": "Closed",
      "service": "rdp",
      "to-addr": "192.168.253.201",
      "to-port": 3389
    }
  ]
}
```

inline service定義と、名前付きserviceの両方に対応しています。

### SNAT / masquerade

現在対応しているSNATは、実用上よく使うmasquerade形式です。

```json
{
  "snat": [
    { "out": ["WAN", "Closed"] }
  ]
}
```

これは、該当zoneのinterfaceに対するnftables `masquerade` として出力されます。

現時点で未対応のもの:

- `to-addr` 付きSNAT
- `to-port` 付きSNAT
- service条件付きSNAT
- `action: exclude`

### TCP MSS clamp

例:

```json
{
  "clamp-mss": [
    { "out": ["WAN", "Closed"] }
  ]
}
```

nftablesのpostrouting mangle hookで次の形に変換します。

```nft
tcp flags syn tcp option maxseg size set rt mtu
```

### Services

service定義は、object形式とarray形式の両方に対応しています。

```json
{
  "service": {
    "ssh": { "proto": "tcp", "port": 22 },
    "dns": [
      { "proto": "udp", "port": 53 },
      { "proto": "tcp", "port": 53 }
    ],
    "ipsec": [
      { "proto": "esp" },
      { "proto": "udp", "port": [500, 4500] }
    ]
  }
}
```

`port` は単一数値でも配列でも読めます。

現在対応しているprotocol:

- `tcp`
- `udp`
- `icmp`
- `icmpv6`
- `esp`
- `gre`
- `ospf`
- `igmp`

### Connection limiting

awall/iptablesでは、次のような `recent` rule に展開されることがあります。

```iptables
-m recent --update --seconds 20 --hitcount 3 --rsource -j logdrop
-m recent --set --rsource -j ACCEPT
```

`awall-nft` では、これをnftablesのmeterベースのルールに変換します。  
drop時のログは出しません。

例えば:

```json
"conn-limit": {
  "count": 3,
  "interval": 20
}
```

の場合、送信元アドレスごとのmeterを使い、rateは `/minute` に変換します。

```text
ceil(count * 60 / interval)
```

つまり、20秒あたり3回は、9/minuteになります。

これはiptables `recent` の完全な挙動コピーではありませんが、SSHスキャン抑制
用途には実用的です。また、ログが大量に出る問題を避けられます。

## 生成されるnftables構造

現在のgeneratorは、次のような構造を生成します。

```text
table inet awall_nft
  chain input
  chain forward
  chain output
  chain postrouting_mangle

table ip awall_nft_nat
  chain prerouting
  chain postrouting
```

filter chainはすべて `policy drop` です。

NAT tableは現時点ではIPv4専用です。現在の用途がIPv4 DNAT/SNAT masquerade
であるためです。

## CLI

### ruleset生成

```sh
awall_nft generate \
  --main /etc/awall/optional/main.json \
  --private-dir /etc/awall/private \
  --services /usr/share/awall/mandatory/services.json \
  -o /tmp/awall_nft.nft
```

default値は次の通りです。

```text
--main        /etc/awall/optional/main.json
--private-dir /etc/awall/private
--services    /usr/share/awall/mandatory/services.json
```

そのため、通常は次のように短くできます。

```sh
awall_nft generate -o /tmp/awall_nft.nft
```

### 生成済みrulesetのcheck

```sh
awall_nft check /tmp/awall_nft.nft
```

内部では次を実行します。

```sh
nft -c -f /tmp/awall_nft.nft
```

### 生成してcheck

```sh
awall_nft build-check -o /tmp/awall_nft.nft
```

### ruleset適用

```sh
awall_nft apply /tmp/awall_nft.nft
```

`apply` はdefaultで事前checkを行います。checkを省略する場合:

```sh
awall_nft apply --no-check /tmp/awall_nft.nft
```

通常運用では `--no-check` は推奨しません。

## Build

```sh
nimble build -d:release
```

ARM向けcross build例:

```sh
nimble build -d:release --cpu:arm
arm-linux-gnueabihf-strip awall_nft
```

## 起動時運用の例

generatorが軽量なので、生成済みfirewall stateを保存・復元するのではなく、
起動時に毎回JSONから生成する運用も現実的です。

例:

```sh
awall_nft generate -o /run/awall_nft/ruleset.nft
awall_nft apply /run/awall_nft/ruleset.nft
```

これにより、JSON設定を常に唯一の正として扱えます。

## awall/iptablesとの差分

意図的な差分:

- iptablesではなくnative nftablesを生成する
- defaultでlogdrop chainを作らない
- `conn-limit` はiptables `recent` ではなくnftables meter/limitで実装する
- filter chainは `policy drop`
- 未定義interfaceは信用しない
- nftables setやprefix matchを使い、rulesetを短くする

未対応または不完全な領域:

- awall完全互換
- 任意のawall variable
- nested import
- SNAT全機能
- ipset/address-set設定
- flowtable生成
- `nft -c` 以上のrollback-safe apply

## 将来の拡張候補

- nftables setによるaddress-set/ipset相当の対応
- 静的Ethernet forwarding向けflowtable生成
- より詳細なvalidate
- rollback-safe apply mode
- configurable logging
- 必要になった場合のIPv6 NAT対応
- WebUI統合
- systemd service統合

## License

MIT
