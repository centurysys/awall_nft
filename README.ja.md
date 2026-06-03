# awall-nft

`awall-nft` は、Linuxルーター向けの小さなnftablesツールです。

主役の機能は、PPP、WireGuard、bridge、LTE/WWAN、製品固有の仮想リンクなど、
実行時に作られるinterfaceへ **nftables flowtableを動的に同期する** ことです。

awall風JSONからnftables rulesetを生成する機能も含みます。ただし、それはこの
プロジェクトの唯一の目的ではありません。`flowtable-sync` subcommandは、
Alpine Linuxやawall JSONを使っていない環境でも、単独で参考にできます。

## 主役の機能: 動的flowtable同期

Linuxルーターでは、forwarding負荷を下げるためにnftables flowtableを使うことが
あります。難しいのは、初期rulesetの生成そのものではありません。難しいのは、
interfaceが実行時に出現・消滅したとき、flowtableのdevice listを正しく追従
させることです。

典型例は次の通りです。

- `pppd` が作るPPP interface
- `wg-quick` やinterface managerが作るWireGuard interface
- bridge interfaceやbridge member
- LTE/WWAN interface
- containerや製品固有サービスが作る仮想interface

多くのrouter stackでは、interface状態の変化に対してfirewall全体を再生成・
reloadする方向になりがちです。`awall-nft flowtable-sync` は、もっと狭い範囲を
更新します。

更新対象はflowtable関連だけです。

1. 現在の設定を読む
2. 明示されたflowtable方向を、現在存在するinterfaceへ解決する
3. 専用の `flowtable_forward` chainをflushする
4. `ft_forward` flowtable objectを、現在のdevice setで削除・再作成する
5. `flow add @ft_forward` ruleだけを再追加する

firewall ruleset全体のflush、再生成、再適用は行いません。

そのため、次のようなhookから呼び出せます。

```sh
# /etc/ppp/ip-up.d/awall-nft-flowtable
# /etc/ppp/ip-down.d/awall-nft-flowtable
#!/bin/sh
/usr/local/sbin/awall_nft flowtable-sync || true
```

WireGuardでは次のように呼べます。

```ini
PostUp = /usr/local/sbin/awall_nft flowtable-sync || true
PostDown = /usr/local/sbin/awall_nft flowtable-sync || true
```

通常出力は短くしています。

```text
flowtable-sync: synced 1 rule(s), skipped 2 rule(s), devices: eth0, eth1, wlisc
```

## Linuxルーター開発者にとっての価値

OpenWrt、firewall4、自作Linuxルーター、組み込みgatewayを扱っている人にとって、
このプロジェクトで一番参考になるのは、`flowtable-sync` が使っている
**手順そのもの** かもしれません。

要点は、flow offload ruleのための安定した差し込み位置を用意し、flowtable object
と対応chainだけを差し替えることです。これにより、firewall全体のreloadによる
副作用を避けつつ、runtime-created interfaceにflowtable device setを追従できます。

このプロジェクトはOpenWrt firewall4を置き換えるものではありません。対象はもっと
狭く、次の一点です。

> firewall全体をreloadせずに、nftables flowtable deviceを動的interfaceへ同期する。

## 副次的な機能: awall風JSONからのnftables生成

同じbinaryには、Alpine Wall (awall) 風の小さな実用subset JSON設定から、native
nftables rulesetを生成する機能もあります。

iptables/nftablesを直接書くと事故りやすく、一方でFirewallDのような大きな
firewall managerは組み込みLinux機器には重い、という用途を想定しています。

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
- forwarding向けの明示的なnftables flowtableヒント
- 実行時に作られるinterface向けの動的flowtable同期

生成したrulesetは、適用前に `nft -c -f` でチェックできます。

## generatorの背景

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
- interface listが空のzoneは許可し、emitter側でskipする
- インターネット向けdropでログを溢れさせない
- 組み込みLinuxでも使いやすい軽量実装にする
- firewallの許可ルールとflowtableの最適化ヒントを分離する

## 現在の状態

現在の実装では、次の処理ができます。

- `sunny` による awall風JSONのparse
- `optional/main.json` の import list 読み込み
- `base`, `zone`, `filter`, `dnat`, `snat` JSONのmerge
- awall service定義の読み込み
- merge後設定のvalidate
- `ssh`, `dns`, `rdp` などのservice名解決
- `br+`, `wg+` のようなinterface prefix表現のnormalize
- interface listが空の任意zone定義を許可
- nftables ruleset生成
- 明示されたzone間方向に対するnftables flowtable rule生成
- 初期flowtable deviceを、実在するexact `ethN` interfaceに限定
- `flowtable-sync` による動的flowtable device同期
- `nft -c -f` による生成rulesetのcheck
- check済みrulesetのapply
- 正規化済み設定の人間向け表示

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

policyの順序は意味を持ちます。本家awallと同様に、広い片側指定policyも
出現順で展開されます。Guest/DMZのようなzoneを広いlegacy policyより制限したい
場合は、より具体的なpolicyを先に置きます。

例:

```json
{
  "policy": [
    { "in": "Guest", "out": "WAN", "action": "accept" },
    { "in": "Guest", "out": "LAN", "action": "drop" },
    { "in": "Guest", "out": "Closed", "action": "drop" },

    { "in": "DMZ", "out": "WAN", "action": "accept" },
    { "in": "DMZ", "out": "LAN", "action": "drop" },
    { "in": "DMZ", "out": "Closed", "action": "drop" },

    { "in": "_fw", "out": "WAN", "action": "accept" },
    { "in": "LAN", "action": "accept" },
    { "out": "LAN", "action": "accept" },
    { "in": "WAN", "action": "drop" },
    { "in": "Closed", "action": "accept" },
    { "out": "Closed", "action": "accept" }
  ]
}
```

この例では、`Guest -> LAN` のdropが、後続の広い `out=LAN accept` より
先に評価されます。`show forward` でFORWARDに効くpolicy順序を確認できます。

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

### Flowtable hints / flowtableヒント

`flowtable` は `awall-nft` 独自拡張です。標準awallの許可モデルでは
ありません。

これは、それ自体では通信を許可しません。通信を許可するかどうかは、通常の
`policy`, `filter`, `dnat`, `snat` の処理が決めます。`flowtable` セクションは、
通常ルールを通過したforward通信のうち、nftables flowtableで高速化してよい
zone間方向を明示するためだけに使います。

例:

```json
{
  "flowtable": [
    { "in": "LAN", "out": "Closed" },
    { "in": "Closed", "out": "LAN" },
    { "in": "Closed", "out": "Closed" },
    { "in": "Guest", "out": "WAN" }
  ]
}
```

方向はraw interface名ではなくzone名で書きます。たとえば
`{ "in": "LAN", "out": "Closed" }` は、`LAN` zoneのinterfaceから入り、
`Closed` zoneのinterfaceへ出ていくforward通信をflowtable対象にしてよい、
という意味です。

重要な性質:

- `flowtable` は最適化ヒントであり、firewallの許可ルールではない
- `awall-nft` は `policy` からflowtable対象を推論しない
- `in` と `out` は必須
- `_fw` は禁止。flowtableはforward通信にだけ適用する
- `{ "in": "LAN", "action": "accept" }` のような片側policyからは、
  flowtable ruleを自動生成しない
- WAN向き・WAN発の方向は、fast path化してよいことが明確な場合だけ追加する

通常のruleset生成では、静的generatorはかなり保守的にしています。
初期flowtable device listに追加するのは、`eth0`, `eth1` のような実在する
exact Ethernet interfaceだけです。`ppp+`, `wg+`, `br+`, `wlan0`, `wwan0`、
または `wlisc` のようなWireGuardベースの閉域網interfaceは、
`flowtable-sync` で扱います。

これは、設定上は存在していても実機上にまだ存在しないinterfaceによって、
`nft -c` が失敗することを避けるためです。`flowtable-sync` は同じJSON設定を
読み込み、設定されたflowtable zone間方向を現在実在するinterfaceへ解決し、
`ft_forward` flowtable objectのdevice listと `flowtable_forward` chainを
再構築します。firewall ruleset全体は再生成・再適用しません。

生成例:

```nft
flowtable ft_forward {
  hook ingress priority 0;
  devices = { eth0, eth1 };
}

chain flowtable_forward {
  iifname "eth0" oifname "eth1" meta l4proto { tcp, udp } flow add @ft_forward
  iifname "eth1" oifname "eth0" meta l4proto { tcp, udp } flow add @ft_forward
  # awall_nft flowtable-sync may replace this chain
}
```

生成される `forward` chain は、established/related通信をacceptしたあと、
通常のforward ruleより前に `flowtable_forward` へjumpします。

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
  flowtable ft_forward        # flowtable deviceがある場合に出力
  chain input
  chain flowtable_forward
  chain forward
  chain output
  chain postrouting_mangle

table ip awall_nft_nat
  chain prerouting
  chain postrouting
```

filter chainはすべて `policy drop` です。`flowtable_forward` chainは、
flowtable ruleを差し込むための安定した場所として生成します。
`flowtable-sync` は、ruleset全体を書き換えずに、このchainと `ft_forward`
flowtable objectを更新できます。

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

### 正規化済み設定の表示

```sh
awall_nft show all
```

`show` はread-onlyです。`generate` と同じ設定を読み込み、normalizeした内容を
人間が読みやすい形で表示します。`nft` は実行せず、firewallも変更しません。

利用できるtopic:

```text
all
zones
policies
forward
filters
dnat
snat
clamp-mss
flowtable
```

`show forward` は、広いpolicyとGuest/DMZ向けの明示policyが混在している場合に
有用です。FORWARD rule生成に効くpolicy順序を表示します。

```text
policy[0] Guest -> WAN  accept
policy[1] Guest -> LAN  drop
policy[4] LAN -> *  accept
policy[5] * -> LAN  accept
```

`*` は、元のawall風policyでその側が省略されていることを意味します。

### flowtable device同期

```sh
awall_nft flowtable-sync
```

このコマンドは、PPP、WireGuard、bridge、`wlisc` のような製品固有の閉域網
interfaceなど、実行時に作成・削除されるinterfaceをflowtableへ同期するために
使います。

実行する更新は限定的です。

1. 現在のawall風JSON設定を読み込み、normalizeする
2. 明示された `flowtable` zone間方向を、現在実在するinterfaceへ解決する
3. `chain inet awall_nft flowtable_forward` をflushする
4. 解決されたdevice setで `flowtable inet awall_nft ft_forward` を再作成する
5. 対応する `flow add @ft_forward` ruleを再投入する

firewall ruleset全体は再生成・再適用しません。

hook例:

```sh
# /etc/ppp/ip-up.d/awall-nft-flowtable
# /etc/ppp/ip-down.d/awall-nft-flowtable
#!/bin/sh
/usr/local/sbin/awall_nft flowtable-sync || true
```

WireGuardまたはWireGuardベースの閉域網interfaceでは、interface管理処理から
同じコマンドを呼び出します。`wg-quick` を使う場合は `PostUp` / `PostDown`
から呼び出せます。

通常出力は意図的に短くしています。

```text
flowtable-sync: synced 1 rule(s), skipped 2 rule(s), devices: eth0, eth1, wlisc
```

`flowtable-sync` は `/run/lock/awall_nft/` 配下の process lock により
直列化されます。ifup hook、lxc-net、boot-completed など複数の契機から
同時に呼ばれても、nftables の更新は並列実行されず、後続処理は先行処理の
完了を待ってから実行されます。競合した場合は、lock を待っていることと、
lock 取得後に実行を再開したことをログに出します。

入力側または出力側が実在interfaceに解決できないruleはskipします。

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
- interface listが空のzoneは許可し、emitter側でskipする
- nftables setやprefix matchを使い、rulesetを短くする

未対応または不完全な領域:

- awall完全互換
- 任意のawall variable
- nested import
- SNAT全機能
- ipset/address-set設定
- `nft -c` 以上のrollback-safe apply

## 将来の拡張候補

- nftables setによるaddress-set/ipset相当の対応
- より詳細なvalidate
- rollback-safe apply mode
- configurable logging
- 必要になった場合のIPv6 NAT対応
- WebUI統合
- systemd service統合

## License

MIT
