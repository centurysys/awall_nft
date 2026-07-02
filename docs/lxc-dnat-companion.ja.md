# LXC 動的 DNAT コンパニオン設計メモ

## 目的

LXC インスタンスが必要とする DNAT を、通常の awall_nft 設定画面で手入力しなくても自動反映できるようにする。

特に HAILO WEB DEMO のように、1つのインスタンスで SSH / Web UI / HLS / WebRTC など複数ポートを公開する場合、現状は `to-addr` に `10.0.3.x` を手入力する必要があり、投入順や再作成でアドレスが変わると設定が壊れやすい。

この機能では、コンテナ内に人間が読み書きしやすい INI 風ファイルを置き、ホスト側 hook が起動中インスタンスのアドレスを付与して DNAT 要求へ変換する。

## 全体の流れ

```text
コンテナ内:
  /etc/lxc-dnat.d/*.conf
    ↓
LXC start-host hook:
  lxc-dnat-helper setup
    ↓
ホスト側の中間表現:
  /run/lxc/dnat-requests.d/<instance>.json
    ↓
反映コマンド:
  lxc-dnat-sync
    ↓
nftables:
  table ip awall_lxc_dnat
```

停止時は次の流れにする。

```text
LXC post-stop hook:
  lxc-dnat-helper cleanup
    ↓
/run/lxc/dnat-requests.d/<instance>.json を削除
    ↓
lxc-dnat-sync
    ↓
該当インスタンス由来の DNAT を削除
```

## コンテナ内設定ファイル

パスは次の形式にする。

```text
/etc/lxc-dnat.d/*.conf
```

1つのセクションが1つの DNAT 要求を表す。

```ini
# /etc/lxc-dnat.d/hailo-web-demo.conf

[ssh]
in = Closed
proto = tcp
port = 8022
to-port = 22

[web]
in = Closed
src = 203.0.113.10/32, 198.51.100.0/24
proto = tcp
port = 8880
to-port = 80

[hls]
in = Closed
proto = tcp
port = 8888
to-port = 8888

[webrtc-tcp]
in = Closed
proto = tcp
port = 8889
to-port = 8889

[webrtc-udp]
in = Closed
proto = udp
port = 8189
to-port = 8189
```

### key

| key | 必須 | 内容 |
|---|---:|---|
| `in` | yes | awall の入力 zone 名。例: `Closed` |
| `src` | no | 許可する source address / CIDR。カンマ区切り |
| `proto` | yes | `tcp` または `udp` |
| `port` | yes | gateway 側の公開ポート。awall JSON の `service.port` 相当 |
| `to-port` | yes | コンテナ内の宛先ポート |
| `enabled` | no | `true` / `false`。省略時は `true` |

`to-addr` は書かせない。`lxc-dnat-helper` が起動中インスタンスの IP アドレスを設定する。

## INI 風パーサの仕様

初期仕様は小さく固定する。

- コメントは行頭の `#` または `;`
- セクション名は `[name]`
- セクション名に使える文字は `A-Z a-z 0-9 _ - .`
- 値は `key = value`
- クォートやエスケープは基本的に扱わない
- `enabled` は `true` / `false` のみ
- `proto` は `tcp` / `udp` のみ
- `port` / `to-port` は `1..65535`
- 未知 key はエラー
- 同一セクション内の key 重複はエラー
- 同一ファイル内のセクション名重複はエラー

## reserved port

コンテナ側設定だけでホスト管理用ポートを奪えるようにはしない。

少なくとも以下は `lxc-dnat-sync` 側で拒否する方針にする。

```text
tcp/22
tcp/80
tcp/443
udp/53
udp/67
```

さらに、ホスト上で既に listen している同一 protocol / port も拒否する。

`443` をどうしてもコンテナへ流したい場合は、この標準機能では扱わない。標準 WebUI や nginx の待受を変更した上で、通常の awall DNAT 設定またはフルカスタム構成として管理する。

## awall_nft との関係

`awall_nft apply` は `table inet awall_nft` と `table ip awall_nft_nat` だけを置き換える。

LXC 動的 DNAT は別 table として管理する。

```nft
table ip awall_lxc_dnat {
        chain prerouting {
                type nat hook prerouting priority -90; policy accept;
                jump dynamic
        }

        chain dynamic {
                # lxc-dnat-sync がここだけを更新する
        }
}
```

通常の awall DNAT より後段で評価されるよう、`priority dstnat` より少し後ろの `-90` を使う想定。

## 最初の実装範囲

最初のステップでは、コンテナ内の `/etc/lxc-dnat.d/*.conf` を読む INI 風パーサを追加する。

この段階では、まだ hook / `/run` JSON 生成 / nftables 反映は実装しない。

## lxc-dnat-helper

`lxc-dnat-helper` は LXC hook から呼ぶための補助コマンドです。

現時点の役割は、コンテナ内の `/etc/lxc-dnat.d/*.conf` を読み、ホスト側の
中間表現として `/run/lxc/dnat-requests.d/<instance>.json` を生成・削除する
ところまでです。

### setup

```text
lxc-dnat-helper setup
```

処理内容:

1. インスタンス名を取得する
2. rootfs mount path を取得する
3. `/etc/lxc-dnat.d/*.conf` を読む
4. `/var/lib/lxc/<instance>/instance.json` の `ipv4` からインスタンスIPv4アドレスを取得する
5. `to-addr` にインスタンスIPv4アドレスを設定する
6. `/run/lxc/dnat-requests.d/<instance>.json` を生成する

`to-addr` はコンテナ内の conf には書かせません。起動中インスタンスの
アドレスを host 側で確定させます。`--address` が指定されていない場合は `instance.json` を優先し、必要な場合のみ LXC config を fallback として参照します。

### cleanup

```text
lxc-dnat-helper cleanup
```

処理内容:

1. `/run/lxc/dnat-requests.d/<instance>.json` を削除する

### LXC hook 設定例

```text
lxc.hook.start-host = /usr/local/bin/lxc-dnat-helper setup --sync-command=/usr/local/bin/lxc-dnat-sync
lxc.hook.post-stop = /usr/local/bin/lxc-dnat-helper cleanup --sync-command=/usr/local/bin/lxc-dnat-sync
```

`lxc-dnat-sync` は次ステップで追加します。現段階では `--sync-command` を
指定しなければ、request JSON の生成・削除だけを行います。
