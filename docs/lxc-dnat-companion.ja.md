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
  lxc-dnat-helper schedule
    ↓
起動後の遅延 worker:
  /proc/<pid>/root/etc/lxc-dnat.d/*.conf を読む
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
                jump lxc_dnat_dynamic
        }

        chain lxc_dnat_dynamic {
                # lxc-dnat-sync がここだけを更新する
        }
}
```

通常の awall DNAT より後段で評価されるよう、`priority dstnat` より少し後ろの `-90` を使う想定。

## 実装ステップ

実装は段階的に進める。

1. コンテナ内の `/etc/lxc-dnat.d/*.conf` を読む INI 風パーサ
2. `lxc-dnat-helper` による `/run/lxc/dnat-requests.d/<instance>.json` 生成・削除
3. `lxc-dnat-sync` による `table ip awall_lxc_dnat` 反映
4. `lxc-dnat-sync` による WebUI 用 status JSON 出力

## lxc-dnat-helper

`lxc-dnat-helper` は LXC hook から呼ぶための補助コマンドです。

役割は、コンテナ内の `/etc/lxc-dnat.d/*.conf` を読み、ホスト側の
中間表現として `/run/lxc/dnat-requests.d/<instance>.json` を生成・削除し、
その後 `lxc-dnat-sync` を呼び出して nftables へ反映することです。

### schedule

```text
lxc-dnat-helper schedule
```

LXC の `start-host` hook から呼び出す通常運用向けコマンドです。

`schedule` は長い処理を直接実行せず、`setup-running` worker を detached process として起動して、すぐ `exit 0` します。LXC hook の処理を止めないためです。

worker は短時間リトライしながら `lxc-info -n <instance> -pH` で起動中コンテナの PID を取得し、次のパスからコンテナが実際に見ている rootfs を読みます。

```text
/proc/<pid>/root/etc/lxc-dnat.d/*.conf
```

これにより、LXC が overlayfs をコンテナ側 mount namespace 内で組み立てる構成でも、firmware 化された squashfs 内の DNAT 宣言を読めます。ホスト側の `/var/lib/lxc/<instance>/rootfs` が空に見える構成でも動作させるための方式です。

`schedule` は stale worker 対策として、インスタンスごとの token を作ります。

```text
/run/lxc/dnat-workers/<instance>.token
```

`cleanup` 時にこの token を削除します。遅れて起動した古い worker は token 不一致を検出して何もせず終了します。

worker のログはデフォルトで次に出ます。

```text
/run/lxc/dnat-workers/<instance>.log
```

### setup-running

```text
lxc-dnat-helper setup-running --instance <instance>
```

`schedule` から起動される内部用の one-shot worker です。手動デバッグにも使えます。

処理内容:

1. `lxc-info -n <instance> -pH` で起動中コンテナの PID を取得する
2. `/proc/<pid>/root/etc/lxc-dnat.d/*.conf` を読む
3. `/var/lib/lxc/<instance>/instance.json` の `ipv4` からインスタンスIPv4アドレスを取得する
4. `to-addr` にインスタンスIPv4アドレスを設定する
5. `/run/lxc/dnat-requests.d/<instance>.json` を生成する
6. `lxc-dnat-sync` を呼び出して動的 DNAT table を同期する

`to-addr` はコンテナ内の conf には書かせません。起動中インスタンスのアドレスを host 側で確定させます。`--address` が指定されていない場合は `instance.json` を優先し、必要な場合のみ LXC config を fallback として参照します。

### setup

```text
lxc-dnat-helper setup
```

従来どおり、`LXC_ROOTFS_MOUNT` または `--rootfs` で指定された rootfs path から `/etc/lxc-dnat.d/*.conf` を読む同期実行コマンドです。

素朴な rootfs 構成やテスト用途では使えますが、LXC が overlayfs を別 mount namespace 内で組み立てる構成では、ホスト側の rootfs path から DNAT 宣言が見えないことがあります。その場合は `schedule` / `setup-running` を使います。

### cleanup

```text
lxc-dnat-helper cleanup
```

処理内容:

1. 遅延 worker 用 token を削除する
2. `/run/lxc/dnat-requests.d/<instance>.json` を削除する
3. `lxc-dnat-sync` を呼び出して該当インスタンス由来の DNAT を削除する

### LXC hook 設定例

```text
lxc.hook.start-host = /usr/local/bin/lxc-dnat-helper schedule
lxc.hook.post-stop = /usr/local/bin/lxc-dnat-helper cleanup
```

`lxc-dnat-helper` はデフォルトで `/usr/local/bin/lxc-dnat-sync` を呼び出します。別パスに置く場合は `--sync-command=<path>` で指定し、テストなどで同期を行わない場合は `--no-sync` を指定します。

`schedule` は hook から即座に戻るため、DNAT 反映はコンテナ起動直後からわずかに遅れます。デフォルトでは 100ms 間隔で最大100回、起動中 PID の取得を試みます。調整する場合は `--retries` と `--interval-ms` を指定します。

## lxc-dnat-sync

`lxc-dnat-sync` は、ホスト側の `/run/lxc/dnat-requests.d/*.json` を全て読み、
LXC 動的 DNAT 専用の nftables table を再生成するコマンドです。

```text
lxc-dnat-sync
```

処理内容:

1. awall 設定を読み込む
2. `/run/lxc/dnat-requests.d/*.json` を全読み込みする
3. DNAT 要求同士の `proto + in + port` 重複を検査する
4. 通常 awall DNAT 設定との `proto + in + port` 重複を検査する
5. reserved port を拒否する
6. ホスト上で既に listen している同一 `proto + port` を拒否する
7. 有効な要求だけから `table ip awall_lxc_dnat` を生成する
8. `nft -c -f` で検査し、問題なければ `nft -f` で適用する

生成される table は次の形です。

```nft
destroy table ip awall_lxc_dnat

table ip awall_lxc_dnat {
        chain prerouting {
                type nat hook prerouting priority -90; policy accept;
                jump lxc_dnat_dynamic
        }

        chain lxc_dnat_dynamic {
                iifname { "eth0", "eth1" } tcp dport 8880 dnat to 10.0.3.13:80
        }
}
```

通常の awall DNAT は `priority dstnat`、つまり `-100` 相当なので、
LXC 動的 DNAT は少し後段の `-90` にしています。

### reserved port

初期実装では以下を拒否します。

```text
tcp/22
tcp/53
tcp/67
tcp/80
tcp/443
udp/53
udp/67
```

これらはコンテナ側 `/etc/lxc-dnat.d/*.conf` からは解除できません。
必要な場合は標準機能ではなく、通常の awall DNAT 設定やフルカスタム構成で扱います。

### 衝突時の扱い

衝突した rule は skip し、stderr に warning を出します。
有効な rule が残っていれば、それらだけを nftables に反映します。

```text
lxc-dnat-sync: warning: alpine_hailo_demo:ssh: reserved host port: tcp/22
lxc-dnat-sync: synced 4 rule(s), skipped 1 rule(s)
```

### option

```text
--check-only
  生成した nft script を nft -c -f で検査するが適用しない。

--dry-run
  生成した nft script を標準出力へ出す。

--status-dir
  WebUI 用 status JSON の出力先を指定する。デフォルトは /run/lxc/dnat-status.d。

--skip-host-listen-check
  ホスト listen port との衝突チェックを無効化する。
  テスト用途を想定。

--skip-reserved-port-check
  reserved port チェックを無効化する。
  テスト用途を想定。
```


## status JSON

`lxc-dnat-sync` は nftables への反映に成功したあと、WebUI 用の状態ファイルを出力します。

```text
/run/lxc/dnat-status.d/<instance>.json
```

停止したインスタンスは `lxc-dnat-helper cleanup` によって request JSON が削除され、次の `lxc-dnat-sync` で status JSON も削除されます。
そのため、DNAT ステータス画面は基本的に「現在起動中で、DNAT 要求を持つインスタンス」だけを表示します。

例:

```json
{
  "instance": "alpine_hailo_demo",
  "address": "10.0.3.13",
  "status": "partial",
  "updatedAt": "2026-07-02T00:00:00Z",
  "active": 4,
  "skipped": 1,
  "rules": [
    {
      "name": "web",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 8880
      },
      "to-addr": "10.0.3.13",
      "to-port": 80,
      "status": "active"
    },
    {
      "name": "host-ssh",
      "in": "Closed",
      "service": {
        "proto": "tcp",
        "port": 22
      },
      "to-addr": "10.0.3.13",
      "to-port": 22,
      "status": "skipped",
      "reason": "reserved host port: tcp/22"
    }
  ]
}
```

`status` は以下のいずれかです。

| status | 意味 |
|---|---|
| `active` | 全 rule が反映された |
| `partial` | 一部 rule は反映され、一部は skip された |
| `error` | 要求はあるが全 rule が skip された |
| `empty` | request はあるが有効な rule が無い |

`--dry-run` と `--check-only` では status JSON は更新しません。実際に nftables へ適用できた状態だけを WebUI に見せるためです。
