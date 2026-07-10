# iPhone Face ID を用いた Linux PAM 認証システム設計書

**バージョン:** 0.2.0

**文書ステータス:** Draft for Implementation

**対象:** Linux 上の 1Password System Authentication、および汎用 PAM 認証  
**想定読者:** セキュリティレビュー担当、Linux/PAM 実装者、iOS 実装者  
**最終更新日:** 2026-07-10

---

## 1. 概要

本システムは、Linux 上の PAM 認証要求を iPhone に転送し、iPhone の Face ID によって使用許可された Secure Enclave 内の秘密鍵でチャレンジへ署名させることで、Linux 側の認証を成立させる。

主用途は、1Password for Linux の **Unlock using system authentication** を利用した 1Password の解錠である。1Password 自体は改変せず、polkit と PAM を経由して本認証方式を利用する。

本設計では、Face ID の「成功／失敗」をネットワーク越しに通知する方式を採用しない。Linux 側の信頼されたコンポーネントが生成した単発チャレンジに対する暗号署名を検証し、次の2点を同時に確認する。

1. 登録済み iPhone が対応する秘密鍵を保持していること
2. その秘密鍵の使用が直前の Face ID 認証によって許可されたこと

---

## 2. 設計目標

### 2.1 ゴール

- iPhone の Face ID を用いて Linux の PAM 認証を成立させる。
- 1Password for Linux の system authentication から利用できる。
- PAM 利用アプリケーションへ応用可能な汎用構成とする。
- 生体情報を Linux 側へ送信しない。
- 非特権ユーザープロセスが侵害されても、単独では認証成功を偽造できない。
- iPhone の紛失、電池切れ、通信障害時にパスワードへフォールバックできる。
- root 権限で動作するコードと攻撃面を最小化する。
- 認証要求の PAM サービス、端末、ユーザー、期限を署名対象へ束縛する。
- 複数 iPhone の登録、失効、再登録に拡張可能な構成とする。

### 2.2 非ゴール

- Face ID の生体データや顔画像を Linux 側へ転送すること。
- 1Password のアカウントパスワードや暗号鍵を置き換えること。
- root 権限を取得済みの攻撃者から 1Password を保護すること。
- 初期版でインターネット越しの認証を提供すること。
- 初期版で PAM のすべての利用場面を公式サポートすること。
- iPhone を常時バックグラウンド待受可能な汎用認証器として扱うこと。

---

## 3. 前提条件

- Linux 側では PAM、polkit、Unix domain socket、systemd を利用できる。
- iPhone 側では Face ID、LocalAuthentication、Keychain、Secure Enclave を利用できる。
- iPhone アプリは自作する。
- 初期版では Linux と iPhone が同一 LAN 上に存在する。
- 1Password の system authentication が有効化されている。
- Linux の root 権限を持つ攻撃者は信頼しない。
- Linux の一般ユーザーセッションは侵害される可能性がある。
- iPhone の秘密鍵は Secure Enclave から取り出せない前提とする。

---

## 4. 脅威モデル

### 4.1 防御対象

本設計は、主に次の脅威を防御対象とする。

- 同一 LAN 上の攻撃者による盗聴、改ざん、リプレイ
- 偽の iPhone 応答による認証成功の偽造
- Linux の非特権ユーザー権限を得たマルウェアによる helper の差し替え
- Unix domain socket 上の偽サーバー、偽クライアント
- 過去の署名応答の再利用
- polkit 認証用の署名を `sudo` や `login` など別 PAM サービスへ流用する攻撃
- Linux 端末 A 向けの署名を Linux 端末 B へ流用する攻撃
- iPhone の生体登録変更後に既存鍵を継続利用する攻撃
- ユーザーに認証対象を誤認させる承認疲れ、要求取り違え

### 4.2 防御対象外

- Linux の root 権限を取得した攻撃者
- 改変済みカーネル、PAM、polkit、1Password クライアント
- iPhone OS または Secure Enclave の完全侵害
- Face ID 自体の誤受入率や物理的強制
- ユーザーが正当な認証要求を誤って承認すること
- 同じ `polkit-1` PAM スタックを使用する polkit action 間で認証方式を分離すること
- パスワードフォールバック経路自体の侵害
- サービス拒否攻撃

---

## 5. セキュリティ原則

### 5.1 Face ID の真偽値を信用しない

ネットワーク越しに次のような値を返す方式は禁止する。

```json
{
  "face_id": true
}
```

この方式では、偽造、リプレイ、プロセス差し替えに対して安全性を確保できない。

### 5.2 Face ID は秘密鍵使用のゲートとして利用する

Face ID は認証結果そのものとして利用せず、Secure Enclave 内の秘密鍵による署名操作を許可する条件として利用する。

Linux 側は署名だけを検証し、Face ID API の戻り値を直接信頼しない。

### 5.3 最終判定は信頼境界内で行う

非特権 helper が返す `success` を PAM が直接信用してはならない。

最終的な認証判定は、次のいずれかで行う。

- PAM モジュール自身
- root 所有の専用 verifier daemon

本設計では、保守性と攻撃面の分離を考慮し、**root 所有の verifier daemon が最終判定を行い、PAM モジュールはその結果だけを受け取る構成**を採用する。

### 5.4 チャレンジは信頼側が生成する

nonce、ユーザー名、PAM サービス名、期限、端末識別子などは、root 所有の verifier が PAM の信頼できるコンテキストから構築する。

非特権 helper はチャレンジを変更せず運搬するだけとする。

---

## 6. コンポーネント構成

```text
[1Password]
     |
     v
[polkit]
     |
     v
[pam_iphone_faceid.so]
     |
     | root-only Unix domain socket
     v
[faceid-authd]  root-owned verifier
     |
     | user-session IPC
     v
[faceid-transport]  unprivileged helper
     |
     | authenticated encrypted channel (helper terminates it)
     v
[iPhone app]
     |
     v
[Secure Enclave + Face ID]
```

### 6.1 PAM モジュール

**権限:** PAM 呼び出し元に依存。通常は特権コンテキスト。

責務:

- PAM からユーザー名、サービス名などを取得する
- `faceid-authd` へ認証要求を送る
- タイムアウトを管理する
- verifier の最終結果を PAM 戻り値へ変換する

責務外:

- iPhone との通信
- Face ID 制御
- 暗号プロトコルの実装
- 公開鍵管理
- mDNS、BLE、HTTP、JSON の複雑な処理

### 6.2 `faceid-authd`

**権限:** root 所有の system service。

責務:

- nonce と request ID の生成
- 認証コンテキストの構築
- 登録済み公開鍵の安全な読み込み
- iPhone 応答署名の検証
- nonce、期限、用途、端末、ユーザーの照合
- 使用済み request ID の再利用防止
- PAM モジュールへの最終判定返却
- 登録鍵、失効情報、ポリシーの管理
- audit ログの最小限の記録

### 6.3 `faceid-transport`

**権限:** 対象ユーザーのセッション権限。

責務:

- iPhone の探索
- LAN または BLE 通信
- iPhone アプリへのチャレンジ転送
- 署名応答の受信と verifier への転送
- ユーザー通知
- 通信失敗やタイムアウトの表示

重要事項:

- 認証成功を決定しない
- 登録済み公開鍵を書き換えられない
- verifier が生成したチャレンジを変更しない
- `success` のような未検証結果を返さない

### 6.4 iPhone アプリ

責務:

- Secure Enclave 内で P-256 鍵ペアを生成する
- Face ID によって秘密鍵の利用をゲートする
- Linux 端末との初期ペアリング
- Linux から受信した認証要求の内容をユーザーへ表示する
- Face ID 成功後に正規化済みチャレンジへ署名する
- 登録済み Linux 端末の表示、削除、失効管理を行う

---

## 7. 信頼境界

### 7.1 信頼するもの

- Linux カーネル
- PAM と polkit の正規実装
- root 所有の PAM モジュール
- root 所有の `faceid-authd`
- root のみ書き込み可能な設定、公開鍵、ソケット
- iPhone OS
- Secure Enclave
- iPhone アプリの署名ロジック

### 7.2 信頼しないもの

- Linux の一般ユーザープロセス
- `faceid-transport`
- LAN
- mDNS
- 中継サーバー
- 受信した JSON、CBOR、バイナリメッセージ
- iPhone から返される表示用メタデータ
- helper が申告するユーザー名、サービス名、操作名
- 壁時計だけに依存した期限判定

---

## 8. 登録フロー

### 8.1 iPhone 側鍵生成

iPhone アプリは Secure Enclave 内で P-256 鍵ペアを生成する。

推奨設定:

- `kSecAttrTokenIDSecureEnclave`
- `kSecAttrKeyTypeECSECPrimeRandom`
- 256 bit
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- `.privateKeyUsage`
- `.biometryCurrentSet`

`.biometryCurrentSet` により、iPhone 上の生体登録セットが変更された場合、既存秘密鍵を使用不能にする。
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` も明示し、端末外へ移行させない方針をアクセス属性として重ねて表現する。

### 8.2 相互ペアリング

初回登録時に、iPhone と Linux は相互に公開情報を交換する。

Linux から iPhone:

- Linux device ID
- Linux 端末表示名
- Linux verifier 公開鍵または証明書
- プロトコルバージョン
- ペアリング nonce

iPhone から Linux:

- iPhone device ID
- iPhone 表示名
- Secure Enclave 公開鍵
- 鍵作成日時
- 対応プロトコルバージョン

推奨 UX:

1. Linux が QR コードを表示する
2. iPhone アプリが QR コードを読み取る
3. 双方に短い比較コードを表示する
4. ユーザーが一致を確認する
5. 相互の公開鍵を保存する

比較コードは片側が生成した乱数そのものではなく、Linux verifier 公開鍵、Secure Enclave 公開鍵、両 device ID、ペアリング nonce、プロトコルバージョンを含む正規化済みペアリングトランスクリプト全体のハッシュから導出する。双方が独立に同じ値を計算し、十分な桁数の short authenticated string として表示する。これにより、Linux から iPhone への QR 経路だけでなく、iPhone から Linux へ返る公開鍵も比較確認へ束縛する。

### 8.3 保存先

Linux 側の登録済み iPhone 公開鍵は、一般ユーザーが書き換えられない場所へ保存する。

例:

```text
/etc/faceid-authd/users/<uid>/devices/<device-id>.json
```

所有者とパーミッション例:

```text
root:root
0640
```

ユーザーごとの登録操作は、polkit などによる明示的な管理認可を必要とする。

---

## 9. 認証プロトコル

### 9.1 認証要求

`faceid-authd` は次の情報から署名対象を構築する。

```text
protocol_version
request_id
nonce
linux_device_id
linux_device_name
target_uid
target_username
pam_service
pam_tty
pam_rhost
requested_action
issued_at
expires_at
verifier_ephemeral_key
```

値が存在しない PAM 項目は、明示的な `null` として正規化する。

### 9.2 用途束縛と polkit の制約

`requested_action` は verifier が信頼できる PAM コンテキストから決定する。初期版では `PAM_SERVICE` から導出し、例えば `polkit-1.authenticate`、`sudo.authenticate`、`login.authenticate` とする。helper や PAM conversation の表示文字列から用途を採用してはならない。

この束縛により、`polkit-1`、`sudo`、`login` など PAM サービス間の署名流用は防止できる。一方、polkit は PAM サービス名として一律 `polkit-1` を使用し、action ID を PAM 会話へ渡さない。このため PAM/verifier は 1Password の unlock と `pkexec` など別の polkit action を識別できず、polkit action 間の暗号学的な用途束縛は行えない。

polkit の `rules.d` では `action.id` に基づいて認可結果を制御するが、action ごとに PAM スタックや認証モジュールを選択することはできない。したがって `pam_iphone_faceid.so` を `polkit-1` の `auth` スタックへ `sufficient` として導入すると、そのスタックで本人認証を行う他の polkit action にも Face ID が利用可能となる。この挙動を許容できない環境では、polkit への統合を行わず専用 PAM サービスまでをサポート範囲とする。信頼できる action ID 伝達機構が将来追加された場合に限り、署名スキーマを拡張する。

### 9.3 正規化

署名対象は曖昧な文字列連結を使用しない。

推奨:

- Deterministic CBOR
- 明確なスキーマを持つ protobuf
- canonical JSON

バージョン、型、長さを明示し、異なる実装間で同一バイト列になることを保証する。

### 9.4 iPhone 側処理

iPhone アプリは以下を検証する。

- Linux device ID が登録済みである
- Linux 側署名またはセッション認証が正しい
- protocol version が対応範囲内である
- request が期限内である
- request ID が直近に処理済みでない
- PAM サービスから導出した用途が許可対象である

その後、次をユーザーに表示する。

```text
1Password のロック解除

端末: workstation
ユーザー: alice
操作: polkit による本人認証
要求時刻: 14:32
有効期限: 15 秒
```

ユーザーが認証を開始した場合のみ Face ID を実行する。

Face ID 成功後、Secure Enclave 内の秘密鍵で正規化済みチャレンジ全体へ署名する。

### 9.5 応答

iPhone から返す応答例:

```text
protocol_version
request_id
iphone_device_id
signed_payload_hash
signature_algorithm
signature
```

署名アルゴリズム候補:

```text
ECDSA P-256 with SHA-256
```

署名形式は X9.62 DER 形式または raw `r || s` のどちらかに固定し、プロトコルで明示する。

### 9.6 Linux 側検証

`faceid-authd` は次をすべて検証する。

1. request ID が現在保留中である
2. request ID が未使用である
3. nonce が verifier 自身の生成値と一致する
4. verifier が要求発行時に記録した monotonic clock からの経過時間が TTL 内である
5. PAM のユーザー、サービス、導出可能な用途が元要求と一致する
6. Linux device ID が自端末と一致する
7. iPhone device ID が対象ユーザーへ登録済みである
8. 署名アルゴリズムが許可済みである
9. 登録済み公開鍵で署名が正しい
10. 応答が同一セッションへ束縛されている
11. 対象鍵が失効済みでない
12. 認証ポリシーを満たしている

検証開始時に、request ID の保留確認と消費を単一のロックまたはトランザクション内でアトミックに行う。署名不正を含めて一度応答を受けた request ID は再利用せず、並行応答による二重検証を拒否する。

`issued_at` / `expires_at` は署名対象に残し、iPhone 側の表示と phone 側の期限確認に用いる。Linux 側で成否を決める TTL の権威は verifier の monotonic clock とし、iPhone と Linux の時計ずれや wall-clock rollback に依存させない。

---

## 10. トランスポート

### 10.1 初期版

初期版は同一 LAN 上の通信を採用する。

推奨構成:

- mDNS は発見用途のみ
- 実通信は相互認証された暗号化チャネル
- ペアリング済み公開鍵で相手を認証
- 接続ごとに ephemeral key を使用
- forward secrecy を確保

候補:

- Noise Protocol Framework
- TLS 1.3 mutual authentication
- 独自 ECDH + AEAD は避ける

初期版の暗号化チャネルは `faceid-transport` で終端する。したがって helper は平文のセッション内容を観測できるが、認証の完全性は verifier が生成したチャレンジと Secure Enclave 署名の連鎖、および verifier での検証によって確保する。相互認証チャネルは、盗聴防止、ペアリング済み端末以外からの要求抑止、DoS 耐性を高める defense-in-depth であり、helper を信頼境界へ含めるものではない。

### 10.2 mDNS の扱い

mDNS の応答は信用しない。

mDNS で得た IP アドレスへ接続後、必ずペアリング済み鍵による認証を行う。

### 10.3 BLE

BLE は将来の選択肢とする。

利点:

- 近接性を UX 上の補助要素として利用できる
- LAN 設定に依存しない

注意点:

- BLE の近接性を本人認証として扱わない
- RSSI をセキュリティ境界にしない
- 通信ペイロードは LAN と同じ署名・暗号要件を満たす
- iOS バックグラウンド制約を検証する

### 10.4 APNs

APNs と中継サーバーは初期版の対象外とする。

将来採用する場合も、中継サーバーは認証判断を行わず、暗号化された要求と署名応答を転送するだけとする。

---

## 11. ローカル IPC

### 11.1 PAM モジュールと verifier

PAM モジュールは root 専用 Unix domain socket を使用する。

例:

```text
/run/faceid-authd/pam.sock
```

要件:

- root 所有
- 一般ユーザーから接続不可
- `SO_PEERCRED` で接続元 UID、PID、GID を確認
- 要求ごとに一意な request ID
- 同一接続上で request と response を対応付ける
- 応答の再利用を禁止
- 読み書きの長さ上限を設定
- タイムアウトを設定
- 不正入力で daemon がクラッシュしない

### 11.2 verifier と transport helper

非特権 helper との IPC では、helper を信用しない。

helper へ渡すもの:

- 完成済みの署名対象
- request ID
- 通信先候補
- UI 表示用の非機密情報

helper から受け取るもの:

- iPhone の署名応答
- 通信エラー
- ユーザーキャンセル
- タイムアウト

helper が返す `approved=true` のような値は認証判定へ使用しない。

---

## 12. PAM 統合

### 12.1 モジュールインターフェース

実装対象:

```c
pam_sm_authenticate()
pam_sm_setcred()
pam_sm_acct_mgmt()
```

`pam_sm_setcred()` は、必要がなければ成功を返すだけの最小実装とする。
`pam_sm_acct_mgmt()` も状態を変更しない明示的な no-op として `PAM_SUCCESS` を返す。初期対象の polkit は通常 auth のみを利用するが、他 PAM サービスへ拡張した際の挙動を定義しておく。

### 12.2 戻り値

例:

- 認証成功: `PAM_SUCCESS`
- Face ID 拒否: `PAM_AUTH_ERR`
- iPhone 未到達: `PAM_AUTHINFO_UNAVAIL`
- タイムアウト: `PAM_AUTHINFO_UNAVAIL`
- 対象ユーザー不明: `PAM_USER_UNKNOWN`
- 内部エラー: `PAM_SYSTEM_ERR`

### 12.3 フォールバック

初期導入時はパスワード認証を残す。

例:

```pam
auth sufficient pam_iphone_faceid.so timeout=30
auth include common-auth
```

ディストリビューションにより `common-auth`、`system-auth` などが異なるため、インストーラーは自動上書きせず、明示的な設定手順と検証を提供する。

### 12.4 polkit 統合の適用範囲

`/etc/pam.d/polkit-1` 全体へ無条件に組み込むと、1Password 以外の polkit 操作にも利用される可能性がある。

現行の polkit では action ID が PAM へ伝わらないため、verifier による 1Password action の確認や action allowlist は実装しない。モジュール引数、環境変数、helper の申告によって `1password.unlock` を渡す方式も、呼び出し元を認証できないため採用しない。

配布時は、この制約と対象ディストリビューションで `polkit-1` スタックを共有する action を管理者へ提示する。polkit の `rules.d` は action ID ごとの認可ポリシーを明示し、不要な action を `not_handled` または拒否相当の結果へ制限するために使用できるが、Face ID モジュールだけを action ごとに選択する機構としては扱わない。管理系 action を `auth_admin` にする場合も同じ PAM スタックを通り得るため、それだけで認証方式が分離されるとはみなさない。

---

## 13. iPhone 側セキュリティ

### 13.1 鍵アクセス制御

推奨:

```text
.privateKeyUsage + .biometryCurrentSet
```

初期版は Face ID のみに限定し、`.biometryCurrentSet` を使用する。このフラグは端末パスコードへのフォールバックを許可しない。将来パスコードを許容する製品ポリシーへ変更する場合は、`.userPresence` や `.devicePasscode` など別のアクセス制御フラグを明示的に選択し、Face ID 限定という保証が失われることを表示する。

### 13.2 認証コンテキスト

- 署名ごとに新しい認証コンテキストを使用する
- 過去の Face ID 成功を長時間再利用しない
- 認証 reuse duration を可能な限り 0 に近づける
- バックグラウンド遷移後の未処理要求を無効化する
- アプリ再起動後に古い request を復元しない

### 13.3 画面表示

承認画面は、Face ID が発火する前に表示する。

最低表示項目:

- Linux 端末名
- Linux ユーザー名
- 操作
- 要求時刻
- 有効期限
- 未登録端末でないこと

「承認しますか？」だけの画面は禁止する。

---

## 14. 失効と回復

### 14.1 iPhone 紛失

Linux 側で登録済み device ID を失効できる管理コマンドを提供する。

例:

```bash
sudo faceid-authctl revoke --user alice --device <device-id>
```

### 14.2 生体登録変更

`.biometryCurrentSet` により鍵が利用不能になった場合、iPhone アプリは新しい鍵を生成し、再登録を要求する。

旧公開鍵は Linux 側で自動的に信用し続けない。

### 14.3 Linux 再インストール

Linux verifier の端末鍵が変わった場合、iPhone 側では別端末として再ペアリングする。

### 14.4 フォールバック

最低1つの回復手段を必須とする。

- Linux アカウントパスワード
- 1Password アカウントパスワード
- 管理者による登録解除
- リカバリーコード

Face ID のみを唯一の認証手段にしない。

---

## 15. ログとプライバシー

### 15.1 記録してよい情報

- 認証開始時刻
- 成功、拒否、タイムアウト、内部エラー
- PAM サービス
- action
- 対象 UID
- device ID の短縮識別子
- プロトコルバージョン

### 15.2 記録してはいけない情報

- 完全な nonce
- 完全な署名
- 秘密鍵
- 生体情報
- Face ID の内部状態
- 1Password の内容
- ネットワーク上の完全な認証メッセージ
- ユーザーのアカウントパスワード

### 15.3 レート制限

- 同一 UID に対する並行要求数を制限する
- 短時間の連続失敗を抑制する
- iPhone への通知連打を防止する
- 認証要求のキュー上限を設定する

---

## 16. タイムアウトと並行性

推奨初期値:

```text
総タイムアウト: 30 秒
接続タイムアウト: 5 秒
Face ID 待機: 20 秒
応答検証: 2 秒
```

要件:

- PAM 呼び出しを無期限にブロックしない
- 同一ユーザーの複数要求を区別する
- 古い要求の応答を新しい要求へ適用しない
- キャンセル後の遅延応答を拒否する
- request ID は128 bit以上のランダム値とする

---

## 17. 実装言語と依存関係

### 17.1 PAM モジュール

候補:

- C
- Rust + `cdylib`

要件:

- 依存ライブラリを最小化
- 例外や panic が PAM 呼び出し元へ伝播しない
- メモリ安全性を重視
- 入力長を厳格に制限

### 17.2 verifier daemon

Rust を推奨する。

理由:

- メモリ安全性
- 型付きプロトコル
- 暗号ライブラリの利用
- systemd との統合
- fuzzing の容易さ

### 17.3 iPhone アプリ

Swift を使用する。

主要 API:

- LocalAuthentication
- Security.framework
- Keychain Services
- Secure Enclave
- Network.framework
- CryptoKit または Security.framework

---

## 18. テスト計画

### 18.1 単体テスト

- canonical encoding
- nonce 生成
- 署名検証
- 期限判定
- device ID 照合
- PAM サービスからの用途導出
- request ID 再利用拒否
- malformed input
- oversized input
- unsupported version

### 18.2 統合テスト

1. CLI から verifier へ認証要求
2. helper 経由で iPhone と通信
3. Secure Enclave 署名
4. Face ID 成功
5. Face ID 拒否
6. Face ID ロックアウト
7. iPhone 未到達
8. 通信切断
9. タイムアウト
10. 複数同時要求
11. PAM テストサービス
12. polkit
13. 1Password

### 18.3 セキュリティテスト

- 応答リプレイ
- nonce 差し替え
- username 差し替え
- service 差し替え
- action 差し替え
- 同一 `polkit-1` 内では action を識別できないことの確認
- host ID 差し替え
- 別 iPhone の署名
- 失効済み鍵
- helper 偽装
- Unix socket 偽装
- mDNS spoofing
- MITM
- downgrade attack
- malformed signature
- parser fuzzing
- daemon restart 中の遅延応答
- clock rollback
- wall-clock 変更中も monotonic TTL が維持されること

### 18.4 PAM 導入テスト

いきなり `/etc/pam.d/polkit-1` を変更しない。

最初に専用 PAM サービスを作成する。

```pam
# /etc/pam.d/faceid-auth-test
auth required pam_iphone_faceid.so timeout=30 action=test.authenticate
account required pam_permit.so
```

専用テストクライアントで動作確認した後、polkit と 1Password へ段階的に導入する。

---

## 19. デプロイと安全策

- インストール前に PAM 設定をバックアップする
- 設定変更を原子的に行う
- 構文エラー時にロールバックする
- SSH または別 root セッションを残して導入する
- パスワードフォールバックを既定で有効にする
- アンインストール時に PAM 設定を復元する
- verifier 停止、通信エラー、明示拒否のいずれでも `PAM_SUCCESS` を返さず、無期限にブロックしない
- `sufficient` 構成では Face ID の失敗と明示拒否後も下段のパスワード認証へフォールバックすることを既定動作とする
- helper が停止していても PAM 全体を破壊しない
- インストール直後およびパッケージ更新後に、対象の PAM 設定ファイルが存在し、有効な設定として読み込まれていることをヘルスチェックする
- `.pacsave`、`.pacnew` などへの退避や置換を検出し、Face ID が意図せず無効化された場合は管理者へ通知する

---

## 20. 代替案

### 20.1 PAM モジュール内で署名検証

利点:

- 構成が単純
- verifier daemon への IPC が不要
- 非特権 helper の成功通知を信用しない

欠点:

- PAM モジュールが厚くなる
- 暗号ライブラリやプロトコル更新が難しい
- PAM 呼び出し元ごとのクラッシュ影響が大きい

### 20.2 非特権 helper の `success` を信用

採用しない。

理由:

- 同一ユーザー権限のマルウェアが成功を偽造できる
- helper 差し替えに弱い
- ロック中の 1Password を保護する脅威モデルに合わない

### 20.3 WebAuthn / passkey / FIDO2

長期的には標準規格の利用が望ましい。

ただし、iPhone を Linux PAM からクロスデバイス認証器として自然に起動する経路は、ブラウザ WebAuthn と比べて実装・運用が未成熟である。

初期版は独自プロトコルとするが、以下を標準に近づける。

- challenge-response
- origin / RP 相当の用途束縛
- device public key
- user verification
- replay protection
- canonical encoding

将来、適切な PAM/WebAuthn ブリッジが利用可能になった場合は移行を検討する。

---

## 21. 未決事項

レビューで合意が必要な項目:

1. polkit action 単位に認証方式を分離できない制約を受容して `polkit-1` へ導入するか
2. 初期版を polkit 対応まで含めるか、専用 PAM サービスまでに制限するか
3. TLS 1.3 mutual authentication と Noise のどちらを採用するか
4. canonical encoding に CBOR、protobuf、JSON のどれを使うか
5. Linux verifier の端末秘密鍵をどこに保存するか
6. transport helper をユーザーごとに起動するか、system service とするか
7. iPhone アプリのバックグラウンド動作制約をどう扱うか
8. 同時に複数 iPhone を呼び出すか、優先順位を付けるか
9. verifier 再起動時に保留 request を全破棄する実装方法
10. PAM conversation に状態表示を出すか、デスクトップ通知に限定するか
11. 鍵登録と失効操作の管理 UX
12. 認証成功のキャッシュを許可するか
13. 対象環境の polkit rules で不要な action をどこまで制限するか

---

## 22. 推奨初期スコープ

最初の実装では以下に限定する。

- Linux 1台
- iPhone 1台
- 同一 LAN
- iPhone アプリを前面で開いている状態
- 1Password unlock を主用途とする（同じ `polkit-1` PAM スタックを使う action からの利用は分離不能）
- P-256 ECDSA
- root verifier daemon
- 非特権 transport helper
- QR コードによる相互ペアリング
- 30秒タイムアウト
- パスワードフォールバックあり
- 認証キャッシュなし
- APNs、BLE、複数端末、遠隔認証は対象外

---

## 23. 実装順序

1. iPhone 上で Secure Enclave 鍵を生成する
2. Face ID 後に固定 challenge へ署名する
3. Linux CLI で署名を検証する
4. canonical encoding を確定する
5. QR コードによる相互ペアリングを実装する
6. 相互認証された LAN 通信を実装する
7. 非特権 transport helper を実装する
8. root verifier daemon を実装する
9. CLI クライアントから end-to-end 認証する
10. PAM モジュールを実装する
11. 専用 PAM サービスでテストする
12. polkit と統合する
13. 1Password で検証する
14. fuzzing、リプレイ、MITM、失効テストを行う

---

## 24. セキュリティ判断の要約

本設計で最も重要な判断は以下である。

- Face ID の成否を送らず、Secure Enclave の署名を使う
- 非特権 helper の `success` を信用しない
- 最終判定を root verifier が行う
- チャレンジを root verifier が生成する
- nonce だけでなく、ユーザー、PAM サービスから導出した用途、端末、期限を署名対象に含める
- Linux と iPhone を相互認証する
- 通信路を暗号化するが、通信路だけを信用しない
- polkit 認証用署名を `sudo` や `login` など別の PAM サービスへ流用できないようにする
- 現行 polkit では action ID が PAM へ渡らず、同じ `polkit-1` 内の action 間分離は保証しない
- Face ID が使えない場合の回復経路を残す
- root 侵害は防御対象外と明示する

---

## 25. レビュー観点

レビュー担当者には、特に以下の確認を依頼する。

### セキュリティ

- 信頼境界は適切か
- 非特権 helper の侵害時にも認証偽造を防げるか
- 署名対象に不足するコンテキストはないか
- 用途束縛は十分か
- ペアリング時の MITM を防げるか
- 失効と回復手順は十分か
- iPhone に表示する情報は十分か

### Linux/PAM

- PAM の戻り値とフォールバック動作は適切か
- polkit action を確実に識別できるか
- PAM モジュールと verifier の責務分離は妥当か
- 導入時にログイン不能となるリスクを抑えられるか

### iOS

- `.biometryCurrentSet` の挙動は要件に合うか
- Face ID 成功の再利用を防げるか
- バックグラウンド制約下で現実的な UX か
- Secure Enclave 署名形式と鍵失効処理は妥当か

### 運用

- iPhone 紛失時に安全かつ迅速に失効できるか
- 複数端末、再インストール、機種変更に拡張できるか
- ログがプライバシーを侵害しないか
- パスワードフォールバックが安全に維持されるか

---

## 26. 変更履歴

### v0.2.0（2026-07-10）

- polkit では action ID が PAM へ渡らず、同じ `polkit-1` PAM スタックを使う action 間で認証方式を分離できないことを明記した。
- `requested_action` を信頼できる `PAM_SERVICE` から導出し、helper や表示文字列が申告する用途を信用しない設計へ変更した。
- polkit の `rules.d` は action ごとの認可ポリシーに使用できるが、PAM モジュールを action ごとに選択する機構ではないことを明記した。
- ペアリング比較コードを、双方の公開鍵、device ID、ペアリング nonce、プロトコルバージョンを含む正規化済みトランスクリプトのハッシュから導出するよう規定した。
- Linux 側の TTL 判定を verifier の monotonic clock に基づかせ、`issued_at` / `expires_at` は iPhone 側の表示と期限確認に用いるよう整理した。
- request ID の保留確認と消費をアトミックに行い、並行応答による二重検証を拒否することを明記した。
- 初期版の暗号化チャネルは非特権 transport helper で終端し、認証の完全性は verifier のチャレンジと Secure Enclave 署名の連鎖で確保することを明記した。
- verifier 停止、通信エラー、Face ID の明示拒否時には `PAM_SUCCESS` を返さず、`sufficient` 構成ではパスワード認証へフォールバックする動作を明確化した。
- PAM 設定がパッケージ更新で退避または置換された場合に備え、更新後のヘルスチェックと `.pacsave` / `.pacnew` の検出を追加した。
- Face ID 限定では `.biometryCurrentSet` を使用し、端末パスコードを許容する場合は別のアクセス制御フラグが必要であることを明記した。
- `pam_sm_acct_mgmt()` を状態変更のない明示的な no-op として定義した。
