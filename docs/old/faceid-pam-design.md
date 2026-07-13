# iPhone Face ID による Linux PAM 認証 — 設計書

## 1. 概要

Linux 上の 1Password を、iPhone の Face ID で解錠できるようにする。1Password for Linux
の「system authentication（システム認証）」は認証を polkit と PAM に委譲する設計になっており、
PAM は Linux アカウントが使えるあらゆる認証方式を継承する。したがって **iPhone の Face ID を
1つの PAM 認証方式として実装すれば、1Password は改変せずにそのまま解錠に使える。**

本書はその PAM モジュールと周辺コンポーネントの設計をまとめる。実装は別途。

## 2. ゴールと非ゴール

### ゴール
- iPhone の Face ID を用いて Linux 側の PAM 認証を成立させる。
- 1Password（polkit 経由）のアンロックに使えること。`pkexec` / `sudo` など他の
  polkit / PAM 利用箇所にも応用可能な汎用モジュールとする。
- Face ID 失敗時はアカウントパスワードにフォールバックできること。

### 非ゴール
- 生体データそのものを Linux 側へ転送すること（原理的に不可能かつ不要）。
- 全ネットワーク環境での動作（初期版は同一 LAN もしくは BLE 近接を前提とする）。
- 1Password のアカウントパスワードの置き換え（暗号化はアカウントパスワードに依存したまま）。

## 3. 中核となるセキュリティ原則

**「Face ID 成功」という真偽値を送ってはならない。** boolean をネットワーク越しに渡す設計は
なりすまし・リプレイし放題になる。

代わりに **Face ID を「Secure Enclave 内の秘密鍵へのアクセス許可」として使い、その鍵で
チャレンジに署名させる**。Linux 側は「新しい nonce に対する正しい署名が返ってきた」という
一点のみで、以下の 2 つを同時に確認できる。

1. 正しい秘密鍵の所持（= 登録済みの iPhone であること）
2. 直近の Face ID 成功（署名が Secure Enclave でゲートされているため）

秘密鍵は Secure Enclave から外に出ず、生体照合はハードウェアがローカルで強制する。

## 4. コンポーネント構成

責務を分割し、特権コードを最小化する。

| コンポーネント | 権限 | 責務 |
|---|---|---|
| PAM モジュール（`.so`） | root（polkitd から呼ばれる） | nonce 生成、署名検証、成否判定のみ。薄く保つ。 |
| ヘルパーデーモン | ユーザーセッション | iPhone との通信（BLE / LAN）、UI 表示（「iPhone を確認」等） |
| iPhone アプリ | — | Secure Enclave 鍵の管理、Face ID ゲート、チャレンジへの署名 |

PAM モジュールとヘルパーは **Unix ドメインソケット** で通信する。iPhone とやり取りする複雑な
コードを非特権プロセスに閉じ込めることで、root コンテキストの攻撃面を小さくする
（ssh-agent / polkit agent と同じ発想）。

```
[1Password] → polkit → [PAM module (root)]
                              │  unix socket
                              ▼
                        [helper daemon (user)]
                              │  BLE / LAN
                              ▼
                        [iPhone app] → [Secure Enclave] → Face ID
```

## 5. 登録フロー（Enrollment）

初回のみ実施する。

1. iPhone アプリが Secure Enclave 内に P-256 鍵ペアを生成する。
   - `kSecAttrTokenIDSecureEnclave`、`kSecAttrKeyTypeECSECPrimeRandom`（256bit）
   - アクセス制御を `SecAccessControlCreateWithFlags` で作成し、
     `.privateKeyUsage` + `.biometryCurrentSet` を指定。署名操作に Face ID を必須にする。
2. 公開鍵のみを Linux 側へ登録する（ヘルパー経由でユーザーの設定ディレクトリに保存）。
   - 例: `~/.config/faceid-pam/enrolled_keys/<device-id>.pub`
3. 登録時にデバイス識別子・登録日時などのメタ情報も併せて保存する。

`.biometryCurrentSet` を使うことで、後から別の顔・指紋が iPhone に登録された時点で鍵が
失効し、第三者が生体を追加して突破する経路を塞げる。

## 6. 認証フロー（Runtime）

1. 1Password がアンロックを要求 → polkit → PAM モジュールが呼ばれる。
2. PAM モジュールがランダムな **nonce** を生成する（十分なエントロピー、短い TTL）。
3. PAM モジュールが nonce をヘルパーへ渡し、ヘルパーが iPhone へ challenge を送信する
   （BLE または LAN）。challenge には nonce に加えて **セッション/コンテキスト識別子** を含める。
4. iPhone アプリが Secure Enclave に署名を依頼 → 署名操作のトリガーとして **Face ID が発火**。
   - 署名アルゴリズム: `.ecdsaSignatureMessageX962SHA256`
5. Face ID 成功時のみ Secure Enclave が challenge に署名し、署名をヘルパーへ返す。
6. PAM モジュールが登録済み公開鍵で署名を検証する。
   - nonce が発行済みのものと一致し、TTL 内で、コンテキスト識別子が一致することも確認。
7. 検証成功 → `PAM_SUCCESS` を返す → 1Password がアンロックされる。
   - 失敗・タイムアウト時は `PAM_AUTH_ERR` を返し、下段のパスワード認証へフォールバック。

## 7. トランスポート方式（トレードオフ）

| 方式 | 長所 | 短所 | 位置づけ |
|---|---|---|---|
| LAN（mDNS + TCP） | 実装が最も単純 | 同一ネットワーク前提 | **初期版に推奨** |
| BLE | 近接時のみ解錠。Touch ID に近い体験 | 実装が重い | 体験重視なら |
| APNs + 中継サーバー | 場所を選ばない | サーバー依存・遅延・APNs 設定が必要 | 個人利用にはオーバースペック |

チャネル自体が MitM 可能でも、署名検証と nonce/コンテキスト束縛により安全性は保たれる。
ただし後述のリプレイ・セッション束縛対策は必須。

## 8. セキュリティ考慮事項

- **リプレイ対策**: nonce は毎回新規発行・使い捨て。短い TTL を設定し、使用済み nonce は破棄。
- **セッション束縛**: challenge にセッション/コンテキスト識別子を含め、署名対象に入れる。
  MitM が別セッションへ署名を流用できないようにする。
- **鍵失効**: `.biometryCurrentSet` により生体登録変更で鍵を失効させる。
- **PAM タイムアウト**: 認証が永久にハングしないよう適切なタイムアウトで失敗を返す。
- **特権最小化**: root で動く PAM モジュールは検証と成否判定のみ。通信は非特権ヘルパーに委譲。
- **アカウントパスワードの保全**: system authentication は暗号化鍵を置き換えない。普段パスワードを
  打たなくなると忘れやすいので、必ずどこかに控えておく。
- **強制利用への配慮**: 生体は本人の意思に反して（就寝中・意識喪失時など）使われうる。懸念が
  ある状況では system authentication を無効化できるようにしておく。

## 9. 1Password との統合

出来上がった `.so` を polkit の PAM スタックに差し込む。

`/etc/pam.d/polkit-1`:
```
auth    sufficient  pam_iphone_faceid.so
auth    include     system-auth
account include     system-auth
password include    system-auth
session include     system-auth
```

- `sufficient` にすると、iPhone 認証が通ればそれで解錠、失敗時は下段のパスワード認証へ
  フォールバックする。
- 1Password 側は Settings > Security > 「Unlock using system authentication」を有効化するだけ。
  モジュール固有の設定は不要（system auth が PAM を継承するため）。
- ウィンドウマネージャ（i3 / sway 等）を使う場合は、polkit の認証エージェントが起動している
  ことを別途確認する（GNOME / KDE は自動起動）。

## 10. テスト方針

1Password で試す前に、polkit 単体で切り分ける。

```
pkexec whoami
```

これで iPhone への challenge → Face ID → 検証 の一連が発火し、成功すれば解錠プロンプトが通る。
段階的な進め方:

1. **最小構成**: LAN + 単純な challenge-response（生体なし・固定鍵）で PAM ↔ アプリの往復を通す。
2. Secure Enclave 署名を追加。
3. Face ID ゲート（`.biometryCurrentSet`）を追加。
4. リプレイ・セッション束縛・タイムアウト等の堅牢化。
5. 1Password への接続確認。

## 11. 標準規格による代替案（参考）

自分でアプリを作らない場合、iPhone は passkey / FIDO2 authenticator として振る舞えるため、
Linux 側を `pam_u2f` 系で済ませる構成が本来はきれい。ただし iPhone をクロスデバイスの
authenticator として使う経路（caBLE / hybrid transport）はブラウザの WebAuthn フロー向けで、
**Linux の PAM から駆動する側のツールが未成熟**。自作アプリ前提なら、本書の独自プロトコル +
Secure Enclave 署名のほうが素直で確実。

## 12. 未決事項 / 今後の検討

- ヘルパー ↔ iPhone のペアリング/初期信頼確立の UX（QR コード交換など）。
- 複数 iPhone の登録・失効管理。
- iPhone が応答しない場合のフォールバック体験（タイムアウト値、UI 表示）。
- BLE を採用する場合の具体的なプロトコル設計。
- ロック画面での「iPhone を確認してください」表示を PAM conversation 関数で出すか、
  ヘルパー側の通知で出すか。

---

### 参考: 主要な API / パス

- PAM: `pam_sm_authenticate`（`.so`、C または Rust）、戻り値 `PAM_SUCCESS` / `PAM_AUTH_ERR`
- polkit: `/etc/pam.d/polkit-1`、`/usr/share/polkit-1/actions/com.1password.1Password.policy`
- iOS Secure Enclave: `SecKeyCreateRandomKey`、`SecAccessControlCreateWithFlags`
  （`.privateKeyUsage` + `.biometryCurrentSet`）、`SecKeyCreateSignature`
  （`.ecdsaSignatureMessageX962SHA256`）
