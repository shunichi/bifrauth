# bifrauth 実装計画（ドラフト v0.5）

**対象:** `docs/iphone-faceid-linux-pam-design.md`（v0.3.2）の実装
**このドキュメントの範囲:** ソフトウェア構成、ディレクトリ構成、使用言語・技術、Linux/Mac の作業分担、実装フェーズの決定。詳細なプロトコル仕様は設計書に従う。
**現在の到達点（進捗）:** 本ファイルは「意図」を記す。各フェーズの現在の done/残りは `docs/progress.md` を参照。
**改訂:** v0.2 で codex レビュー第1巡の指摘（1〜9）を反映。v0.3 で第2巡の blocking（§4.2 の P-256 署名 API 固定）と軽微（§5 P3 の cross-platform 前提明示）、および第3巡の非blocking編集提案（§4.2 digest API 注記を将来判断事項へ移動）を反映。v0.4 でプロジェクト名 BifrAuth 採用に伴うコンポーネント改名（`bifrauthd` / `bifrauth-transport` / `bifrauthctl` / `pam_bifrauth` / 専用テスト PAM サービス `bifrauth-test`）を反映（技術的内容は不変、名前のみ。命名は `docs/naming.md`）。**v0.5 で §4.9（identity 解決＝NSS/uzers、glibc 動的リンク前提・musl 静的非ゴール）を追加（ユーザー承認済み・2026-07-14）。codex 設計レビュー第1巡（uzers は不在/一時エラーを区別できないとの指摘）とユーザー決定（ローカル個人利用中心・uzers 維持・区別要件は外す）を反映し、canonical pw_name 束縛・逆引き不要・NSS/PAM timeout の配備要件・cache 不使用を追記。**
**レビュー状況:** v0.3 の内容は codex による3巡のクロスレビューで **承認済み**。v0.4 は改名のみで技術的内容は不変。**v0.5 の §4.9 は codex 設計レビュー第2巡を依頼中。**

---

## 1. 全体方針

- **モノレポ**で管理する。Linux 側（Rust）と iOS 側（Swift）を同一リポジトリに置き、`docs/` の設計書と近接させる。
- **Linux 側を先に、このマシンで実装・テストする。** iPhone アプリ（Swift）は Secure Enclave / Face ID / LocalAuthentication を要するため、後で Mac 上で実装する。
- iPhone を待たずに Linux 側を end-to-end で開発・テストできるよう、**ソフトウェアで iPhone を模擬する `mock-iphone`** を用意する。これは Secure Enclave の代わりにソフトウェア上の P-256 鍵で「Face ID 後の署名」を再現し、設計書 §23 の手順 1〜11 相当をこのマシンだけで検証可能にする。
- **Rust と Swift はコードを共有できない。** 実装間で共有する成果物は「プロトコル仕様（canonical encoding の bifrauth プロファイル）」と「golden / negative テストベクタ」であり、これらを一次成果物として管理する。

---

## 2. 使用言語・技術（設計書 §17 を踏まえた確定案）

| コンポーネント | 言語 | 主要技術・クレート（候補） |
|---|---|---|
| verifier daemon `bifrauthd` | **Rust** | tokio / std, systemd socket activation, ed25519-dalek, p256, sha2, rand |
| PAM モジュール `pam_bifrauth.so` | **Rust（cdylib）** | 手書き最小 FFI もしくは `pam` バインディング。profile で `panic = "unwind"` を保証し、各 `extern "C"` 入口を `catch_unwind` で包む |
| transport helper `bifrauth-transport` | **Rust** | 通信・mDNS（`mdns-sd` 等）・暗号チャネル（TLS 1.3 mTLS, `rustls`） |
| 管理 CLI `bifrauthctl` | **Rust** | 登録・失効・デバイス一覧 |
| 共有ロジック | **Rust クレート群**（下記） | canonical encoding / crypto / IPC |
| `mock-iphone`（テスト用） | **Rust** | ソフト P-256 鍵で iPhone 側処理を再現。golden/negative ベクタの生成にも用いる |
| iPhone アプリ | **Swift**（後で Mac） | LocalAuthentication, Security.framework（ECDSA message API）, Keychain, Secure Enclave, Network.framework（TLS 1.3）, CryptoKit |

**PAM モジュールを C ではなく Rust とする理由:** メモリ安全性・入力長制限の重視（設計書 §17.1）、verifier/helper/共有クレートとの型・プロトコル共有。FFI 境界での panic 遮断を必須要件とする（§4-6）。

---

## 3. ディレクトリ構成

```text
bifrauth/
├── Cargo.toml                  # Rust ワークスペース定義
├── rust-toolchain.toml         # ツールチェイン固定
├── crates/
│   ├── bifrauth-proto/         # メッセージスキーマ, canonical encoding(bifrauth CBORプロファイル), バージョニング
│   ├── bifrauth-crypto/        # Ed25519署名/検証, P-256検証, SHA-256, CSPRNG(nonce/request_id/確認コード)
│   ├── bifrauth-ipc/           # Unixソケットのフレーミング, SO_PEERCRED, 長さ上限, タイムアウト
│   ├── bifrauthd/              # root verifier daemon（bin）
│   ├── bifrauth-transport/     # 非特権 transport helper（bin）
│   ├── pam_bifrauth/           # PAM モジュール（cdylib → pam_bifrauth.so）
│   ├── bifrauthctl/            # 管理 CLI（bin）
│   └── mock-iphone/            # iPhone 模擬（bin + lib、テストで共用）
├── spec/
│   ├── cbor-profile.md         # canonical encoding の bifrauth プロファイル仕様
│   └── vectors/                # golden / negative テストベクタ（Rust・Swift 双方が参照）
├── ios/                        # Swift アプリ（後で Mac 上で実装。今はプレースホルダ + README）
├── dist/
│   ├── systemd/                # bifrauthd.service, bifrauthd.socket
│   └── pam/                    # 例: /etc/pam.d/bifrauth-test, インストール/検証スクリプト
├── tests/                      # ワークスペース横断の統合テスト
└── docs/                       # 設計書・レビュー・本計画
```

**クレート分割の意図:** canonical encoding（`bifrauth-proto`）と暗号処理（`bifrauth-crypto`）を独立クレートにし、fuzzing と単体テスト（設計書 §18.1）を集中させる。プロトコル型を verifier / helper / PAM / mock-iphone が共有し、実装間のバイト列一致（§9.4）を保証しやすくする。`spec/` は Rust/Swift が共有できない代わりの一次成果物。

---

## 4. 確定事項と要決定事項（codex レビュー第1巡を反映）

### 4.1 canonical encoding
- **Deterministic CBOR を採用**。ただし RFC 8949 §4.2 とライブラリ名だけでは不足。`spec/cbor-profile.md` に **bifrauth プロファイル**を固定する:
  - 整数 map キーによるスキーマ、definite length、shortest encoding、**map キー順の規定**、float/tag の禁止、**未知キー・重複キーの拒否**、文字列の正規化方針、各フィールドとメッセージのサイズ上限。
- 実装は「decode 後に再 encode して比較」ではなく、**受信バイト列そのものの canonicality を検査**できること。採用ライブラリ（`ciborium`/`minicbor` 等、Swift 側 `SwiftCBOR` 等）がこれを満たすか P0 で確認する。
- 共有物は crate ではなく **仕様 + golden vectors**。

### 4.2 P-256 相互運用（署名 API・hashing・形式）
- raw / DER を未決のまま P0 に入らない。**API 定数・入力・出力を次に固定し、二重 hash を防ぐ:**
  - iPhone（Swift）: `SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, canonical_challenge_bytes, &error)` を用いる。**入力は未ハッシュの canonical bytes** とし、SHA-256 は Security.framework が**ちょうど1回**行う。**事前計算した 32-byte digest を渡してはならない。** 署名出力は **X9.62 DER**。
  - Rust 側（p256）の検証も、**同一の canonical bytes に対する ECDSA/SHA-256**（`signed_payload_hash = SHA-256(canonical_challenge)`、署名対象は canonical bytes 全体）とする。
  - Rust / Swift の **独立実装 golden / negative ベクタ**を P0 必須成果物とする。
- **（将来変更時の判断事項）** 初版は message API（`.ecdsaSignatureMessageX962SHA256`）に固定する。将来 digest API へ変更する場合のみ、`.ecdsaSignatureDigestX962SHA256` に SHA-256 値を渡す方式へ**一本化**し、message API と digest API を混在させないこと。

### 4.3 署名対象と応答の扱い
- verifier Ed25519 と iPhone P-256 の双方が **canonical_challenge 全体**へ署名。request_id / nonce / uid / username / PAM_SERVICE 由来用途 / device / 期限 / 確認コードの束縛は設計書と整合。
- **応答の `signed_payload_hash` を認証入力として信用しない。** `bifrauthd` は保留中要求の canonical bytes から自分で再計算し、それに対して署名検証する。
- `iphone_device_id` は**鍵選択のヒントに留める**。選択した登録公開鍵での署名検証成功が本人性の根拠。

### 4.4 トランスポート暗号チャネル（方針変更）
- **初版は TLS 1.3 mTLS を採用**（旧 v0.1 の Noise IK 推奨を撤回。Swift 側 Noise 実装の成熟度が未解消のため）。
  - ペアリング transcript で**双方の SPKI をピン留め**し、Web PKI に依存しない。**0-RTT 禁止**。
  - **helper のチャネル鍵と verifier 署名鍵を分離**（設計書 §10.1）。
  - 証明書・鍵アルゴリズムは Network.framework と rustls の**共通集合（例: P-256）へ固定**。
- **P3 着手の前提条件**として、Network.framework(iPhone/Mac) ↔ rustls(Linux) の相互接続 **spike** を Mac で実施。spike 失敗時のみ Noise を再評価する。

### 4.5 helper IPC / 起動形態
- transport helper は**ユーザーセッションのサービス**（対象ユーザー権限、設計書 §6.3）。
- `bifrauthd`（root）が **target UID のどの helper へどう到達するか**を先に規定する（例: `/run/user/<uid>/…`）。SO_PEERCRED、所有者/モード、UID 対応付け、framing・長さ上限・timeout を定義。
- **同一 UID の偽 helper**は DoS・平文閲覧は可能でも、未検証 success や challenge 改変では認証成功できないことをテストで確認。

### 4.6 PAM FFI
- `catch_unwind` 必須。profile で **`panic = "unwind"` を保証**し、全 `extern "C"` 入口を包む。panic 時は **`PAM_SYSTEM_ERR`**。null / 非 NUL 終端 / 過長文字列、argc/argv、`pam_get_item`、conversation callback を厳格検証。
- catch_unwind は **OOM abort や不正 C ポインタは救えない**点を前提化。
- export symbol / ABI の検査と**実 PAM ロードテスト**を P6 に追加。

### 4.7 verifier 端末秘密鍵の保存
- `/etc/bifrauthd/verifier_key`（root:root **0600**、親 dir **0700**）。**atomic create**、**symlink / 非通常ファイルの拒否**、**既存鍵の黙示的再生成禁止**、fsync / バックアップ取扱いを要件化。将来 TPM 保護を検討。

### 4.8 初期スコープ（polkit 可否）
- **まず専用 PAM サービスまで**を確実に完成。polkit / 1Password 統合は iPhone 実機が揃う Mac 段階（フェーズ7）。

### 4.9 identity 解決（username→uid）とリンク方針（ユーザー承認済み・2026-07-14）
- **username→uid の解決は NSS 経由**（PAM/login と**同一の権威データベース**）で行う。理由は confused-deputy
  対策（ipc-design §3）: daemon が uid を wire 入力ではなく OS のアカウント DB から引き直し、
  「この username は確かにこの uid」を保証してから challenge を発行する。`/etc/passwd` 直読みは不可
  （SSSD/LDAP/AD ユーザーを取りこぼし、login 経路と判断がズレる）。
- **依存クレート: `uzers` 0.12.2（最新安定版）**。libc 直（unsafe FFI）・nix（過大）ではなく uzers を採用
  （安全・目的特化・**リエントラント `getpwnam_r`** 利用。マルチスレッドのワーカープールで必須）。
  uzers 0.12.2 が `getpwnam_r`＋ERANGE バッファ倍増を使うことは codex レビューで確認済み。
- **配備は glibc 動的リンク前提**（`x86_64-unknown-linux-gnu`、`+crt-static` を付けない）。
  **musl 静的リンクは非ゴール**: musl は NSS プラグイン非対応で SSSD/LDAP/AD を解決できず、認証判断が
  login 経路とズレるため。`pam_bifrauth` は `libpam` に load される cdylib で元々 glibc 動的であり、
  daemon だけ musl 静的にしても一貫しない。配布は systemd unit + PAM 設定のパッケージ形態で、
  「単一可搬静的バイナリ」は最初から配布モデルではない。
- **スコープ: ローカル個人利用中心（ユーザー決定・2026-07-14）。** 主ターゲットはローカル `/etc/passwd`
  ユーザーのワークステーション。SSSD/LDAP/AD は当面の主対象ではない。
- **fail closed の割り当て（区別しない）**: uzers の `get_user_by_name` は `Option<User>` で、**「不在」と
  「一時 NSS エラー（SSSD 応答不能等）」を両方 `None` に潰す**（codex 確認済み）。ローカル運用では一時エラーは
  ほぼ発生しないため、**両者を区別せず一律 deny（challenge を発行せず接続を閉じる → PAM はパスワードへ
  フォールバック）**とする。両方 fail closed（fail-open にならない）で、**認証成功の安全性には影響しない**が、
  可用性・観測性・PAM エラー分類には影響する（区別を捨てるのは初期スコープでこの観測性/分類を諦める意味）。
  - 区別が要る局面（SSSD 障害の観測性、`PAM_USER_UNKNOWN` と `PAM_AUTHINFO_UNAVAIL` の撃ち分け）は
    **将来のエンタープライズ対応時の拡張**とする。その際は `libc::getpwnam_r` の薄い wrapper
    （`Result<Option<_>, ResolveError>`）＋ wire の pre-issue エラー応答＋PAM 写像が必要（本タスク範囲外）。
- **canonical identity**: 逆引き（`getpwuid_r` 往復）は**行わない**。uzers `User` の **`name()`（レコードの
  canonical pw_name）と `uid()` をそのまま challenge の identity として束縛**する。理由: 逆引き必須化は
  正当な alias/大小文字マッピングを拒否し、2 回の NSS lookup 間の TOCTOU を増やすため（codex 推奨）。
  要求された username と canonical name が異なる場合は**機密でない監査イベント**とし、**同一 UID 束縛**を
  security identity とする。
- **可用性（配備要件）**: `getpwnam_r`/NSS は同期呼び出しで、**CLOCK_BOOTTIME の overall deadline では
  SSSD/LDAP の hang を強制中断できない**。したがって「daemon の 30 秒が NSS を必ず中断する」とは書かない。
  NSS/SSSD 側 timeout と **PAM 側 30 秒 timeout** を配備要件とする。resolver 呼び出しは verifier lock の外
  （session で担保済み）。**negative cache / `UsersCache` は使わない**（認証 identity 変更の反映が遅れるため）。

---

## 5. 実装フェーズ（Linux/Mac の分担と完了条件を明示）

設計書 §23 を「このマシン（Linux, Rust, mock-iphone）で可能」と「Mac/iPhone 実機が必要」に振り分ける。各フェーズは下記の**完了条件**を満たすこと。

### このマシンで実施（Rust + mock-iphone）

- **P0 基盤:** ワークスペース雛形、CI。`bifrauth-proto` の canonical encoding（bifrauth CBOR プロファイル、§4.1）と単体テスト。**P-256 の署名 API・hashing・形式の確定（§4.2）と golden/negative ベクタ**を成果物とする。
  - 完了条件: 受信バイト列の canonicality 検査が通る／golden ベクタが Rust 実装で再現／negative ベクタ（malformed, 未知/重複キー, oversized, unsupported version）を拒否。
- **P1 暗号:** `bifrauth-crypto`（Ed25519 verifier 署名、P-256 検証、CSPRNG）＋ `mock-iphone` の署名（§23-1〜3,5 を mock で）。
  - 完了条件: 確認コードの一様生成、downgrade / unsupported algorithm 拒否。
- **P2 ペアリング:** QR トランスクリプトのハッシュと SAS 導出（§8.2, §23-6）を mock で。
  - 完了条件: allowlist 変更は再ペアリングでのみ可能（challenge では拒否）。
- **P3 トランスポート（cross-platform 前提あり・唯一 Linux 完結でないフェーズ）:** TLS 1.3 mTLS（§4.4）+ `bifrauth-transport` を mock-iphone とループバック/LAN で（§23-7,8）。**このフェーズは着手条件として Mac で Network.framework↔rustls spike を通す必要があり、Linux 側の本実装は spike 完了待ちとなる。** spike 失敗時のみ Noise を再評価（§4.4）。
- **P4 verifier + IPC:** `bifrauthd`、root ソケット IPC（§4.5）、`bifrauthctl` から end-to-end（§23-9,10）。
  - 完了条件: request_id の verify 開始時 **atomic consume**（不正署名でも消費）、CLOCK_BOOTTIME による **suspend 込み TTL**、同一 UID 偽 helper が成功できないこと（§4.5）。
- **P5 number matching（状態機械）:** PAM conversation ↔ iPhone の6桁照合の**状態機械 + テストクライアント**（実 PAM conversation は P6 へ）。iPhone は受信コードを表示・自動補完せず照合のみ。
- **P6 PAM:** `pam_bifrauth.so` と専用 PAM サービス `bifrauth-test`（§23-12,13）。symbol/ABI 検査・実 PAM ロードテスト（§4.6）。
  - 完了条件: Face ID 拒否・未到達・timeout・daemon/helper 停止・malformed の各ケースで **`PAM_SUCCESS` にならず**、`sufficient` の下段 password へ到達する統合テスト。
- 各フェーズでセキュリティテスト（設計書 §18.3）の該当項目を完了条件へ組み込む。

### 後で Mac / iPhone 実機で実施（Swift）

- iPhone アプリ本体（Secure Enclave 鍵生成、Face ID ゲート、承認画面、確認コード入力）。§4.2 の署名 API を実機で確定。
- 実機の Secure Enclave 署名で §23-1〜3 を再検証（golden ベクタと突合）。
- 対象 polkit エージェントの同一ダイアログ表示の実機確認（§23-14）。
- polkit 統合（§23-15）、1Password 検証（§23-16）、実機を含む end-to-end セキュリティテスト（§23-17）。

`mock-iphone` と実 iPhone は `spec/` の同一プロファイルと golden vectors を共有するため、Linux 側は実機到着後の作り直しを避けられる。

---

## 6. 最初の具体的アクション（合意後）

1. リポジトリ直下に Rust ワークスペースを作成（`Cargo.toml`, `rust-toolchain.toml`, `crates/*` の空クレート、`spec/`・`ios/`・`dist/` の雛形）。
2. `spec/cbor-profile.md` を書き、`bifrauth-proto` に canonical encoding とメッセージ型、受信バイト列 canonicality 検査、往復テストを実装。
3. P-256 の署名 API・hashing・形式を確定し、`bifrauth-crypto` + `mock-iphone` で「固定 challenge への署名 → 検証」を通し、golden / negative ベクタを `spec/vectors/` に確定（§23-1〜5 の mock 版）。
