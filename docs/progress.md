# bifrauth 進捗状況

> **現状のスナップショット**。「何を・どの順で・完了条件は何か」という**安定した意図**は
> `docs/implementation-plan.md`（フェーズ P0–P6）と設計書 §23（実装順序）にある。本ファイルは
> それらに対する**現在の到達点**を記録する（更新頻度が高いので plan 本文とは分離）。
>
> 最終更新: 2026-07-14

## 凡例

- ✅ 完了（レビュー合意・main マージ済み）
- 🟡 一部実装（コアはあるが本番配線 or 一部機能が未了）
- ⛔ ブロック中（前提条件待ち）
- ⬜ 未着手

## サマリ

Linux 側（Rust + mock-iphone）の基盤〜verifier+IPC+管理 CLI+number matching までが完了
（P0–P5 + NSS resolver）。残りは **P6 PAM**（Linux 完結・未着手）と、**P3 トランスポート**
（Mac の spike 待ちでブロック）。本番 daemon の稼働（`bifrauthd` の serve 有効化）は P3 と
「管理変更の transactional reload」の完成が前提。

## フェーズ別

| フェーズ | 状態 | 内容 | 根拠 |
|---|---|---|---|
| P0 基盤 | ✅ | ワークスペース雛形、CI（fmt/clippy/test, Rust 1.97）、`bifrauth-proto`（canonical CBOR プロファイル `spec/cbor-profile.md`、golden/negative ベクタ） | task 0001/0002/0005 |
| P1 暗号 | ✅ | `bifrauth-crypto`（Ed25519 署名/検証、P-256 検証 strict DER、SHA-256、CSPRNG）＋ `mock-iphone`（ソフト P-256 署名） | task 0003/0004 |
| P2 ペアリング | ⬜ | QR トランスクリプトのハッシュ / SAS 導出（設計書 §8.2, §23-6）。設計のみ、未実装 | — |
| P3 トランスポート | ⛔ | TLS 1.3 mTLS + `bifrauth-transport`。**着手条件: Mac で Network.framework↔rustls spike を通すこと**（implementation-plan P3）。`bifrauth-transport` はスタブ | crate スタブ |
| P4 verifier + IPC | ✅ | `bifrauthd` verifier コア、root ソケット IPC、`bifrauthctl`、mock 経由 end-to-end | task 0007/0008/0009 |
| P5 number matching | ✅ | iPhone 側 6桁照合の承認状態機械（mock-iphone `Approval`）+ テストクライアント。外部 user-entered code で駆動・コード非露出・注入 clock で timeout・型状態で単回。verifier 側状態機械は P4 済 | task 0011 |
| P6 PAM | ⬜ | `pam_bifrauth.so` + 専用サービス `bifrauth-test`、symbol/ABI 検査、フォールバック契約の統合テスト（§23-12,13）。`pam_bifrauth` はスタブ | crate スタブ |
| NSS resolver | ✅ | `UzersResolver`（NSS 経由 username→uid、glibc 動的リンク方針確定） | task 0010 |

## クレート実装状況

| crate | 状態 | 備考 |
|---|---|---|
| `bifrauth-proto` | ✅ | canonical CBOR（層A/層B）、challenge/response/envelope スキーマ、text policy |
| `bifrauth-crypto` | ✅ | Ed25519 / P-256 / SHA-256 / CSPRNG |
| `bifrauth-ipc` | ✅ | wire/frame/deadline/clock/transport port（PAM↔verifier IPC） |
| `mock-iphone` | 🟡 | 署名往復 + **number matching 承認状態機械**（`Approval`: 照合・Face ID 注入・timeout・単回）実装（task 0011）。**未実装**: iPhone 側 expiry/replay（別タスク）、purpose allowlist（P2）、実 Secure Enclave |
| `bifrauthd`（lib） | ✅ | verifier コア・session・serve・systemd・resolver・registry |
| `bifrauthd`（bin/main.rs） | 🟡 | **本番未配線**（Transport=P3・verifier_key ロード・reload 待ちで serve を有効化していない） |
| `bifrauthctl` | ✅ | register/revoke/list（永続レジストリ、NSS 解決、root 専用） |
| `bifrauth-transport` | ⬜ | スタブ（P3、ブロック中） |
| `pam_bifrauth` | ⬜ | スタブ（P6） |

## 設計書 §23 実装順の対応

| # | 手順 | 状態 | 備考 |
|---|---|---|---|
| 1 | iPhone Secure Enclave 鍵生成 | ⬜ | Swift/実機（mock で代替中） |
| 2 | Face ID 後に固定 challenge 署名 | ✅(mock) | `mock-iphone` |
| 3 | Linux CLI で署名検証 | ✅ | `bifrauth-crypto` + ベクタ |
| 4 | canonical encoding 確定 | ✅ | `spec/cbor-profile.md` |
| 5 | verifier Ed25519 署名 + iPhone 検証 | ✅ | crypto + mock-iphone |
| 6 | QR 相互ペアリング | ⬜ | P2 |
| 7 | 相互認証 LAN 通信 | ⛔ | P3（Mac spike 待ち） |
| 8 | 非特権 transport helper | ⛔ | P3（`bifrauth-transport` スタブ） |
| 9 | root verifier daemon | 🟡 | コア/IPC/レジストリは完了、本番配線が P3・verifier_key・reload 待ち |
| 10 | CLI から end-to-end 認証 | ✅(test) | task 0009 の実 socket 統合テスト（mock-iphone Transport 注入）。runnable auth client は task B へ |
| 11 | number matching | ✅ | task 0011（P5）。iPhone 側照合を mock-iphone `Approval` に実装、NumberMatchingTransport で socket 経路も matching 化 |
| 12 | PAM モジュール | ⬜ | P6 |
| 13 | 専用 PAM サービスでテスト | ⬜ | P6 |
| 14 | polkit エージェント同一ダイアログ実機確認 | ⬜ | 実機 |
| 15 | polkit 統合 | ⬜ | 実機 |
| 16 | 1Password 検証 | ⬜ | 実機 |
| 17 | fuzzing / replay / MITM / 失効テスト | 🟡 | replay・失効は単体/統合テスト済み。fuzzing・MITM は未 |

## 残作業（Linux 完結・優先度順）

1. **P6 PAM モジュール**（§23-12,13）— フォールバック契約（Face ID 拒否/未到達/timeout/daemon 停止/malformed で `PAM_SUCCESS` にならず password 下段へ）を完了条件に。P5 が前提を解いた。
2. **verifier_key(§4.7) のファイル生成/ロード + `Zeroizing<[u8;32]>` シード API** — task 0009 で別出しにしたフォローアップ。本番 daemon 起動に必要。レジストリと同じファイル安全性作法を再利用。
3. **iPhone 側 expiry / request_id replay**（task 0011 で別出し）— §9.5 は承認画面前の検証として列挙。TTL/replay の権威は verifier（P4 済）で、iPhone 側は defense-in-depth の重複実装。mock-iphone は現状これを実装せず partial。
4. **fuzzing / MITM テスト**（§23-17 の残り）。

## Blocking dependency（本番稼働の前提）

- **P3 トランスポート**: Mac で Network.framework↔rustls の spike を通すまで Linux 側の本実装に着手しない（設計判断）。`bifrauthd` の本番 serve 配線もこれ待ち。
- **管理変更の transactional reload**（管理 IPC もしくは SIGHUP 等）: `bifrauthctl` の register/revoke は永続化のみで**稼働中 daemon には再起動まで反映されない**。iPhone 紛失時の revoke が再起動まで効かない状態を完成版に持ち込まないため、reload 完成まで production serve を有効化しない（設計書 §21-9・§23-10）。
- **purpose allowlist ゲート（P2 の完了条件として追跡）**: 設計 §9.5 は allowlist 検証を iPhone 承認画面の**前段の必須 gate**とするが、allowlist を確立するのはペアリング（§8.2＝P2、未着手）。mock-iphone `Approval` には gate 差込点をコメントで明示済み。**P2 の完了条件**として、(a) ペアリング時の allowlist 保存、(b) allowlist 外の要求の拒否、(c) challenge による allowlist 更新の拒否（§18.3）を実装・テストすること。単なる TODO ではなく本項目で追跡する。

## 参照

- 設計（正）: `docs/iphone-faceid-linux-pam-design.md`
- 実装計画（フェーズ・完了条件）: `docs/implementation-plan.md`
- レビュー記録: `docs/reviews/`
- タスク管理: agent-tasks ストア（`~/agent-tasks-store/bifrauth/`、リポジトリ外）。0001–0011 が done。
