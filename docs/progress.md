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

Linux 側（Rust + mock-iphone）の基盤〜verifier+IPC+管理 CLI までが完了（P0–P4 + NSS resolver）。
残りは **P5 number matching**・**P6 PAM**（いずれも Linux 完結・未着手）と、**P3 トランスポート**
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
| P5 number matching | ⬜ | PAM conversation ↔ iPhone の6桁照合の状態機械 + テストクライアント（§23-11）。Linux 完結。**次の推奨着手先** | — |
| P6 PAM | ⬜ | `pam_bifrauth.so` + 専用サービス `bifrauth-test`、symbol/ABI 検査、フォールバック契約の統合テスト（§23-12,13）。`pam_bifrauth` はスタブ | crate スタブ |
| NSS resolver | ✅ | `UzersResolver`（NSS 経由 username→uid、glibc 動的リンク方針確定） | task 0010 |

## クレート実装状況

| crate | 状態 | 備考 |
|---|---|---|
| `bifrauth-proto` | ✅ | canonical CBOR（層A/層B）、challenge/response/envelope スキーマ、text policy |
| `bifrauth-crypto` | ✅ | Ed25519 / P-256 / SHA-256 / CSPRNG |
| `bifrauth-ipc` | ✅ | wire/frame/deadline/clock/transport port（PAM↔verifier IPC） |
| `mock-iphone` | 🟡 | 署名往復は実装。**未実装**: number matching（6桁照合）、expiry/replay、Face ID 失敗注入（P5/実機で追加） |
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
| 11 | number matching | ⬜ | P5 |
| 12 | PAM モジュール | ⬜ | P6 |
| 13 | 専用 PAM サービスでテスト | ⬜ | P6 |
| 14 | polkit エージェント同一ダイアログ実機確認 | ⬜ | 実機 |
| 15 | polkit 統合 | ⬜ | 実機 |
| 16 | 1Password 検証 | ⬜ | 実機 |
| 17 | fuzzing / replay / MITM / 失効テスト | 🟡 | replay・失効は単体/統合テスト済み。fuzzing・MITM は未 |

## 残作業（Linux 完結・優先度順）

1. **P5 number matching 状態機械**（§23-11）— 自己完結・P6 の前提を解く。**次の推奨着手先**。
2. **verifier_key(§4.7) のファイル生成/ロード + `Zeroizing<[u8;32]>` シード API** — task 0009 で別出しにしたフォローアップ。本番 daemon 起動に必要。レジストリと同じファイル安全性作法を再利用。
3. **P6 PAM モジュール**（§23-12,13）— フォールバック契約（Face ID 拒否/未到達/timeout/daemon 停止/malformed で `PAM_SUCCESS` にならず password 下段へ）を完了条件に。
4. **fuzzing / MITM テスト**（§23-17 の残り）。

## Blocking dependency（本番稼働の前提）

- **P3 トランスポート**: Mac で Network.framework↔rustls の spike を通すまで Linux 側の本実装に着手しない（設計判断）。`bifrauthd` の本番 serve 配線もこれ待ち。
- **管理変更の transactional reload**（管理 IPC もしくは SIGHUP 等）: `bifrauthctl` の register/revoke は永続化のみで**稼働中 daemon には再起動まで反映されない**。iPhone 紛失時の revoke が再起動まで効かない状態を完成版に持ち込まないため、reload 完成まで production serve を有効化しない（設計書 §21-9・§23-10）。

## 参照

- 設計（正）: `docs/iphone-faceid-linux-pam-design.md`
- 実装計画（フェーズ・完了条件）: `docs/implementation-plan.md`
- レビュー記録: `docs/reviews/`
- タスク管理: agent-tasks ストア（`~/agent-tasks-store/bifrauth/`、リポジトリ外）。0001–0010 が done。
