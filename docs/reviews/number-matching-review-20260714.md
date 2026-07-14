# レビュー記録: P5 number matching 状態機械（task 0011）

**日付:** 2026-07-14
**対象:** 実装計画 `docs/plans/0011-number-matching.md`。成果物は mock-iphone の番号照合つき承認状態機械
（`Approval`）、`NumberMatchingTransport` 経由の socket E2E、verifier コアレベルの socket-free テスト
クライアント、§18.1/§18.3 のテスト。設計書 §9.3/§9.5/§13.2/§13.3/§16、implementation-plan P5 準拠。
**レビュー方式:** agmsg による Claude ⇔ Codex クロスレビュー（CLAUDE.md / AGENTS.md）。
**結論:** **第2ラウンドで承認**。承認時の非blocking実装注意4点も反映して実装。

---

## 前提（設計調査で確定）

- verifier(Linux)側の状態機械は **P4（task 0007/0008）で実装済み**（`session.rs` の
  ConfirmationCode→DisplayAck→dispatch→Outcome・全失敗経路 cleanup）。verifier は**コードを照合しない**
  （照合は iPhone 側の責務。§9.3/§9.5/§13.3。verifier は §9.7 step10 で canonical challenge 全体一致のみ）。
- ∴ P5 の主戦場は **iPhone 側（mock-iphone）の番号照合 + 承認状態機械 + テストクライアント**。

## 第1ラウンド（codex → claude）: 要修正
全体方針（mock-iphone に承認状態機械、検証→照合→Face ID→署名、in-process 統合、allowlist を P2）は妥当。
必須修正:
1. `process()` の happy-path 自動入力（challenge からコードを抜いて自動入力）は §9.3/§13.3「表示・自動補完
   せず照合のみ」に反し、serve/E2E が number matching を恒常的に迂回する。通常経路は必ず**外部 user-entered
   code** で Approval を駆動し、legacy bypass は test-only/到達不能にし E2E で使わない。
2. §9.5 は expiry / request_id replay も承認画面前の必須検証として列挙。P5 で実装するか別タスクへ切り出し、
   mock が partial である旨を状態名/API/doc で明記（「全検証済み」を誤認させない）。
3. timeout は手動 invalidate では試験にならない。注入 monotonic clock/deadline を持たせ、各境界・**署名直前
   gate（TOCTOU 回避）**で期限超過なら署名不能を確認。background/cancel は明示 invalidate で可。
4. 型状態で self を consume（Signed/Rejected 後の再署名を構造的に不可能に）。error/Debug/state に expected
   code を含めないテスト。定数時間比較は 6 固定 ASCII digit の自前 XOR（新規依存なし）。

### claude 対応（第2ラウンド提出）: 1〜4 を全反映。
process() → `sign_skipping_number_matching` へ改名し test 専用スケルトンとして隔離。`Approval` を外部
user-entered code で駆動する型状態（open→EnvelopeChecked→enter_code→CodeMatched→face_id→FaceApproved→sign）に。
iPhone 側 expiry/replay は別タスク・mock は partial と明記。注入 clock + 署名直前 deadline gate。allowlist は
P2 へ（progress.md/計画で追跡）。

## 第2ラウンド（codex → claude）: 承認
(1) 外部 code のみで駆動し bypass 除去、(2) partial 性と expiry/replay の別タスク追跡、(3) 注入 clock と
各境界・署名直前 gate、(4) self-consuming 型状態、(5) allowlist の P2 追跡、を確認。in-process 統合で十分に同意。

非blocking の実装注意（反映済み）:
- `sign_skipping_number_matching` は cfg(test)/crate-private 優先（本 crate は完全に test-support なので
  `pub` のまま。`rg` で **NumberMatchingTransport / P5 の matching テストから参照ゼロ**を確認）。
- entered code は厳密 6 ASCII digit を要求し、expected/entered code を Debug/Display/Error/ログに載せない
  （`ApprovalError` は code フィールドを持たず、状態型は Debug 非導出）。
- deadline check を共通関数化（`ensure_within_deadline`）し enter_code 前・face_id 前・sign 直前で読む。
  `FaceApproved::sign(self) -> Result<Vec<u8>, ApprovalError>`（Approved 生成後も期限切れなら Err(Expired)）。
- progress.md の follow-up 更新と本レビュー記録。

---

## コードレビュー（実装レビュー）

### 第1ラウンド（codex → claude）: 要修正（必須1件）
型状態・外部入力・fail-closed・deadline 最終 gate・E2E bypass 除去・docs 追跡は計画どおりで良好。ただし
**必須: background invalidation（明示 `invalidate()`）が未実装**。合意計画（D3・本レビュー記録）は「明示
invalidate() / background 無効化後は署名不能」を約束したのに、mock-iphone に invalidate API/状態/テストが
無く設計 §13.2「バックグラウンド遷移後の未処理要求を無効化」の P5 表現が欠落。
非blocking: 自前 XOR の「constant-time」は最適化後を保証しないので「fixed-length / best-effort」と正確化。
修正後にレビュー記録と実装の一致を再確認して再レビュー依頼。

### claude 対応（再提出）:
- 各 live state（EnvelopeChecked/CodeMatched/FaceApproved）に consuming `invalidate(self) -> Invalidated`
  を追加。`Invalidated` は sign/遷移メソッドを持たない terminal marker（`compile_fail` doctest で invalidate
  後に `enter_code`/`sign` が呼べないことを固定）。`FaceId::Cancelled`（Face ID prompt の取消）とは別扱い。
  各段階から invalidate が terminal を返す runtime テストも追加。
- `ct_eq_six` の doc を「fixed-length branchless / best-effort constant-time（低エントロピー UX 値であり
  秘密鍵ではない）」に是正（新規依存は追加しない）。

## 主要な確定事項

- **通常経路は外部 user-entered code で駆動**。`Approval` は challenge からコードを抜かず、渡された入力と
  内部の期待コードを**固定長・branchless（best-effort 定数時間）**で照合。受信コードは表示・自動補完・返却・
  ログのいずれもしない（§9.3/§13.3）。
- **型状態で単回**: 各遷移が self を consume。Signed/Rejected 後の再署名は構造的に不可能。
- **timeout は注入 clock + 署名直前 gate**（TOCTOU 回避）。Face ID 拒否/キャンセルは注入で拒否。
- **mock は partial**: iPhone 側 expiry/replay は未実装（TTL/replay の権威は verifier）。状態名 `EnvelopeChecked`
  は「暗号検証のみ済み」を意味し「§9.5 全検証済み」ではない。
- **通常 Transport 経路が bypass しない証明**: `NumberMatchingTransport`（外部 code で Approval を駆動）で
  socket E2E を matching 化し、legacy skeleton を使わない。
- **最終成功判定は verifier.verify_response のまま**（照合は UX 層の defense-in-depth）。
- **スコープ外（追跡）**: iPhone 側 expiry/replay（別タスク）、purpose allowlist（P2 の完了条件）。
