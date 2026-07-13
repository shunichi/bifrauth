# レビュー記録: BifrAuth CBOR プロファイル（P0）

**日付:** 2026-07-13〜14
**対象:** `spec/cbor-profile.md`（BifrAuth deterministic CBOR プロファイル）。承認済み実装計画 v0.4 の P0 成果物。
**レビュー方式:** agmsg による Claude ⇔ Codex クロスレビュー（CLAUDE.md / AGENTS.md）。
**結論:** **第3巡で承認**（P0 実装の規範）。承認時の非blocking局所修正5点を反映済み。

---

## 第1巡（codex → claude）: 要修正（12点）
方向性（RFC 8949 §4.2.1 基礎・definite/shortest/uint key/bytewise order/float・tag禁止・直接検査）は妥当。
P0 で Rust/Swift の受理集合を一致させるための blocking として、canonical と schema の分離、challenge.v1 の
全キー必須・各フィールド exact/範囲、許可データモデルの列挙、map キー strict `<`、リソース境界（深さ・
allocation前拒否）、NFC の application 制約化、日時=epoch uint、version 進化、response.v1 の同時定義、
challenge envelope の wire schema、negative/golden ベクタ拡充、設計同期を指摘。

### claude 対応（v0.2）: 上記1〜12を反映（層A/層B分離、スキーマ厳密化、allowlist、strict順序、depth、NFC、epoch、version、response、envelope、vectors、設計同期は承認後）。

## 第2巡（codex → claude）: 要修正（12点、実値の凍結）
"暫定/固定する"を実値へ凍結せよ、response schema の構造矛盾（7 field 必要）、§5.1 の確定、envelope の
CBOR wire schema 化、サイズ包含関係（inner/outer）、simple value 記述の訂正、全未確定値の凍結、
field 文字制約の確定、device ID 表現の凍結、target_uid の `(uid_t)-1` 拒否、version 役割分離、
層A/層B 境界の呼称、vectors 追加を指摘。

### claude 対応（v0.3）: 実値で凍結。response.v1=7-entry（alg/sig 分離）、signature≤72B・strict DER・
r,s∈[1,n-1]・low-S非要求、envelope.v1=3-entry、inner4096/outer4608/response512B、simple 0..23非最短と
24..255 allowlist外の分離、epoch 0..253402300799・TTL差1..30秒、Unicode16.0・未割当拒否、全tstrで
NUL/C0/C1/bidi拒否、device ID=exact16B bstr、uid 0..4294967294、version役割分離と対応表、層Aを
"BifrAuth deterministic profile validity"と呼称、vectors拡充。

## 第3巡（codex → claude）: 承認
v0.3 の direct deterministic scan・型allowlist・challenge 16-key/response 7-key exact schema・raw challenge
への署名検証・hash非信頼・inner/outer bounds・epoch/TTL・device ID・UID sentinel拒否・version役割分離・
vectors が一貫して確定され、設計§5/§9 と整合するとして **P0 実装の規範として承認**。

### 承認時の非blocking局所修正（再レビュー不要・実装/merge前に反映）→ claude 反映済み
1. `pam_service`(≤128B)＋`.authenticate` 導出が最大141B → `requested_action` を 1..256B へ拡張。
2. Unicode を **16.0 / UAX #15 Revision 56** に pin（latest URL をやめ固定 revision）、未割当判定も Unicode 16.0 UCD 基準。
3. 「bidi制御」を Unicode 16.0 `Bidi_Control=Yes` プロパティとして定義。
4. §9 欠番を「予約・将来利用」と明記。
5. envelope が on-wire に message_type/protocol_version を持たず外部framingで型固定、inner の protocol_version=1 も検査する旨を version 節へ cross-reference。

## 後続（設計同期）
- 正本設計を v0.3.3 に更新: §9.4 を Deterministic CBOR 確定へ、§21.4 の未決事項4を解消、§26 に記録。
  技術的意味の追加はなく確定済み encoding の反映のみのため、別途クロスレビューは不要（AGENTS.md の
  「技術的意味を追加する場合は別途レビュー」に該当しない）。
