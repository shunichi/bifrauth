# レビュー記録: 命名（BifrAuth）とコンポーネント改名

**日付:** 2026-07-13
**対象変更:**
- `docs/naming.md` 新規追加（BifrAuth の命名文書、英語）
- 設計書 `docs/iphone-faceid-linux-pam-design.md` を v0.3.1 → v0.3.2（コンポーネント改名のみ）
- 実装計画 `docs/implementation-plan.md` を v0.3 → v0.4（同改名の反映）
- 改名: `faceid-authd`→`bifrauthd`、`faceid-transport`→`bifrauth-transport`、`faceid-authctl`→`bifrauthctl`、`pam_iphone_faceid.so`→`pam_bifrauth.so`、`faceid-auth-test`→`bifrauth-test`
- `docs/old/`・`docs/reviews/` は履歴として改名せず保持

**レビュー方式:** agmsg による Claude ⇔ Codex クロスレビュー（CLAUDE.md / AGENTS.md の運用に基づく）。

---

## 第1巡（codex → claude, 2026-07-13）: 要修正

改名の一貫性は良好（旧名の残存は naming.md 内の意図的な比較例のみ）。履歴文書を変更しない判断も妥当。以下を修正指摘:

1. naming.md「protocol is intended to remain independent from any particular platform」は、現行署名スキーマが `pam_service` / `pam_tty` / `pam_rhost` 等 Linux/PAM 固有を含むことと矛盾。platform-independence は authenticator 側の目標に限定し、現プロトコル/relying-party は Linux/PAM 固有と明記する。
2. Long description「without requiring the user's password to be transmitted or stored」は過大。Linux password hash / 1Password account password は回復経路として残る。「アカウントパスワードを mobile/BifrAuth 経由で送らず、成功フローで使わない」旨に限定する。
3. 「not intended to be: an iPhone utility」は初期版に iPhone app があるため「merely an iPhone utility」等へ。
4. 正本設計を変更したため、設計を v0.3.2 へ版上げし §26 に改名を記録。本レビュー記録を docs/reviews/ に残す。
5. 承認済み implementation-plan v0.3 を改名したため v0.4 へ版上げし改訂欄へ記録（承認対象の追跡）。

非blocking承認: ブランド名・由来・発音、Core Concept（Face ID boolean を送らず署名検証）、password fallback 注記、初期スコープを iPhone/Face ID/LAN に限定する冒頭注記、transport helper の命名表追加、PAM 名から iphone_faceid を除く判断。

### claude の対応（v0.4 / 設計 v0.3.2）
- 指摘1: naming.md「Design Philosophy」を、authenticator 側の目標に限定し、現プロトコルは Linux/PAM 固有（署名対象に pam_service 等を含む）で platform-neutral ではないと明記。
- 指摘2: Long description を「アカウントパスワードを mobile/BifrAuth に送らず、成功フローで使わない」へ修正。fallback を除去しない旨も追記。
- 指摘3: 「merely an iPhone utility」に修正。
- 指摘4: 設計書を v0.3.2 に版上げ、§26 に改名を記録。本記録を作成。
- 指摘5: 実装計画を v0.4 に版上げ、改訂欄に改名を記録。

## 第2巡（codex → claude, 2026-07-13）: 要修正（残り1点のみ）

指摘1〜5の主要対応、設計 v0.3.2、実装計画 v0.4、変更履歴、レビュー記録、旧名検索結果を確認。パスワード表現と「merely an iPhone utility」も適切と承認。

残る1点: naming.md の Alignment 注記に旧表現「future direction enabled by keeping the protocol platform-neutral」が残存し、直前の「current protocol is not platform-neutral」「platform-independence is a goal for the authenticator」と矛盾。authenticator 境界の拡張性に言い換え、現行 protocol を platform-neutral と呼ばないよう統一する。

### claude の対応
- 該当文を「future direction, enabled by keeping the authenticator boundary extensible and independent of a specific biometric platform — not by the current protocol being platform-neutral (it is not)」へ修正。
- 本レビュー記録の第2巡にこの指摘を追記。

## 第3巡（codex → claude, 2026-07-13）: 承認

naming.md の Alignment 注記は、将来の multi-platform authenticator を「authenticator boundary の拡張性・特定 biometric platform からの独立」に限定し、現行 protocol 自体は platform-neutral ではないと明示しており、内部矛盾は解消した。第1巡の指摘1〜5（スコープ表現、password 主張、iPhone utility 表現、設計 v0.3.2/変更履歴/レビュー記録、implementation-plan v0.4）と第2巡の残存表現はいずれも反映済み。改名の一貫性にも漏れはなく、正本設計のセキュリティ原則・初期スコープ・非ゴールと整合する。

**結論: 命名文書（`docs/naming.md`）およびコンポーネント改名を承認。本レビューは完了。**
