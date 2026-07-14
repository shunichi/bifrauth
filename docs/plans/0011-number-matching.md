# 実装計画: task 0011 — P5 number matching 状態機械（§23-11）

> レビュー依頼用ドラフト（codex 宛）。設計書 §9.3/§9.5/§13.2/§13.3/§16、implementation-plan P5、
> §18.1/§18.3 を根拠にする。

## 背景（重要）

**verifier(Linux)側の状態機械は P4（task 0007/0008）で実装済み**。
- verifier が CSPRNG で一様な6桁コードを要求ごとに生成し、署名対象 challenge の `confirmation_code`
  に含める（§9.3/§16）。`session.rs` が `ConfirmationCode`→`DisplayAck`→dispatch→`Outcome` を駆動、
  全失敗経路で pending を cancel（ipc-design §4/§4.1/§4.2）。
- verifier は**コードの照合をしない**。照合は iPhone 側の責務（§9.3/§9.5/§13.3）。verifier は step 10 で
  canonical challenge 全体一致（＝コードを含む署名対象一致）を確認するのみ（§9.7）。
- `ConfirmationCode.confirmation_code`（PAM が表示する値）＝ challenge に埋めた署名対象コード（同一値）。

∴ P5 の残作業は **iPhone 側（mock-iphone）の番号照合 + 承認状態機械 + テストクライアント + テスト**。
verifier 側の変更は原則不要（既存契約を iPhone 照合込みで E2E に閉じる）。

## スコープ（P5 / このマシン完結）

1. mock-iphone に **番号照合つき承認状態機械**を実装（§9.5 の順序・§13.2/§13.3 の不変条件）。
2. **失敗注入**（mismatch / Face ID 拒否 / cancel / timeout / background 無効化）で fail closed を再現。
3. **テストクライアント**（issue→表示コード→iPhone 入力照合→verify を一周、負経路含む）。
4. §18.1「number matching 確認コードの生成と照合」・§18.3「不一致・キャンセル・PAM conversation 表示失敗」
   のテスト。
5. `cargo test --workspace` / `clippy -D warnings` / `fmt --check` 緑。

## 主要な設計判断（← 重点レビュー希望）

### D1. iPhone 承認状態機械を mock-iphone に置く。**通常経路は外部 user-entered code で駆動**（不変条件優先）

（codex 第1ラウンド #1 反映）
- 承認状態機械 `Approval` を新設。**コードは challenge から自動入力せず、常に外部から渡された
  user-entered code を使う**（§9.3/§13.3「表示・自動補完せず照合のみ」）。テストは「Linux 画面表示
  ＝ `IssuedChallenge.confirmation_code` / `ConfirmationCode` メッセージ」の値を**ユーザー役として読み取り**、
  それを Approval に手入力として渡す（envelope から抜くのではなく、表示チャネルの値を使う＝忠実）。
- **型状態で遷移ごとに self を consume**（codex #4）:
  `Approval::open(envelope) -> Result<Verified, Rejected>`（envelope 暗号検証）→
  `Verified::enter_code(self, entered: &str) -> Result<Matched, Rejected>`（定数時間照合）→
  `Matched::face_id(self, outcome) -> Result<Approved, Rejected>` →
  `Approved::sign(self) -> Vec<u8>`。各段が self を消費するので **Signed/Rejected 後の再署名は構造的に不可能**。
- 既存 `MockIphone::process(envelope)`（検証→Face ID 成功→署名、照合なし）は **number matching を
  スキップする legacy skeleton** として明示改名（例 `sign_skipping_number_matching`）＋ doc で「忠実経路
  ではない、Linux 側状態機械テスト専用」と明記。**P5 の number matching テスト/E2E は絶対にこれを使わない**。
- **通常 Transport 経路が Approval を迂回しないことを証明**する: `NumberMatchingTransport`
  アダプタ（dispatch 時に外部供給の user code で Approval を駆動）を用意し、P5 の統合テストで
  「issue → 表示コードをユーザー役が読取 → Transport が Approval を駆動 → verify」を通す。
  0009 の socket E2E も number matching 経路へ寄せ、process() bypass を残さない。

### D2. §9.5 の順序を守る（検証 → コード照合 → Face ID → 署名）。**mock は partial であることを明記**

mock は UI を持たないが、**順序と早期破棄**をロジックで守る:
1. envelope 検証（既存: verifier 署名・challenge decode・verifier_key_id・linux_device_id）。
   **1つでも失敗したら、コードにも承認にも触れず破棄**（`Rejected`。§9.5 L455）。
2. （purpose allowlist ゲートの差込点。実装は P2＝D5）
3. **コード照合**: 外部入力 == challenge.confirmation_code を**定数時間比較**（6 固定 ASCII digit を
   自前 XOR 集約、新規依存なし。codex #4）。**受信コードは返さない/露出しない**（§9.3 L433 / §13.3 L704）。
   不一致 → Rejected（署名なし）。
4. **Face ID**: 注入結果が Success のときだけ次へ。Denied/Cancelled → Rejected（署名なし）。
5. 署名直前 deadline gate（D3）→ P-256 署名。

**iPhone 側 expiry / request_id replay は P5 に含めない**（codex #2）。§9.5 は本来これらも承認画面前の
必須検証として列挙するが、mock は現状これを実装しておらず、**P5 でも実装しない**（TTL/replay の権威は
verifier: CLOCK_BOOTTIME・atomic consume、P4 済）。∴:
- `Approval` の状態名・API・doc は**「§9.5 を全て満たした状態」を意味しない**ようにする
  （例: `Verified` ではなく `EnvelopeChecked` 等、「暗号検証のみ済み」と読める命名にする）。
- **iPhone 側 expiry/replay（defense-in-depth の重複実装）は別タスクに切り出す**（本計画末尾のフォロー
  アップに記載し、progress.md にも残す）。これで D2 と「iPhone は partial」の整合を取る。

### D3. §13.2/§16 の不変条件: 単回（型状態）・注入 clock による timeout・明示 invalidate・非復元

- **単回使用**: D1 の型状態（各遷移が self を consume）により、Signed/Rejected 後の再署名は構造的に不可能。
- **timeout は注入 clock + 署名直前 gate**（codex #3）: `Approval` に**注入可能な monotonic clock と
  approval deadline**（envelope 受信時に設定、Face ID 待機ウィンドウ相当。§16 の per-stage 20s に対応）
  を持たせる。テストは clock を進め、**署名直前の期限チェック**で期限超過なら署名不能を確認（TOCTOU 回避で
  sign gate に置く）。コード入力前・Face ID 完了前の各境界でも期限超過を拒否できる形にする。
- **background / cancel**: 明示 `invalidate()`（背景遷移・キャンセル相当。§13.2）。以降は署名不能。
- **旧要求の非復元**: 新しい `Approval` は過去状態を引き継がない（アプリ再起動で古い request を復元しない
  の mock 表現）＝型状態で自然に成立（状態は値に閉じる）。
- 注: これらは §13.2「Face ID 成功を長時間再利用しない・背景で無効化」の iPhone 側表現（二重防御）。
  認証成功の最終判定は依然 verifier.verify_response。

### D4. テストクライアントは統合テスト（実 socket は使わず in-process でよいか要相談）

- 主成果物: number matching を一周させるテスト。issue（verifier）→ `IssuedChallenge.confirmation_code`
  を「Linux 表示コード」とみなす → iPhone `Approval` にそのコードを入力 → 署名 → verifier.verify。
  - happy: 正コード + Face ID 成功 → verify 成功。
  - 負: 不一致コード → 署名なし → （verify に到達しない or 署名なしで Denied 相当）。
  - 負: Face ID 拒否 / cancel → 署名なし。
  - 負: PAM conversation 表示失敗（DisplayAck=false）→ verifier が dispatch しない（既存 session の
    テストで担保済み。P5 では iPhone に到達しないことを一言確認）。
- **方針（codex D4 反映）**: number matching ロジックの検証は **in-process 統合で十分**。ただし
  「通常 Transport 経路が Approval を迂回しない」ことを `NumberMatchingTransport` 経由の統合テストで
  **証明する**（既存の process() ベース socket happy path だけでは bypass が残り不十分）。実 socket まで
  通すのは任意（0009 の socket E2E を number matching 経路へ寄せる形で bypass を除去）。

### D5. purpose allowlist は P5 に含めず P2 ペアリングへ（追跡を docs に明記）

（codex D5 反映）
- §9.5 は allowlist 検証を承認画面の**前段の必須 gate**とするが、**allowlist を確立するのはペアリング
  （§8.2, P2、未着手）**。mock-iphone は現状 allowlist を持たない。
- **P5 は number matching に集中**し、allowlist 強制は P2 で実装する。P5 では順序ゲートの差込点を
  コード上のコメントで示すだけでなく、**progress.md と本計画に「§9.5 の必須 gate であり P2 の完了条件
  として追跡する」旨を明記**する（単なる TODO コメントに留めない）。§18.3 の allowlist テスト（allowlist 外
  要求の拒否・challenge による allowlist 更新拒否）は P2 の完了条件へ。

## 実装ステップ（合意後）

1. mock-iphone: 型状態 `Approval`（D1）。envelope 検証は既存流用。注入 clock + approval deadline（D3）。
2. 定数時間照合（自前 XOR）+ コード非露出 + Face ID 注入 + 署名直前 deadline gate + 明示 invalidate（D2/D3）。
3. legacy `process()` を `sign_skipping_number_matching` へ改名 + doc 明記（Linux 側テスト専用・非忠実）。
4. `NumberMatchingTransport` アダプタ + in-process 統合テスト（通常経路が Approval を駆動＝bypass なし）。
   0009 socket E2E を number matching 経路へ寄せる。
5. §18.1/§18.3 テスト: 生成と照合、不一致→署名なし、Face ID 拒否/キャンセル→署名なし、表示失敗
   （DisplayAck=false）で iPhone 非到達、**コード非露出**（Debug/error/state に expected code を含めない）、
   単回（再署名不可）、background invalidate、**timeout（注入 clock で署名直前 gate）**。
6. mock-iphone の doc コメント（「not implemented: number matching …」）を更新。iPhone 側 expiry/replay は
   別タスク・progress.md に記載。
7. 既存の Linux 側テスト（session/serve/lib）が壊れないことを確認。lint/fmt/test 緑 + コミット。

## フォローアップ（P5 では実装しない・追跡）

- **iPhone 側 expiry / request_id replay**（§9.5 の承認画面前検証の残り。defense-in-depth の重複実装）→ 別タスク。
- **purpose allowlist ゲート**（§9.5 の必須 gate）→ **P2 ペアリング**の完了条件（データ確立・変更拒否テスト含む）。
  progress.md に明記して追跡する（D5）。

## レビューしてほしい観点

- D1（型状態・外部 user code 駆動・legacy skeleton の隔離・通常経路が bypass しない証明）。
- D2（§9.5 の順序・早期破棄・コード非露出・定数時間・mock が partial である旨の命名/doc）。
- D3（型状態の単回・注入 clock + 署名直前 gate の timeout・明示 invalidate）。
- D4（in-process 統合 + bypass なし証明で十分か）。
- D5（allowlist を P2 へ、追跡明記）。
- セキュリティ: 不一致/Face ID 失敗/キャンセル/timeout で確実に署名しない（fail closed）／受信コード非露出／
  最終成功判定は verifier.verify_response のまま（照合は UX 層 defense-in-depth）。
