# bifrauth を読むための本 — 章構造案（ドラフト v3）

> **目的:** この分野の前提知識がない読者が、bifrauth のコードを理解し、自分でセキュリティ
> レビューできるようになること。
>
> **改訂:**
> - v2: codex レビュー第1ラウンドの指摘を反映（OS 基礎の前倒し、実装状態ラベル、
>   `lib.rs`/`session.rs` の責務分離、PAM 専章化、実践編の拡張、運用セキュリティ／downgrade／
>   FFI／永続化／テスト技法の追加、source-of-truth 順位の明記）。
> - v3: codex レビュー第2ラウンドの指摘を反映（正しさの順位で正本を「唯一の正」とし詳細仕様を
>   委譲範囲内に限定、第10章のチャネル方式を未決（TLS mTLS / Noise 候補）として提示、
>   第18章で永続化の実装済み範囲と設計要求を分離、第22章の実装状態を commit/date で固定）。
>
> **このファイルはまだ「章構造の案」**。各章の中身は未執筆。

---

## 本書の位置づけと「正しさの順位」（source of truth）

矛盾を見つけたとき、どれを正とするかの順位を最初に固定する:

1. **正本設計書** `docs/iphone-faceid-linux-pam-design.md` — **唯一の正**。
2. **正本から明示的に委譲・参照された詳細仕様**（例: `docs/ipc-design.md`、`spec/cbor-profile.md`）—
   その**委譲された範囲内でのみ規範的**であり、**正本を上書きできない**。
3. **実装**（`crates/*`）— 「仕様に適合しているかを検査する対象」。
4. **本書** — 上記を読み解くための導き。

矛盾があったときの正しいレビュアーの動き:

- **正本との差を finding として扱う。** 本書を根拠に実装や正本を勝手に書き換えない。
- 詳細仕様・実装・本書が正本とずれているなら、**それら（下位）の側を是正**する。
- **正本自体を変える必要があるなら、設計変更レビューを経る**（正本は勝手に書き換えない）。

`docs/old/` は古いので**参照しない**。

### 各章に付けるラベル（実装状態）

読者が「設計上の話」と「今のコードの話」を混同しないよう、章・節に次のラベルと、
参照した **commit / 日付**を明記する:

- `仕様（正本）` — 設計書で決まっているが実装状態は別
- `実装済み` — このマシンの Rust 実装に存在（対象 commit を示す）
- `mockのみ` — `mock-iphone` などテスト用実装にのみ存在（本番ではない）
- `未実装 / 将来予定` — 設計はあるがコードがない、または stub のみ

> **重要な訓練:** mock を読んでも本番 iOS アプリをレビューしたことにはならない。
> 未実装を「安全である証明」に数えない。

### コード解説章の定型枠

第 II 部の各章は次の枠を備える:

- **正本の対応節**（設計書の §）
- **主要 invariant**（この章のコードが守る不変条件）
- **source files**（commit permalink / 対象バージョン併記）
- **tests**（対応するテスト）
- **未実装・前提**（この章の範囲で「まだない」もの）

### クイズと用語の扱い（重複管理を避ける）

- **章末には問題のみ**を置く。**解答・解説（根拠リンク付き）は付録 B に集約**する。
- **序章の用語ミニ辞典は索引／最小語**。**正式な用語集（canonical glossary）は付録 A**。

---

## 全体の構成（3 部 + 序章 + 付録）

- **序章** — この本の歩き方 / bifrauth が何を解決するのか（1 枚の地図）
- **第 I 部 土台となる技術（プロジェクト非依存）**
- **第 II 部 bifrauth のコードを読む**
- **第 III 部 セキュリティレビュー実践**

---

## 序章. この本の歩き方

- 対象読者と前提（前提知識ゼロを想定）
- bifrauth が解決する問題を 1 段落で（「Face ID 成功という真偽値を送らない」）
- 登場人物とデータの流れを 1 枚の図で（1Password → polkit → PAM → bifrauthd → transport →
  iPhone → Secure Enclave）
- source-of-truth の順位と、実装状態ラベルの読み方（上記の要約）
- 用語ミニ辞典（索引・最小語。正式版は付録 A）
- （クイズ）

---

## 第 I 部 土台となる技術（プロジェクト非依存）

### 第 1 章 Linux の最小モデル 〔前提の前提〕
- user と UID、root（特権）と一般ユーザー
- process とその権限、file descriptor
- file の owner と mode（誰が読める／書けるか）
- service / daemon とは、systemd の役割（socket activation の予告）
- 「root だけが書ける」がなぜ安全性の土台になるか
- （クイズ）

### 第 2 章 認証と認可、脅威モデルの立て方
- 認証（authentication）と認可（authorization）の違い
- パスワード認証が実際に何をしているか
- なりすまし・リプレイという攻撃の基本形
- 信頼境界とは何か、asset / adversary / trust boundary の考え方
- 「非特権プロセスが侵害されても単独で認証を偽造できない」の意味
- （クイズ）

### 第 3 章 PAM — Linux の認証を差し替える仕組み
- PAM とは何か、なぜ存在するか、service 名の役割
- application / module / conversation の三者
- 4 つの管理グループ（auth / account / password / session）
- コントロールフラグ（required / sufficient / requisite …）による stack 合成
- `pam_sm_authenticate` などのモジュール入口と戻り値
- フォールバック（`sufficient` の下段へ落ちる）
- （クイズ）

### 第 4 章 polkit と 1Password の system authentication
- polkit とは（システム全体の「この操作を許してよいか」の調停役）
- action、認証エージェント、`polkit-agent-helper-1`
- polkit が PAM を呼ぶ関係
- **重要な制約:** polkit は action ID を PAM に渡さない
- 「1Password が何を起動するか」は**環境・版依存の実機確認事項**と、設計上確認済みの前提を区別する
- （クイズ）

### 第 5 章 暗号の最小限と Secure Enclave 〔「真偽値を送らない」の核心〕
- 公開鍵暗号、「秘密鍵で署名・公開鍵で検証」、ハッシュ（SHA-256）
- nonce とチャレンジレスポンス — なぜリプレイを防げるか
- 署名対象への「文脈の束縛」（誰が・どのサービスで・いつ・どの端末で）
- 本書で使う 2 つの署名: Ed25519（verifier）と ECDSA P-256（iPhone）
- Secure Enclave（取り出せない鍵）と、Face ID を「署名操作の許可（ゲート）」として使う
- なぜ `{ "face_id": true }` を送ってはいけないか（偽造・リプレイ・差し替え）
- （クイズ）

### 第 6 章 ローカル通信とファイル・永続化の安全性
- プロセス間通信（IPC）と Unix domain socket
- `SO_PEERCRED`：接続してきた相手の UID/PID を OS に問う（誰が認可を持つかは後章）
- ファイルの所有者・パーミッションと TOCTOU・symlink 差し替え、`openat`/`O_NOFOLLOW`
- **永続化の安全性:** atomic rename、fsync、crash consistency、tombstone / rollback
- （クイズ）

### 第 7 章 バイト列を一致させる技術 — 正規化・CBOR・バージョン交渉
- なぜ「署名対象のバイト列」が実装間で一致しないと困るか
- deterministic CBOR、正規化の落とし穴（キー順・重複キー・数値表現・NFC）
- **未知フィールド・重複キーを fail-closed で拒否**する
- downgrade 攻撃と version / algorithm / schema version の交渉（プロトコル全体の観点）
- 「受信バイト列そのものの canonicality を検査する」発想
- （クイズ）

### 第 8 章 認証フローの動特性 — 時刻・TTL・状態機械・並行性
- wall-clock と monotonic、`CLOCK_BOOTTIME`、サスペンド時間の算入
- 有効期限（TTL）、リプレイ、時計の巻き戻し攻撃
- 状態機械としての認証フロー、**単回 consume**（一度使った要求は再利用しない）
- 並行性と lock 境界、cancellation と cleanup（途中で失敗したら確実に片付ける）
- （クイズ）

### 第 9 章 可用性・濫用対策とログ／監査・プライバシー
- resource limit / rate limit / キュー上限 と DoS 耐性
- ログ・監査に何を記録してよいか
- 記録してはいけないもの（確認コード・完全な署名・秘密鍵・生体情報・個人情報）
- （クイズ）

### 第 10 章 ペアリングと中間者攻撃（MITM）〔実装状態: 主に設計・未実装〕
- 初回ペアリングで公開鍵を安全に交換する難しさ
- QR コードと SAS（短い比較文字列）、トランスクリプトハッシュ
- **相互認証された暗号化チャネルの目的**（盗聴防止・非ペア端末の抑止・「通信路だけ」を信じない）
- **チャネル方式は未決**（正本 §21.4）: 候補は TLS 1.3 相互認証（mTLS）と Noise。
  実装計画（詳細仕様）は暫定的に TLS 1.3 mTLS を選好（§4.4）だが、正本では確定していない旨を区別する。
- 鍵ピン留めなどは「採用済み仕様」と「候補・一般論」を混同せずに提示する
- （クイズ）

### 第 11 章 FFI 境界の安全性
- C の pointer / ABI と、Rust から C 世界へ出る境界
- panic / unwind と `catch_unwind`、境界を越えて panic を伝播させない
- `catch_unwind` で救えないもの（OOM abort、不正 C pointer）
- 入力長制限・NUL 終端・argc/argv の厳格検証
- （クイズ）

---

## 第 II 部 bifrauth のコードを読む

### 第 12 章 全体像とクレート構成
- ワークスペースと各クレートの責務
- 認証 1 回のシーケンスをコードの登場人物で追う
- source-of-truth 順位・実装状態ラベル・定型枠の再掲
- 読む順番の地図
- （クイズ）

### 第 13 章 `bifrauth-proto` — メッセージ型と canonical CBOR
- CBOR プロファイル（`spec/cbor-profile.md`）とスキーマ（`schema.rs`）
- エンコーダと受信バイト列の canonicality スキャナ（`cbor.rs`）
- 文字列ポリシーと Unicode 正規化（`text.rs` / `unicode_cn.rs`）
- golden / negative テストベクタ
- （クイズ）

### 第 14 章 `bifrauth-crypto` — 署名・検証・乱数
- Ed25519 署名／検証、ECDSA P-256 検証（strict DER）
- SHA-256、CSPRNG（nonce / request_id / 確認コード）
- 二重ハッシュを防ぐ署名 API の固定
- （クイズ）

### 第 15 章 `bifrauth-ipc` — フレーミングと deadline
- wire / frame / deadline / transport port（`wire.rs` / `frame.rs` / `deadline.rs` / `clock.rs`）
- 長さ上限・タイムアウト
- ※ **`SO_PEERCRED` による peer 認可はこのクレートの責務ではない**（serve/systemd 側・
  PAM connector 側で扱う。第 17・19・22 章）
- （クイズ）

### 第 16 章 verifier core（`bifrauthd/src/lib.rs`）
- challenge 発行、pending 要求ストア、device snapshot
- §9.7 の 12 検証、request_id の **atomic consume**（不正署名でも消費）
- CLOCK_BOOTTIME による suspend 込み TTL
- （クイズ）

### 第 17 章 PAM IPC session（`bifrauthd/src/session.rs`）
- AuthRequest → ConfirmationCode → DisplayAck → Transport → Outcome の状態機械
- **不変条件:** `conversation_succeeded` 前に transport へ dispatch しない／全失敗経路で cancel／
  Outcome 送信失敗を「外部成功」にしない
- cleanup guard（途中終了時の後始末）
- serve/systemd 側の `SO_PEERCRED` peer 認可との接続
- （クイズ）

### 第 18 章 デバイスレジストリと管理操作（`registry.rs` + `bifrauthctl`）
- 保存形式（決定論的 CBOR）とディレクトリ構造
- ファイル安全性（`openat`/`O_NOFOLLOW`/`fstat`/`renameat2`）と fail-closed
- **永続化の安全性は「実装済みの範囲」と「設計上の要求」を分離して示す**（atomic rename / fsync /
  crash consistency のどこまでがこの commit で実装され、どこが設計要求か。第 6 章の一般論を
  実装済み保証と誤認させない）
- 失効の tombstone と再登録拒否
- 管理 CLI `bifrauthctl`（register / revoke / list）とレジストリの接続、反映タイミングの注意
- （クイズ）

### 第 19 章 serving・systemd・ユーザー解決（`serve.rs` / `systemd.rs` / `resolver.rs`）
- root 専用ソケットの提供、worker pool
- `SO_PEERCRED` による peer 認可、poison recovery
- systemd socket activation
- NSS 経由の username→uid 解決（uzers）と confused-deputy 対策、fail-closed
- （クイズ）

### 第 20 章 number matching — プロトコル不変条件
- 仕様上の流れ（Linux/PAM 側にコード表示 → iPhone 側で入力・照合）
- **不変条件:** iPhone は受信コードを表示も自動補完もせず、照合にのみ使う
- （クイズ）

### 第 21 章 `mock-iphone` — テストダブルとその限界
- ソフト P-256 鍵で「Face ID 後の署名」を再現する仕組み
- self-consuming API / deadline / invalidate の型状態
- **限界:** test-only bypass が本番経路へ漏れていないか、mock が受信コードを自動入力していないか
  をレビュー観点にする（mock ≠ 本番 iOS）
- （クイズ）

### 第 22 章 `pam_bifrauth` — PAM モジュール（専章）〔実装状態: 執筆対象 commit/date の実装状態をラベルで固定（P6。progress.md の可変文言だけに依存しない）〕
- FFI と module args、`pam_get_item`、conversation callback の厳格検証
- client 側の `SO_PEERCRED`、deadline
- Outcome → PAM 戻り値の写像、fallback
- panic 遮断（第 11 章の実地）
- （クイズ）

### 第 23 章 実装ギャップと残余リスク
- 設計中心・未実装の領域（pairing、TLS transport、Secure Enclave / iOS アプリ、
  `bifrauth-transport` の stub / `main.rs`）
- 「未実装を安全性の証明に数えない」訓練、執筆時 commit の `progress.md` を参照
- （クイズ）

---

## 第 III 部 セキュリティレビュー実践

### 第 24 章 セキュリティのためのテスト技法
- golden / negative / fuzz / property / integration / fault injection
- design ↔ code ↔ test の traceability
- （クイズ）

### 第 25 章 脅威モデルを自分で作る
- asset / adversary / trust boundary を書き出す
- 設計書 §4 を出発点に、自分の言葉で脅威を並べる
- （クイズ）

### 第 26 章 1 つの認証フローを不変条件で追跡する
- 入力源 → 署名対象 → 検証 → 「PAM success の唯一経路」を辿る
- どこで文脈が束縛され、どこで消費されるか
- （クイズ）

### 第 27 章 敵対的テストの設計と証拠収集
- negative / fault / concurrency / fuzz を「反証の試み」として設計する
- レビューの証拠（何を実行し何を確認したか）の残し方
- （クイズ）

### 第 28 章 finding の報告とチェックリストの正しい使い方
- severity / 再現条件 / 修正案 / 残余リスク / 未実装・運用前提の報告
- チェックリストは**最後の成果物**。「チェック済みだから安全」という誤用を戒める
- ケーススタディ: 過去の `docs/reviews/` から実際に見つかった指摘
  （label policy、mode、unknown entry、background invalidation、peer auth 等）
- （クイズ）

---

## 付録
- **A. 用語集（canonical glossary）**
- **B. クイズ解答・解説**（根拠リンク付き。章末は問題のみ）
- **C. さらに学ぶための参考資料**（PAM / polkit / CBOR / 署名の一次情報）

---

## 執筆の進め方（合意事項）
1. **この章構造案（v3）**を codex 承認（第3R）＋ユーザー承認済み →
2. 第 I 部の章を順に執筆（章ごとに codex レビュー）→
3. 第 II 部・第 III 部の章を順に執筆（章ごとに codex レビュー）。
- 章末に問題、解答は付録 B。実装状態ラベルと定型枠を各章で守る。
- コード解説章は設計書・実装と矛盾しないことを都度確認する。
