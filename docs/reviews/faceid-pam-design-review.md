# 設計書レビュー結果 — iPhone Face ID を用いた Linux PAM 認証システム

**対象文書:** iPhone Face ID を用いた Linux PAM 認証システム設計書（Draft for Review, 2026-07-10）
**レビュー範囲:** セキュリティ、Linux/PAM 統合、iOS、運用
**節番号は対象設計書のもの。**

---

## 総評

設計思想は妥当で、堅牢。以下の判断はいずれも正しい。

- Face ID の真偽値を送らず、Secure Enclave の署名を使う
- 最終判定を root 所有の verifier daemon に集約する
- 非特権 transport helper の `success` を信用しない
- nonce だけでなくユーザー・用途・端末・期限を署名対象へ束縛する
- Linux と iPhone を相互認証する
- 通信路を暗号化するが通信路だけを信用しない
- Face ID が使えない場合の回復経路を残す
- root 侵害は防御対象外と明示する

三層構成（薄い PAM モジュール → root verifier daemon → 非特権 transport helper）は
OpenSSH 的な特権分離の教科書的な形になっており、二層構成より確実に堅牢。
§22 の初期スコープ、§23 の実装順序も現実的。

以下、着手前に対応すべき指摘を重要度順に示す。

---

## 指摘 1（最重要）: 用途束縛（§9.2）は polkit では PAM 層で成立しない

### 問題
設計書は `requested_action=1password.unlock` を署名対象に含め、§4.1 で
「1Password 解錠署名を sudo や別 polkit action へ流用する攻撃」を**防御対象**に挙げている。
しかし polkit 経由では、この防御機構が原理的に成立しない。§12.4 / §21.1 で著者自身が
「未検証の未決事項」として挙げているが、これは "未検証" ではなく "現状の polkit では
PAM 層で実現不可能" と断定できる。

### 根拠（polkit の実装挙動）
- polkit は PAM のサービス名として固定で `polkit-1` を使う。設定は `/etc/pam.d/polkit-1`。
  したがって 1Password の解錠も `pkexec` も、PAM から見れば一律 `PAM_SERVICE=polkit-1` で
  区別がつかない。
- action の ID（例: `org.freedesktop.policykit.exec`）や mechanism が渡す変数は、
  polkit の**認可ルール**（`/etc/polkit-1/rules.d/` の JavaScript）側で `action.id` /
  `action.lookup()` として参照できる。PAM 会話には乗ってこない。
- 実際の認証は `polkit-agent-helper-1` が PAM と会話して行う。action ID はこの経路に含まれない。
- 出典: polkit 公式ドキュメント（polkit.8）、polkit issue #592（PAM サービス名 = polkit-1）、
  pam-face issue #8（polkit 経由では `pamh.service == "polkit-1"`）。

### 脅威モデルに沿った切り分け
- **PAM サービス跨ぎ（polkit ↔ sudo ↔ login）の流用**: `pam_service` 束縛で防げる。設計は正しい。
- **polkit action 跨ぎ（1Password ↔ pkexec 等、いずれも polkit-1）の流用**: `pam_service` が
  同一のため**防げない**。`sufficient` で faceid を polkit-1 スタックに入れた時点で、
  `auth_self` を要求する全 polkit action で faceid が使える。§4.1 の防御主張と §9.6 の
  用途照合はここで矛盾する。

### 推奨対応
- 「action を署名へ束縛する」方向ではなく、**polkit 認可ルール層（rules.d）で
  どの `action.id` にこの認証を許すかを制御する**方向へ設計変更する。
- ただし rules が選べるのは結果（yes / auth_self / auth_admin / not_handled）のみで、
  action ごとに PAM スタックを差し替えることはできない。現実的には
  「1Password の action を rules で明示的に扱い、faceid を使わせたくない管理系 action は
  auth_admin（別経路）へ寄せる」といった設計になる。
- §9.2 の「action を署名対象へ入れて allowlist」は polkit 単独スコープでは成立しないため、
  §4.1 の脅威記述と併せて書き直す。
- 補足: `requested_action` フィールド自体は、将来 sudo / login など PAM サービスが異なる
  場面へ拡張する際には `PAM_SERVICE` から導出でき意味を持つ。問題は polkit 内の粒度に限る。

---

## 指摘 2: ペアリングの MITM 対策（§8.2）に仕様の穴

### 問題
QR + 短い比較コードという SAS（short authenticated string）方式の枠組みは正しいが、
**比較コードが何から導出されるかが未定義**。ここが曖昧だと MITM を防げない。
特に QR は Linux→iPhone に verifier 公開鍵を運ぶ一方、iPhone→Linux（Secure Enclave 公開鍵）の
戻り経路の真正性の担保が書かれていない。

### 推奨対応
- 比較コードを「双方の公開鍵 + ペアリング nonce を含むトランスクリプト全体のハッシュを
  短縮したもの」と明記する（Bluetooth numeric comparison / Signal safety number と同じ考え方）。
- 片側が生成した乱数を見せるだけの方式にしない。

---

## 指摘 3: 期限判定は wall-clock ではなく verifier の monotonic clock で（§9.6-4, §16, §21.10）

### 問題
`issued_at` / `expires_at` を署名に含めるのは良いが、iPhone と Linux は独立時計のため、
絶対時刻の比較で期限判定すると、短 TTL を狙うほど時計ずれで誤判定する。

### 推奨対応
- 期限の権威判定は **verifier が request を発行した monotonic 時刻からの経過**で行う。
- 署名内の `expires_at` は iPhone 側の表示と phone 側の失効チェック用と位置づける。
- §16 のローカルタイムアウトは正しい発想。§9.6 ステップ 4 を「verifier 自身の単調時計で測る」と
  明示すれば整合し、clock rollback（§21.10）の懸念もほぼ解消する。

---

## 指摘 4: 暗号チャネルの終端点を明記すべき（§6, §10.1）

### 問題
構成図では暗号チャネルが transport helper と iPhone の間にある。helper で終端する場合、
helper はセッション内部に入る。ただし「verifier 生成チャレンジ + SE 署名」の署名連鎖が
完全性を担保するため、helper が改ざんしても検出できる。つまり
**認証の完全性はチャネル暗号ではなく署名連鎖に由来する**。mutual-auth チャネルは主に
機密性と DoS 耐性の defense-in-depth。§10.1 が Noise / TLS 相互認証を必須級に描いているのは
実際の信頼の所在とややズレる。

### 推奨対応
- チャネルの終端点（verifier まで張るのか helper 止まりか）を一文で確定させる。
- §7.2 / §24 の「通信路だけを信用しない」という思想は正しいので、§10.1 の記述温度を合わせる。

---

## 指摘 5: 「fail closed」の用語が誤解を招く（§19）

### 問題
「verifier 停止時は fail closed とし、下段 PAM へフォールバック」とあるが、`sufficient` 行が
失敗して次のパスワード認証へ流れるのは挙動としては**フォールバック（fail-secure with fallback）**
であり、一般的な意味の fail closed（＝拒否）ではない。

### 推奨対応
- 用語を整理する。守るべき不変条件は「エラー時に絶対に `PAM_SUCCESS` を返さない」
  「無期限ブロックしない」で、これは §12.2 / §16 で押さえられている。
- `PAM_AUTH_ERR`（Face ID 明示拒否）も `sufficient` ではパスワードへ素通りする点が
  意図どおりか確認し、明記する。

---

## 指摘 6: デプロイの実地ハマり — polkit-1 の設定パスが揺れている（§12.3, §19）

### 問題
§12.3 でディストリ差を警告しているのは良いが、より具体的な地雷がある。
一部ディストリ（Arch 系）では `/etc/pam.d/polkit-1` が `.pacsave` にリネームされ、
告知なしに `pam_u2f` 設定が無効化された事例がある（出典: EndeavourOS フォーラム 2024-01）。
faceid も同じ経路に置く以上、**パッケージ更新で設定が退避されて突然無効化される**リスクがある。

### 推奨対応
- インストーラは配置後の存在確認に加え、パッケージ更新後の再検証（ヘルスチェック）まで行う。

---

## 指摘 7（細かい点）

- **§13.1 の用語**: `.biometryCurrentSet` は仕様上パスコードフォールバックを許可しない
  （許可するのは `.userPresence` / `.devicePasscode`）。「フォールバックを許可するかは
  製品ポリシー」という記述は、フラグ選択が既にそれを決めている点と混線している。
  「生体限定なら `.biometryCurrentSet`、パスコード許容なら別フラグ」と対応づける。
- **§8.1 の `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`**: `.biometryCurrentSet` により
  鍵は既に端末バインド・非移行のため belt-and-suspenders。誤りではないが意図を一言添える。
- **§9.6 の request_id 消費**: 並行応答での二重検証を防ぐため、**アトミックな
  check-and-consume** であることを明記する。
- **account/session フェーズ**: polkit は auth のみ回すが、他サービスへ拡張する将来を考え
  `pam_sm_acct_mgmt` を明示的に no-op にしておく。

---

## 着手前の優先順位

1. **polkit action 束縛の方針転換**: §9.2 / §12.4 を rules.d 前提に書き直し、§4.1 の脅威と整合させる。
2. **ペアリング比較コードの導出を厳密化**: §8.2。
3. **期限判定を monotonic clock に**: §9.6-4 / §16。

この 3 点を確定させれば、残りはそのまま実装に進める品質。指摘 4〜7 は記述の明確化・用語整理・
運用強化であり、設計の根幹を揺るがすものではない。
