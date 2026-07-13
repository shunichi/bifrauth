# BifrAuth CBOR プロファイル（ドラフト v0.3）

**目的:** BifrAuth の署名対象・メッセージを、Rust と Swift の独立実装が**バイト単位で一致**して
生成・検証できるよう、CBOR の決定的サブセットと各メッセージのスキーマを**確定値で**固定する。
根拠: 実装計画 §4.1、設計書 §9。

> ステータス: **codex クロスレビュー 3巡で承認済み**（P0 実装の規範）。v0.2→v0.3 で第2巡（1〜12）を
> 確定値で反映し、第3巡で承認。承認時の非blocking局所修正5点（requested_action 256B / Unicode 16.0
> Rev.56 pin / Bidi_Control 定義 / §9 予約明記 / envelope version cross-ref）を反映済み。
> レビュー記録: `docs/reviews/cbor-profile-review-20260713.md`。

## 0. 二層構造

- **層A: BifrAuth deterministic profile validity** — バイト列がプロファイルの決定的規則（§1・§2）に
  従うか。メッセージ種別非依存。RFC 8949 core canonicality を基礎に BifrAuth 制約（allowlist・NFC 等）を
  重ねたもので、**RFC core canonicality そのものとは呼ばない**（codex 指摘11）。
- **層B: schema-valid** — その値が対象メッセージのスキーマ（§4〜§6）に厳密一致するか。

受信バイト列を**直接走査**して層Aを判定し、続いて層Bを判定する（decode→再encode 比較はしない）。
受理は両層を満たすもののみ。

---

## 1. 層A: 許可データモデル（allowlist）

使用する CBOR 型: **unsigned integer（major 0）/ byte string（major 2, definite）/ text string
（major 3, definite, UTF-8）/ map（major 5, definite）/ `null`（0xf6）のみ**。

**禁止（negative ベクタを置く）:** negative integer（major 1）、array（major 4）※初版未使用、
tag（major 6, bignum 2/3 含む）、float、bool（0xf4/0xf5）、undefined（0xf7）、`null` 以外の simple、
indefinite-length・break（0xff）。

## 2. 層A: 決定的規則と直接拒否項目

規則（RFC 8949 §4.2.1 core deterministic 基礎）: definite length のみ / preferred serialization（最短）/
map キーは uint で**エンコード済みバイト列の bytewise 辞書順昇順**（uint キーでは数値昇順に一致）/
text は UTF-8 かつ NFC（§7, application 制約）。

スキャナの直接拒否項目:
- 非最短の integer / length head
- indefinite-length（全 major）/ 不正・早期 break `0xff`
- major 0/1/6 の additional info = 31、reserved additional info 28..30
- tag / bignum / float / bool / undefined / **`null` 以外の simple**
- **simple value の扱い（指摘5・訂正）**: simple 0..23 を `0xf8 xx` で表す形は**非最短**として拒否。
  simple 24..255 は `0xf8 xx` が preferred だが **allowlist 外**として拒否（＝理由が異なる。
  negative ベクタも「非最短(0..23)」と「allowlist外(24..255)」で分ける）。
- map/array の**宣言長と実要素数の不一致**（well-formedness を走査で確認 → その後 allowlist 型判定。
  受理結果は順序に依らず同一, 指摘11）
- **重複キー / 昇順違反**（strict `previous_key < current_key`）
- truncated head/body、**trailing bytes**、**複数 top-level 値**
- 不正 UTF-8 / 非 NFC（§7）

## 3. 層A: リソース境界（length-head 時点で allocation 前に拒否）

深さは全メッセージ **1（top-level map のみ）**。汎用の「累積アイテム数」上限は置かず、**各スキーマの
固定 entry 数**（§4/§5/§8）で代替する（指摘4）。サイズは包含関係を分けて固定（指摘4）:

| メッセージ | 最大バイト |
|---|---|
| `challenge.v1`（envelope の inner） | 4096 B |
| challenge envelope（outer, inner を bstr で内包） | 4608 B |
| `response.v1` | 512 B |

フィールド個別のバイト上限は §4/§5/§8 の表で確定。

## 4. 層B: `bifrauth.challenge.v1`（definite map, キー 0..15 全必須・各1回）

余分/欠損/型違い/`null` 位置違いは拒否。`pam_tty`/`pam_rhost` は欠損不可（値のみ `null` 可）。

| key | field | 型 | 確定制約 |
|---|---|---|---|
| 0 | `message_type` | tstr | 完全一致 `"bifrauth.challenge.v1"`（ASCII） |
| 1 | `protocol_version` | uint | **= 1**（§10 の対応表） |
| 2 | `request_id` | bstr | **exact 16 B**（CSPRNG） |
| 3 | `nonce` | bstr | **exact 16 B** |
| 4 | `verifier_key_id` | bstr | **exact 32 B** |
| 5 | `linux_device_id` | bstr | **exact 16 B**（CSPRNG。§8） |
| 6 | `linux_device_name` | tstr | 1..128 B、空不可、NUL/C0/C1/bidi 拒否 |
| 7 | `target_uid` | uint | **0..4294967294**（`(uid_t)-1`=4294967295 を拒否, 指摘9） |
| 8 | `target_username` | tstr | 1..256 B、空不可、NUL/C0/C1/bidi 拒否 |
| 9 | `pam_service` | tstr | 1..128 B、空不可、NUL/C0/C1/bidi 拒否 |
| 10 | `pam_tty` | tstr / `null` | 1..256 B（tstr のとき）、NUL/C0/C1/bidi 拒否 |
| 11 | `pam_rhost` | tstr / `null` | 1..256 B（tstr のとき）、NUL/C0/C1/bidi 拒否 |
| 12 | `requested_action` | tstr | **1..256 B**、空不可、NUL/C0/C1/bidi 拒否（`pam_service`(≤128B)＋`.authenticate` 導出が最大 141 B になり得るため 256 B に拡張, 指摘1） |
| 13 | `issued_at` | uint | epoch 秒、**0..253402300799**（year 9999, < 2^53） |
| 14 | `expires_at` | uint | epoch 秒、同上範囲、**`issued_at < expires_at`**、**`expires_at - issued_at` は 1..30 秒**（設計の総 30 秒 timeout と整合） |
| 15 | `confirmation_code` | tstr | **ASCII `[0-9]{6}`**（exact 6 B） |

TTL の権威は Linux 側 `CLOCK_BOOTTIME`（設計§9.7）。`issued_at`/`expires_at` は iPhone 表示・phone 側
期限用。phone 側 clock skew の許容は別 policy として規定（本プロファイルの数値制約とは別レイヤ）。

## 5. 層B: `bifrauth.response.v1`（definite map, キー 0..6 全必須・各1回）

message_type を含め **7 entry**（指摘1: nested 禁止・depth=1 と両立するよう alg/sig を分離）。

| key | field | 型 | 確定制約 |
|---|---|---|---|
| 0 | `message_type` | tstr | 完全一致 `"bifrauth.response.v1"` |
| 1 | `protocol_version` | uint | **保留 challenge と exact 一致**（= 1） |
| 2 | `request_id` | bstr | exact 16 B、保留要求と一致 |
| 3 | `iphone_device_id` | bstr | **exact 16 B**、鍵選択ヒント（本人性の根拠にしない。ただし選択した登録鍵と対象 user への登録対応を必ず検査, 指摘8） |
| 4 | `signed_payload_hash` | bstr | exact 32 B。下記の扱い |
| 5 | `signature_algorithm` | tstr | 完全一致 `"ECDSA_P256_SHA256_DER"`（§5.1） |
| 6 | `signature` | bstr | 1..**72 B**（P-256 X9.62 DER の最大長）、§5.1 |

**`signed_payload_hash`（設計§9.7・計画§4.3）:** `bifrauthd` は保留 `canonical_challenge` から SHA-256 を
再計算し、受信値と不一致なら **malformed として拒否**。ただし**署名検証の入力には決して使わず**、
**保存済み canonical bytes** に対して P-256/SHA-256 検証する。**response map 自体は署名対象ではない。**

### 5.1 署名（確定, 指摘2）
- `signature_algorithm` wire は **exact tstr `"ECDSA_P256_SHA256_DER"`**（enum 衝突回避のため文字列固定）。
- `signature` は **X9.62 DER**、上限 **72 B**（P-256 DER の exact maximum）。crypto 層で **strict DER**
  パースと **`r,s ∈ [1, n-1]`** を検査。**初版は low-S を要求しない**（request の atomic consume で
  malleability の実害がないため。将来要求へ変更可能）。

## 6. challenge envelope: `bifrauth.envelope.v1`（definite map, キー 0..2 全必須, 指摘3）

外部 framing で型が確定するため message_type/protocol_version を持たない **3-entry map**。

| key | field | 型 | 確定制約 |
|---|---|---|---|
| 0 | `canonical_challenge` | bstr | 1..4096 B（§3 inner 上限）。層A/層B 検査対象の**生バイト列** |
| 1 | `verifier_signature_algorithm` | tstr | 完全一致 `"Ed25519"` |
| 2 | `verifier_signature` | bstr | **exact 64 B**（Ed25519） |

iPhone は Ed25519 署名を **`canonical_challenge` の生バイト列**に対して検証し、**同じバイト列**へ
層A/層B 検査を行う。**helper が decode/reencode した値を署名検証に使わない。**

## 7. 文字列（NFC, 指摘6・7）

- **NFC は application 制約**（RFC core の要件ではない）。normative: **UAX #15, Unicode 16.0 / Revision 56**
  （§13 に固定 URL）。**未割当判定は Unicode 16.0 UCD 基準**とし、**未割当 code point を含む文字列は拒否**
  （指摘2）。
- **生成側は黙って normalize せず、非 NFC・非 UTF-8 を拒否**（識別子の別名化防止）。拒否時は PAM 戻り値を
  成功にせず **password フォールバック**（設計§12.3）。
- 全 tstr で **NUL / C0（U+0000..U+001F）/ C1（U+0080..U+009F）/ bidi 制御を拒否**。bidi 制御は
  **Unicode 16.0 の `Bidi_Control=Yes` プロパティを持つ code point**と定義する（Rust/Swift が同一集合を
  拒否できるよう UCD 由来で固定, 指摘3）。`message_type`/`confirmation_code` は ASCII のみ。

## 8. device ID（凍結, 指摘8）

`linux_device_id`（challenge key5）/`iphone_device_id`（response key3）は **exact 16 B bstr の CSPRNG ID**。
pairing transcript・登録情報も同一表現を使う。iphone ID は鍵選択ヒントだが、**選択した登録鍵と対象
user への登録対応を必ず検査**する。

## 9.（予約・将来利用, 指摘4）

将来のフィールド／メッセージ拡張のための予約枠。現状は未使用。

## 10. バージョン進化（役割分離, 指摘10）

- **スキーマ変更は必ず新 `message_type`**（例 `bifrauth.challenge.v2`）。同一 `message_type` の
  スキーマを `protocol_version` 値で変えない。
- **`protocol_version` は全体の互換セット / handshake version**（別役割）。初版対応表:
  **`{challenge.v1, response.v1, envelope.v1} ↔ protocol_version = 1`**。
- `response.protocol_version` は保留 challenge と一致。旧スキーマの key は**永久に再利用しない**。
- 未知は **fail closed**、**downgrade 禁止**。
- **envelope（§6）は on-wire に message_type/protocol_version を持たない**。`envelope.v1` の選択は
  **外部 framing で固定**され、内包する inner challenge の `protocol_version = 1` も検査する（指摘5）。

## 11. テストベクタ（`spec/vectors/`, 指摘12）

- **negative**: 非最短 int/length、indefinite（全 major）、map 順序境界（**23/24・255/256**）、重複、
  missing/unknown、型違い、禁止 simple/negative/tag/bignum/float、**simple `0xf8` 0..23 非最短 と 24..255
  allowlist外の区別**、不正 UTF-8 / 非 NFC / 未割当、allocation 前 oversize（inner/outer 別）、深さ超過、
  trailing、truncation、複数 top-level、**response hash mismatch**、**response 7-key 順序違反**、
  **algorithm 改ざん**、**DER malformed/overlong**、**UID 4294967295**、**zero/過大 TTL**、
  **device ID wrong length**、envelope 境界（inner 最大 / outer 最大）。
- **golden**: 各フィールド境界値、Rust 生成 ↔ Swift 検証 / 逆方向の双方。

## 12. 正本設計との同期（承認後に実施, 指摘12/前巡点12）

プロファイル承認後、設計 §9.4 を「BifrAuth profile の Deterministic CBOR」へ更新、§21.4 を解消、
設計 version を上げ、変更履歴と `docs/reviews/` の記録を残す。

## 13. Normative references

- RFC 8949 §4.2.1 Deterministic Encoding — https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
- Unicode UAX #15 Normalization Forms, **Unicode 16.0 / Revision 56**（固定 revision） — https://www.unicode.org/reports/tr15/tr15-56.html
- 未割当判定・`Bidi_Control` プロパティ: **Unicode 16.0 UCD** — https://www.unicode.org/versions/Unicode16.0.0/
- user_namespaces(7)（`(uid_t)-1` 予約） — https://man7.org/linux/man-pages/man7/user_namespaces.7.html
