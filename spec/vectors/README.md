# spec/vectors/ — cross-language テストベクタ

Rust と Swift の独立実装が共有する**真実**。実装コードは共有しないため、ここのベクタで
受理集合・バイト一致・検証挙動を固定する（実装計画 §4.1/§4.2、P0 完了条件）。
**Rust を producer/oracle** として値を確定し、Swift は同じ fixture を consumer として読む。
形式は **TSV**（`#` 始まりはコメント、列はタブ区切り）。

## ファイルと契約

### `text_policy.tsv` — テキストポリシー（プロファイル §7・§7.1）
列: `id <TAB> expected <TAB> scalars(空白区切り16進 code point) <TAB> description`。
`expected` は `ok` / `not_nfc` / `unassigned` / `bad_text`。NFC・Unicode 16.0 未割当(Cn)・
制御(C0/C1)・Bidi_Control(全12)・境界受理(space/DEL/NBSP)を網羅。
検証: `bifrauth-proto` の `text_policy_vectors_conformance` が TextPolicy の結果と一致を固定。

### `messages_golden.tsv` — メッセージ canonical（プロファイル §4/§5/§6）
列: `id <TAB> canonical_hex`。`challenge_v1` / `response_v1` / `envelope_v1` の canonical CBOR。
検証: `bifrauth-proto` の `messages_golden_conformance` が decode→再encode の byte 一致を固定。

### `crypto_vectors.tsv` — 暗号（プロファイル §5/§6、設計 §9）
列: `name <TAB> hex`。固定 canonical challenge に対する値。契約:
- **exact 再生成**: `ed25519_seed` から作った鍵の pubkey/sign が `ed25519_pubkey`/`ed25519_sig` と
  byte 一致（Ed25519 は決定論的）。`SHA-256(canonical)` == `sha256`。
- **検証成功**: `p256_sec1` で canonical への `p256_der_sig` が verify 成功（P-256 は nonce 依存の
  ため実装間の byte 一致は要求しない）。
- **negative**: `canonical_tampered` に対して Ed25519/P-256 の署名がいずれも検証失敗。
検証: `mock-iphone` の `shared_crypto_vectors_conformance`（`messages_golden` の challenge_v1 と
canonical が byte 同一であることも相互 assert）。

## 補足
- `crypto_vectors.tsv` の canonical は verifier_key_id=0x33*32 の**crypto 単体 fixture**で、
  pairing 整合値ではない（`mock-iphone.process` には投入できない）。
- 鍵はすべて**公開してよいテスト鍵**。生成の再現手順は各生成物・`tools/` を参照。
