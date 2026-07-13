# spec/vectors/ — golden / negative テストベクタ

Rust と Swift の独立実装が共有する**真実**。実装コードは共有しないため、ここのベクタで
バイト単位の一致と拒否挙動を担保する（実装計画 §4.1/§4.2、P0 完了条件）。

- **golden**: 固定入力に対する正解（canonical CBOR バイト列、`SHA-256(canonical_challenge)`、
  Ed25519 / P-256 署名など）。両実装が再現できること。
- **negative**: 必ず**拒否**すべき入力（非 canonical CBOR、未知/重複キー、非最短、indefinite length、
  float/tag 混入、oversized、unsupported version、改ざん署名 など）。

形式は P0 実装時に確定（例: `*.json` に hex を格納）。現状はプレースホルダ。
