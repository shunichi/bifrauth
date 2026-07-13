# ios/ — BifrAuth Mobile (iOS)

Swift 製の iPhone アプリ（**BifrAuth Mobile**）を置くディレクトリ。Secure Enclave / Face ID /
LocalAuthentication を要するため、**このマシン（Linux）ではビルドできない。後で Mac 上で実装する**
（実装計画 `docs/implementation-plan.md` のフェーズ「後で Mac / iPhone 実機で実施」）。

現状はプレースホルダ。Linux 側は `crates/mock-iphone` で iPhone 側処理を模擬してテストする。

実機実装時に固定する主要点（計画 §4.2）:
- 署名は `SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, canonical_challenge_bytes, &error)`。
  入力は未ハッシュの canonical bytes、SHA-256 は Security.framework が1回だけ、出力は X9.62 DER。
- `spec/` の canonical encoding プロファイルと `spec/vectors/` の golden/negative ベクタを Rust 実装と共有する。
