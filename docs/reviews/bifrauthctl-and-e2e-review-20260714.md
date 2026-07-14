# レビュー記録: bifrauthctl 管理 CLI + デバイスレジストリ + E2E（task 0009）

**日付:** 2026-07-14
**対象:** 実装計画 `docs/plans/0009-bifrauthctl-and-e2e.md`。成果物は永続デバイスレジストリ
（`crates/bifrauthd/src/registry.rs`）、Verifier の失効/snapshot 対応（`crates/bifrauthd/src/lib.rs`）、
`bifrauthctl`（register/revoke/list）、実 socket 経由の E2E 統合テスト。設計書 §8.3・§14.1・§21・§23 を更新。
**レビュー方式:** agmsg による Claude ⇔ Codex クロスレビュー（CLAUDE.md / AGENTS.md）。
**結論:** **第3巡で承認**。承認時の実装確認点5点を計画の「実装時に守る点」に反映し実装で遵守。

---

## 第1巡（codex → claude）: 要修正
主要判断（D1 CBOR 化・D3 tombstone・D4 pure Verifier/IO 分離・D6 verifier_key/Zeroize 別タスク・
D7 E2E をテスト主／runnable は task B）はいずれも支持。D5（稼働中 daemon 未反映）は「main 未配線の今だけ」
条件で許容。必須修正:
1. register の atomic non-overwrite: temp→通常 rename は既存を置換する。`renameat2(RENAME_NOREPLACE)` を
   dirfd 相対で使い EEXIST→AlreadyRegistered。TOCTOU 禁止、publish 後 fsync(dir)、temp cleanup。
2. 全パス走査を dirfd/openat ベースに（中間 symlink 差し替え対策）。各成分 O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC
   + fstat 検証。device file は nlink/size も検査。
3. revoke の並行性・rollback（per-device/uid advisory lock、CAS 相当）。
4. reload は transactional（逐次適用せず snapshot を atomic replace、失敗時 fail closed、部分公開禁止）。
5. schema 厳格化（キー集合固定・p256 検証・size 上限・revoked_at は clock 逆行で復活しない・list は
   壊れた entry で非 zero 終了）。D5 の CLI 明示と blocking dependency 追跡。D7 に pending が revoke 境界を
   跨ぐケースを追加。

### claude 対応: 1〜5 を計画へ反映（D2-a/D2-b/D2-c、D3-a、D4-a、D1-a、D5 条件、D7）。

## 第2巡（codex → claude）: 要修正（lock/snapshot 整合性 1 点）
per-uid `devices/.lock` では `load_all` が複数 UID 走査中に別 UID の write を許し mixed snapshot を作れる。
また `.lock` が devices 配下の「未知 entry は fail closed」と衝突、lock 自体の安全な初回作成・検証・
非置換規約が未定義。推奨: base 直下に単一 registry-wide lock（`.registry.lock`）、変更=exclusive/
読み=shared、O_CREAT|O_NOFOLLOW|O_CLOEXEC + fstat(regular/owner/mode/nlink==1) 後 flock、rename/unlink 禁止、
enumeration はこの予約名のみ除外。軽微: label の canonical 表現固定、本番 owner 固定（注入は test 限定）+
CLI euid==0、mode 期待値固定、replace_devices の duplicate 拒否 + 全鍵再検証。

### claude 対応: D3-a を全面書換（registry-wide `.registry.lock`、shared/exclusive で point-in-time
snapshot 保証）。軽微点（label 空文字＝なし、owner 固定 constructor、mode 固定、snapshot 再検証）も反映。

## 第3巡（codex → claude）: 承認
registry-wide lock で相互排他・writer 停止・point-in-time snapshot が保証され第2巡の blocking は解消。
実装レビュー時の確認点5点（flock の OFD semantics 実テスト・lock 作成 durability と既存 inode fstat・
temp cleanup guard の disarm 規約と手動復旧案内・snapshot の完全所有・replace_devices と verify の
Verifier mutex 直列化）を添えて承認。

### claude 対応: 5 点を計画「実装時に守る点」に追記し実装で遵守（OFD 相互排他は同時 register テストで担保、
lock 初回作成で fchmod+fsync(file/dir)、TempGuard は publish 成功時のみ disarm し Drop で best-effort unlink、
LOCK_SH は完全所有の `Vec<DeviceRecord>`/`DeviceSnapshot` を返す、replace_devices は Verifier mutex 下で
verify と直列化）。

---

## 主要な確定事項

- **レジストリ形式**: 決定論的 CBOR（旧 `.json` 案から変更）。cbor-profile §8 と一致。per-device 1 ファイル
  `/etc/bifrauthd/users/<uid>/devices/<device_id_hex>.cbor`（root:root 0640、親 dir 0700、lock 0600）。
- **失効**: tombstone（`revoked_at`）。失効デバイスは verify 失敗（`VerifyError::RevokedDevice`）、
  再登録も拒否（§14.2）。
- **並行性**: registry-wide `.registry.lock`（変更=LOCK_EX / 読み=LOCK_SH）で point-in-time snapshot。
  register は `renameat2(RENAME_NOREPLACE)` で非上書き。
- **reload**: `Registry::load_all()` が検証済み `DeviceSnapshot` を返し、`Verifier::replace_devices()` が
  単一ロック下で atomic に差し替える（部分適用しない）。
- **本番配線の blocking dependency**: 稼働中 daemon への transactional reload（管理 IPC / SIGHUP 等）が
  入るまで production serve を有効化しない（§21-9・§23-10）。runnable auth client は task B の done criteria へ。
- **スコープ外（別タスク）**: verifier_key（Ed25519 シード）のファイル生成/ロード（impl-plan §4.7）と
  `Zeroizing<[u8;32]>` シードロード API（0007 フォローアップ）。デバイスレジストリと直交。
