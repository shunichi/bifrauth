# 実装計画: task 0009 — bifrauthctl 管理 CLI + E2E CLI クライアント

> レビュー依頼用ドラフト（codex 宛）。設計書 §8.2/§8.3/§9.7/§14/§18.3、
> implementation-plan §4.7、cbor-profile §8 を根拠に、未確定領域の設計判断をまとめる。

## スコープ（task 0009 の done criteria）

1. デバイスレジストリの**永続化**（`/etc/bifrauthd/` 配下、root所有・制限perm）。
2. Verifier に **revoke** とレジストリのロード対応を追加。**失効デバイスは verify に失敗**。
3. **bifrauthctl**（root 専用 CLI）: `register` / `revoke` / `list`。
4. **E2E**: socket 経由で issue→respond→verify を一周（mock-iphone を Transport に注入）。
   失効デバイスが verify に失敗することも E2E で示す。
5. `cargo test --workspace` / `clippy -D warnings` / `fmt --check` 緑。

## 主要な設計判断（← ここを重点レビューしてほしい）

### D1. レジストリのシリアライズ形式: **正規化 CBOR**（設計書 §8.3 の `.json` から変更を提案）

- 設計書 §8.3 は `/etc/bifrauthd/users/<uid>/devices/<device-id>.json`（JSON）と書くが、
  **cbor-profile §8** は「pairing transcript・登録情報も同一表現（CBOR、device ID = exact 16B）を使う」
  と規定しており、両者が矛盾する。
- 提案: レジストリファイルも **`bifrauth_proto::cbor` の正規化 CBOR** で保存する。理由:
  - プロジェクト全体が「単一の正規受理表現＝決定論的 CBOR」で統一されている（proto lib.rs の設計思想）。
  - JSON 依存（serde_json 等）を新規に増やさない。決定論的でバイト一意。
  - cbor-profile §8 と一致する。
- **設計書 §8.3 の更新が必要**（`.json` → 正規化 CBOR、内部スキーマの明記）。承認いただければ
  設計書とレビュー記録（docs/reviews/）を更新する。
- 保存パス: `<root>/users/<uid>/devices/<device_id_hex>.cbor`
  （`<root>` は本番 `/etc/bifrauthd`、テストは一時ディレクトリを注入）。
- 代替案（不採用）: 単一レジストリファイル。→ register/revoke が全体 read-modify-write になり
  並行 bifrauthctl 実行でレース窓が広がる。per-device ファイルなら register=atomic create、
  revoke=1ファイルの書換で blast radius が小さい。設計書 §8.3 のレイアウトとも一致。

#### レジストリ device レコードのスキーマ（正規化 CBOR map、uint キー）

| key | 型 | 内容 |
|----|----|------|
| 0 | uint | format_version（=1） |
| 1 | uint | uid（`target_uid` と同レンジ 0..=4294967294、`(uid_t)-1` 拒否） |
| 2 | bstr(16) | device_id（exact 16B、cbor-profile §8） |
| 3 | bstr | p256_sec1（登録公開鍵） |
| 4 | tstr | label（任意・人間可読名。text policy 準拠、長さ上限） |
| 5 | uint | created_at（wall-clock epoch 秒） |
| 6 | uint | revoked_at（**失効時のみ存在**。wall-clock epoch 秒） |

- key 6 の有無で active/revoked を表す（tombstone 方式。D3 参照）。
- device_id はファイル名（hex）とレコード内 key2 の両方に持ち、ロード時に一致を検査
  （ファイル名改竄・取り違え検出）。

#### D1-a. スキーマ厳格化（codex schema 補足）

- **map キー集合**: format_version==1 のとき active={0..5}／revoked={0..6} のキー集合**のみ**許可。
  unknown key・missing key は拒否（cbor 層が strict ascending・重複拒否を既に保証）。
- **p256_sec1**: decode/register 時に P-256 として検証（`validate_public_key`）。長さ上限 **33/65B**
  （compressed/uncompressed）。
- **label**: key4 は**常に存在**する tstr（canonical 表現を 1 つに固定）。CLI で `--label` 省略時は
  **空文字列 `""`（= ラベルなし）** を格納。proto の text policy 準拠（ただし label は空を許容）+ 明示的
  長さ上限。
- **uid**: `0..=4294967294`（`(uid_t)-1`=4294967295 拒否）。
- **record/ファイル合計 size 上限**を alloc 前に検査。
- **revoked_at は状態フラグ**であり、wall clock の逆行で失効を復活させない（revoked record は
  revoked_at の値に関わらず revoked 扱い）。

### D2. ファイル安全性（implementation-plan §4.7 踏襲 + codex 第1ラウンド必須修正）

- ディレクトリ: `/etc/bifrauthd` および配下 `users/`, `users/<uid>/`, `devices/` を root:root・
  **0700** で作成（親から辿って作る）。
- device ファイル: root:root・**0640**（設計書 §8.3 準拠）。
- device ファイル名: uid は canonical decimal、device_id は canonical lowerhex。enumeration 時に
  非 canonical 名・symlink・filename↔record 不一致・未知 entry を検出したら **fail closed**
  （黙って skip しない。list は非 zero 終了、load は abort）。

#### D2-a. パス走査は全て dirfd/openat ベース（必須2: 中間 symlink 差替え対策）

文字列パスで `mkdir`/`open` し最終ファイルだけ `O_NOFOLLOW` にしても、中間ディレクトリを
symlink に差し替えられる。信頼済み base dirfd から各コンポーネントを順に辿る:
- 各中間ディレクトリを `openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` で開き、
  `fstat` で **ディレクトリであること・所有者 uid/gid・mode（想定外の書込ビットが無いこと）** を検証。
- 作成は `mkdirat` → 再 `openat`/再検証（作成と検証を分けても、検証済み dirfd 相対でのみ以降を操作）。
- 所有者検証は本番では uid==0 && gid==0 を要求する。**本番 constructor は期待 owner=0 を固定**し
  呼出側に任意値を渡させない。owner 注入 constructor は `cfg(test)` または明示的な testing 専用 API に
  限定する（テスト実行=非特権でも走査・symlink 拒否・mode 検証を行えるようにするため）。所有権チェック
  だけ環境依存にし、symlink/非通常/mode の検査は常に有効。CLI（bifrauthctl）は **euid==0 を早期検査**。
- **mode 期待値を固定**: dir=**0700** / device file=**0640** / lock=**0600**。少なくとも group/world
  write を拒否。既存が過度に緩ければ fail closed。
- device ファイルは `openat(...O_NOFOLLOW...)` で開き、`fstat` で **通常ファイル・所有者・mode・
  link count（nlink==1、想定外の hardlink 拒否）・size 上限（alloc 前）** を検査。

#### D2-b. register の atomic non-overwrite（必須1）

`temp → 通常 rename` は既存 target を**置換する**ため、O_EXCL で temp を作っても
AlreadyRegistered/tombstone 保護にならない。存在確認→rename の TOCTOU も禁止。
- CSPRNG 名の temp ファイルを同一 devices ディレクトリ（検証済み dirfd 相対）に `O_EXCL|O_NOFOLLOW`
  で作成 → 内容書込 → `fsync(file)` → **`renameat2(dirfd, temp, dirfd, final, RENAME_NOREPLACE)`**
  で publish → `fsync(dir)`。`EEXIST` を **AlreadyRegistered** に写像。
  （rustix に `renameat_with(..., RenameFlags::NOREPLACE)` あり。無い場合は同一 dir 内 hard-link に
  よる no-replace publish で代替。）
- 失敗時は temp を `unlinkat` で cleanup。
- 既存 active/revoked tombstone があれば必ず拒否（§14.2 黙示再登録防止）。
- テスト: 2 プロセス同時 register で高々 1 つ成功、既存 active/revoked の bytes が一切不変。

#### D2-c. 黙示的再生成禁止 / fail closed

レジストリが壊れている/読めない場合、空レジストリを黙って作り直さず fail closed
（daemon は serve 開始前 abort、bifrauthctl はエラー表示・非 zero 終了）。

### D3. 失効の表現: **tombstone（revoked_at）**、削除ではない

- revoke = device ファイルの `revoked_at` を立てて atomic 書換（削除しない）。理由:
  - 監査証跡が残る。§14.2「旧公開鍵を自動的に信用し続けない」= 同じ device_id の**黙示再登録を防ぐ**
    （register は tombstone に対しても AlreadyRegistered）。
  - 「失効情報の管理」（設計書 §6.2）を削除と区別して表現できる。
- verify: device が見つかっても revoked なら失敗。**新設 `VerifyError::RevokedDevice`**
  （観測性のため UnregisteredDevice と区別。PAM への Outcome はいずれも粗粒度 Denied のまま）。
- 代替案（不採用）: revoke=ファイル削除。→ 監査証跡が消え、同 device_id の再登録を素通しする。

#### D3-a. registry-wide lock による並行性・point-in-time snapshot（必須3 + 第2ラウンド修正）

per-uid lock（旧案）は撤回。`load_all()` が複数 UID を走査中に別 UID の write が入り、単一時点に
存在しない **mixed snapshot** を作れてしまうため。**base 直下に単一の registry-wide lock を置く**:
- lock ファイル: `<base>/.registry.lock`（予約名）。検証済み base dirfd 相対で
  `openat(O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600)`（初回作成競合に安全）→ `fstat` で
  **regular / 期待 uid,gid / mode==0600（group/world write 無し）/ nlink==1** を検証してから `flock`。
  **絶対に rename/unlink しない**（flock 対象 inode を置換しない規約）。RAII で panic/error 時も unlock。
- **register / revoke = LOCK_EX**、**load_all / list = LOCK_SH**。lock 取得後に全 path traversal /
  record 操作を行う。→ load_all は全 records 検証〜snapshot 完成まで writer を止め、point-in-time
  snapshot を保証（per-uid lock は不要に）。
- **enumeration はこの予約名 `.registry.lock` のみ明示除外**。それ以外の dotfile・temp 残骸・未知 entry・
  非 canonical 名・filename↔record 不一致は **fail closed**（黙って skip しない）。
  - temp 残骸への態度: register/revoke は全 error path で temp を `unlinkat` cleanup する。ハードクラッシュ
    （SIGKILL/電源断）で残った temp は fail closed（オペレータが調査・除去）。セキュリティ daemon として
    「未知の残骸があれば止まる」を優先する意図的トレードオフ。

revoke（read-modify-write）自体の規約:
- LOCK_EX 下で dirfd 相対 `O_NOFOLLOW` で現 record を読み、**active のみ**を revoked へ一方向遷移。
- 書換は CSPRNG temp（予約 dot-prefix）+ O_EXCL → fsync(file) → **atomic replace（通常 rename）** →
  fsync(dir)（同一 device への操作は lock で直列化済みなので通常 rename で安全）。
- revoked record への revoke は **AlreadyRevoked**（bytes 不変）。
- decode/SEC1 検証/uid-id 一致/created_at 等が不正なら書換せず fail closed。
- テスト: load_all を途中で gate し並行 register/revoke が lock 待ちになること・load 完了後の次 snapshot
  で変更が丸ごと見えること／revoke×revoke・register×revoke で tombstone 保護／lock の symlink・FIFO・
  wrong mode・hardlink 拒否／並行初回 lock 作成／panic・error でも RAII unlock。

### D4. Verifier とレジストリの分離: **Verifier は純粋なまま、registry モジュールが I/O を持つ**

- `Verifier` は現状「socket/IPC を持たないライブラリ」。この設計を維持し、**ファイル I/O は
  新モジュール `crates/bifrauthd/src/registry.rs` に隔離**する。
- registry モジュール（on-disk 操作 + D2 の安全性）:
  - `Registry::open(base_dir)` — ベースディレクトリを束縛（本番/テストで差し替え）。
  - `register(uid, device_id, sec1, label, now) -> Result<(), RegistryError>`（atomic create）。
  - `revoke(uid, device_id, now) -> Result<(), RegistryError>`（tombstone、read-modify-write）。
  - `list(uid) -> Result<Vec<DeviceRecord>, _>` / `list_all()`。
  - `load_all() -> Result<Vec<DeviceRecord>, _>`（daemon 起動時のスナップショット）。
- `Verifier` 側の追加:
  - value 型を `Vec<u8>`（SEC1）から `DeviceRecord { sec1, revoked }` 相当へ変更。
  - `revoke_device(uid, device_id) -> Result<(), RevokeError{NotRegistered, AlreadyRevoked}>`
    （稼働中 daemon への将来の revoke 反映用。0009 の主経路は下記 snapshot replace）。
  - `verify_response` を revoked-aware に（RevokedDevice を返す）。

#### D4-a. reload は transactional（必須4）: 逐次適用しない

`load_all()` 結果を live Verifier へ 1 件ずつ register/revoke すると、途中の破損で**部分適用**され、
将来 reload 時に旧 active 鍵が残る危険がある。
- registry モジュールが **全 record を独立 snapshot へ完全 decode/validate**（duplicate・path 整合・
  filename↔record 一致・schema 検証を含む）してから返す。
- `Verifier` に **`replace_devices(snapshot)`** を新設し、**単一ロック下で device registry 全体を
  atomic に差し替える**（部分適用しない。pending は別管理なので触らない）。
  - snapshot 型は**構築時に duplicate (uid, device_id) を拒否**（不可能にする）。差替 API 内部でも
    **全 key/sec1 を再検証**し、不正な caller が invalid registry を注入できないようにする。
- 起動失敗（snapshot 構築失敗）は **serve 開始前に abort**。将来 SIGHUP/inotify でも、失敗時は
  旧 snapshot で継続せず fail closed（少なくとも新規 issue 停止）。**部分 snapshot は絶対公開しない**。
- ∴ D4 の「既存 2 メソッド再利用でロード」案は撤回し、snapshot atomic replace に変更（codex 指摘）。

### D5. bifrauthctl ↔ daemon 連携: **(a) 直接ファイル書き込み**、リロードは将来課題

- bifrauthctl が root 権限でレジストリファイルを直接読み書きし、daemon は起動時に `load_all()` で
  Verifier へ取り込む。管理 IPC は追加しない（ipc-design に管理ソケットの定義はなく、
  本番 daemon 配線自体が task B 待ち）。
- **リロードのタイミング**: 起動時ロードを基本とする。稼働中 daemon への即時反映（inotify/mtime 監視や
  SIGHUP リロード）は、本番 daemon がまだ serve していない（main.rs はスタブ）ため **0009 では対象外**
  とし、registry を `load_all()` で容易に再取り込みできる形にしておく（将来タスク）。
  - 0010 の「negative cache 不使用（identity 変更を遅延させない）」方針とは、レジストリを
    信頼できる真実源として都度ロードできる構造にすることで整合させる。
- **D5 条件（codex 必須）**:
  - bifrauthctl の revoke/register 出力・docs に **「稼働中 daemon には未反映・再起動が必要」** を明示。
    revoke 成功を「即時失効」と表示しない。
  - task B / main 本番配線の **blocking dependency** として「管理変更の transactional reload
    （管理 IPC または SIGHUP 等）完成まで production serve を有効化しない」を追跡（設計書 §21/§23 の
    未決事項 or フォローアップに追記）。iPhone 紛失時 revoke が daemon 再起動まで効かない状態を
    完成版に持ち込まない。0010 の negative-cache 議論とは別物。

### D6. スコープ外にするもの（0009 では入れない提案）

- **verifier_key（Ed25519 シード）のファイル生成/ロード（impl-plan §4.7）**: デバイスレジストリと
  直交（register/revoke は verifier シードを必要としない）。E2E は既存テスト同様に固定シードで足りる。
  → **別タスク**に分離を提案。
- **`Zeroizing<[u8;32]>` シードロード API（0007 フォローアップ）**: 上記 verifier_key ロードと一緒に
  やるのが自然なので、同じく別タスクへ。
- 反対意見あればレビューで指摘してほしい。

### D7. E2E の形: **統合テスト（実 socket）を主成果物**、runnable バイナリは要相談

- 主成果物: `crates/bifrauthd/tests/e2e_socket.rs`。`serve` を実 UnixListener で起動し、Transport に
  mock-iphone アダプタを注入、クライアントが AuthRequest→ConfirmationCode→DisplayAck→Outcome を一周。
  レジストリ（一時ディレクトリ）から Verifier をロードし、(1) 登録デバイスは Success、
  (2) **revoke 後にロードし直すと Denied** を検証する。
  - 既存 `session.rs` テストの `client_flow` / `GatedTransport` が実装の下敷きになる。
  - socket bind 不可環境では既存テスト同様に skip する（`Gate socket-binding tests on bind capability`
    の方針を踏襲）。
  - **(3) pending が revoke 境界を跨ぐケース（codex 必須）**: issue 済み pending がある状態で
    revoke → snapshot atomic replace → その pending response を verify すると **RevokedDevice で
    consume** されること（active snapshot の残像で成功しない）。
- §23-10「CLI クライアントから end-to-end 認証する」の runnable auth client は **task B 後へ分離**
  （本番 Transport 未了のため）。0009 では §23-10 を完了扱いにせず、**task B 側の done criteria へ移す**
  （codex 合意）。0009 の E2E 主成果物は上記統合テスト。

## 実装ステップ（合意後）

1. registry モジュール（D1/D1-a/D2/D2-a/D2-b/D2-c/D3-a の on-disk 形式・安全性・並行性）+ 単体テスト:
   中間dir symlink・file symlink/FIFO・wrong owner/mode（可能な環境）・oversize・unexpected file・
   非canonical名・filename↔record不一致・同時registerの高々1成功&bytes不変・revoke×revoke/register×revoke
   のtombstone保護・AlreadyRevoked bytes不変・load_all の破損時 fail closed。
2. Verifier に DeviceRecord・revoke_device・RevokedDevice・`replace_devices(snapshot)`（D4-a atomic）を追加、
   verify を revoked-aware に。既存テスト更新。
3. bifrauthctl: `register --user <name> --device <hex16> --pubkey <hex SEC1> [--label ...]` /
   `revoke --user <name> --device <hex16>` / `list [--user <name>]`。username↔uid は UzersResolver で解決。
   入力は hex（SEC1 は compressed/uncompressed どちらも受理、canonical 化は pairing タスクへ）。
   出力に「稼働中 daemon には未反映・要再起動」を明示（D5 条件）。壊れた entry は list で非zero終了。
4. E2E 統合テスト（D7: 登録=Success / revoke後snapshot=Denied / pending が revoke 境界を跨ぐ=RevokedDevice）。
5. 設計書 §8.3 を CBOR へ更新 + docs/reviews に記録（D1）。§21/§23 に D5 の blocking dependency を追記。
6. lint/fmt/test を緑にしてコミット。

## 実装時に守る点（codex 第3ラウンド承認時の確認点）

1. **flock の OFD semantics**: 各 Registry 操作は独自に lock を open して flock し、同一プロセス内の
   複数 Registry/スレッド間でも相互排他になることを実テストで確認。**lock 取得前に
   security-sensitive な存在確認/列挙をしない**（列挙は lock 下でのみ）。
2. **lock 作成の durability**: 初回作成後に `fsync(file)` と `fsync(base dir)`。O_CREAT 時も
   **既存 inode を必ず fstat 検証してから flock**。
3. **temp cleanup guard**: publish 成功時のみ disarm。panic/unwind でも best-effort `unlinkat`。
   hard crash 残骸は計画どおり fail closed とし、**CLI は対象 path を示す安全な手動復旧案内**を出す
   （自動削除しない）。
4. **snapshot の所有権**: LOCK_SH で返す Vec snapshot は lock 解放後も完全所有値
   （dirfd/borrowed buffer への参照を残さない）。
5. **replace_devices と verify の境界**: Verifier mutex 単一 lock で直列化し、snapshot 交換後に
   開始した verify が**旧 device state を参照しない**こと。

## レビューしてほしい観点（要点）

- D1（CBOR 化 + 設計書 §8.3 更新の是非）、D3（tombstone + RevokedDevice）、D4（Verifier 純粋維持）、
  D5（直接ファイル方式 + リロード先送りの許容）、D6（verifier_key/Zeroize を別タスク化）、
  D7（E2E をテスト主にするか runnable も要るか）。
- セキュリティ原則: 失効鍵が確実に verify 失敗するか。fail-closed（レジストリ破損時に黙って空生成しない）。
  register の非上書き（tombstone 含む）。ファイル安全性（symlink/非通常/perm/atomic）。
