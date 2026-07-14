# bifrauthd IPC 設計（v0.3・codex 第2ラウンド承認済み）

**対象:** タスク0008（root Unix ソケット IPC: PAM ↔ verifier）。設計書 §6・§9.5・§11・§15.3、実装計画 §4.5 を具体化する。
codex 設計レビュー: v0.2 で第1ラウンドの必須修正(1〜4)を反映→第2ラウンドで**承認**。v0.3 で承認時の軽微な追補(A〜D)を反映して実装へ。

---

## 1. スコープ（0008 = A のみ）

BifrAuth のローカル IPC は 2 本（設計 §6）:
- **A. PAM モジュール ↔ verifier**（root 専用ソケット、設計 §11.1）— **本タスク0008の実装対象**。
- **B. verifier ↔ transport helper**（非特権ユーザーセッション、設計 §11.2）— **本番ソケットは別タスクへ分離**。

0008 では **`Transport` trait/port** を定義する（envelope を渡し、iPhone の署名応答または通信結果を返す）。
**Transport は deadline/cancellation を引数で受ける契約**にし、後続 B が無期限に block できないようにする（追補B）。
E2E テストは **mock-iphone アダプタ**を注入し、次を検証する:
- **DisplayAck 成功前に Transport が呼ばれない**。
- **成功は Transport の返り値ではなく `core.verify_response` だけが決める**（未検証 success を信用しない）。
- **Transport が overall deadline 内に応答を返しても、その後の verify / Outcome 送信に失敗したら安全に
  terminal 化する。認証成功を PAM へ届けられなければ「外部上の成功」にはならない**（追補B）。
  - 注: Transport I/O 中の PAM 切断を*即時*検出するには非同期監視/cancellation が要る。0008 では即時検出まで
    行わず、overall deadline での打ち切り + 上記「PAM へ届かなければ成功にしない」で安全側に倒す。

## 2. ソケットと接続

- パス `/run/bifrauthd/pam.sock`、所有者 **root:root**、モード **0600**。
- **SO_PEERCRED** で peer uid/pid/gid を取得。**認可条件は uid==0 のみ**。pid/gid は**監査/異常診断にのみ**使い、
  PID や実行ファイルパスを恒久的 authenticator にしない（race/更新/namespace 問題のため）。0600 + uid==0 の二重確認で十分。

### 2.1 socket ライフサイクル（systemd socket activation 一本／自己 bind なし）
- **socket の owner は systemd socket activation のみ**とする（追補C: 自己 bind 分岐を実装せず攻撃面を減らす）:
  `bifrauthd.socket` に `ListenStream=/run/bifrauthd/pam.sock` / `SocketMode=0600` / `SocketUser=root` /
  `SocketGroup=root`。**unit ファイル自体もテスト/レビュー対象**にする。
- daemon は受領 FD を厳密に検証する（すべて満たさなければ **fail closed**）:
  - **受領 FD 数がちょうど 1**（`LISTEN_FDS==1`、`sd_listen_fds` 相当）。
  - `getsockname` の path が **期待パス `/run/bifrauthd/pam.sock`**。
  - **`SO_ACCEPTCONN==1`**（listen 済み）、**`SO_DOMAIN==AF_UNIX`**、**`SO_TYPE==SOCK_STREAM`**。
  - 検証後に受領 FD へ **`FD_CLOEXEC`** を設定（子プロセスへ漏らさず activation 環境の再解釈も防ぐ。`sd_listen_fds`相当）。
- accept 後の各接続で SO_PEERCRED を確認（§2）。

## 3. フレーミング・エンコード・制限

- 各メッセージ = **4 バイト BE 長プレフィックス + 本文**。本文上限 **8 KiB**。**zero-length 拒否**。
- 本文は **proto の決定的 CBOR（`bifrauth-proto` の bounded scanner）を再利用**し、**IPC 専用スキーマ**を定義する。
  受理表現を1つに保つ（test/fuzz 有利）ため **canonical 検査を維持**（必須/未知キー拒否/重複キー拒否/各 text・bstr 長/
  本文 8KiB）。「厳密でなくてよい」という二重方針は採らない。
- **個別 byte 上限と text policy**（追補D）: `username`/`pam_service`/`pam_tty`/`pam_rhost` は各々の byte 上限を定め、
  proto と同じ UTF-8/text policy（制御文字・NFC・未割当拒否）を適用する。`OutcomeCode` は**未知値を拒否**する。
  これらを golden/negative ベクタに含める。
- **タイムアウトは CLOCK_BOOTTIME の絶対 overall deadline 30 秒**（設計 §16 の総タイムアウト）+ 各段階上限
  （例: Face ID 待機 20 秒）。各 read/write は **残り overall deadline を超えない**。suspend 後も即 timeout。
  partial な長さプレフィックス/本文・EOF も安全に終了する。deadline 計算の overflow は**期限切れ扱い（fail closed）**
  にし、far-future の never-expire を作らない。
- 1 接続 = 1 認証フロー。**同一接続・同一 request_id のみ受理**。2 個目の AuthRequest や重複 Ack は
  **protocol error として接続を閉じる**。

## 4. メッセージ型と状態機械（A）

状態遷移（正常系＋異常系 terminal を全列挙。追補A）:

```
Issued/AwaitingDisplayAck --DisplayAck(true)-->  Dispatched
Issued/AwaitingDisplayAck --DisplayAck(false)/失敗経路--> Finished(cancel)
Dispatched                --verify success-->    Finished(consume=Success)
Dispatched                --verify failure-->    Finished(consume=Denied)
Dispatched                --Transport error/timeout/送信失敗--> Finished(cancel)
```

- **terminal 遷移は高々 1 回の cancel/consume**。cleanup guard は**冪等**にし（例: `Option<Pending>` を
  `take()` する / core 側 `remove` の二重呼びを無害化）、どの return 経路から入っても二重 consume しない。

```
PAM -> verifier:  AuthRequest {
    username, pam_service, pam_tty?, pam_rhost?
}
// peer=root ゆえ信頼するが、下記は AuthRequest 入力にせず daemon 設定/ポリシーから供給/検査する:
//  - linux_device_id / linux_device_name: daemon 設定から
//  - ttl_seconds: daemon ポリシー（1..=30）から
//  - pam_service: daemon 側の専用サービス allowlist で検査
//  - username <-> target_uid: daemon 側で解決・検査（confused-deputy / 誤設定防止）

verifier -> PAM:  ConfirmationCode { request_id, confirmation_code }
// core.issue_challenge 済み。envelope はまだ Transport(B) へ出さない。
// ※ この送信に失敗した場合も pending を cancel する。

PAM -> verifier:  DisplayAck { request_id, conversation_succeeded: bool }
// フィールド名は「実描画保証ではない」ため displayed から conversation_succeeded へ改名（設計 §9.3）。

// conversation_succeeded==true のときだけ Transport.dispatch(envelope) を呼ぶ（Dispatched）。
// 応答が戻ったら core.verify_response で atomic consume/verify（Finished）。

verifier -> PAM:  Outcome { request_id, result: OutcomeCode, }
// OutcomeCode は bounded enum: Success | Denied | Unavailable | Timeout | ProtocolError | InternalError
// PAM 戻り値への写像は固定（Success->PAM_SUCCESS, Denied->PAM_AUTH_ERR, Unavailable/Timeout->PAM_AUTHINFO_UNAVAIL,
//  ProtocolError/InternalError->PAM_SYSTEM_ERR）。自由文 reason は持たない。
```

### 4.1 cancel/consume の網羅（全失敗経路で pending を破棄）
core に **`cancel_pending(request_id)`** を追加する。次の全経路で pending を cancel/consume する:
- `conversation_succeeded==false`、request_id 不一致、順序違反（重複 AuthRequest/Ack）、
- EOF/接続断、decode error、各段階 timeout、Transport error、ConfirmationCode 送信失敗。
- **遅延 Ack / 遅延 response は `UnknownOrConsumedRequest`** になる（既に cancel 済み）。

## 4.2 並行モデル（コードレビュー第1ラウンド反映）
- accept は**有界ワーカープール**（既定8スレッド）で処理する。各ワーカーは1接続ずつ担当し、遅い1フロー
  （Face ID待ち/transport/NSS）は自分のワーカーだけを塞ぐ。プール数が同時フロー数の上限で、超過接続は
  kernel の accept backlog で待ち（埋まれば fail closed）。**無制限 thread spawn はしない**（DoS防止）。
  共有物（Verifier/clock/transport/policy/resolver/authorize）は `Arc` で共有。これにより §5 のロック解放と
  §15.3 の複数 pending / per-uid 上限が実運用で意味を持つ。
- **CleanupGuard は RAII**（`Drop`）で、通常 return だけでなく **panic/unwind でも** pending を cancel する。
  `Drop` は poison lock を回復し（`into_inner`）、`cancel_pending` は純粋な map 削除なので**再 panic せず abort
  しない**。ワーカー境界で `catch_unwind` し、1接続の panic がワーカー/デーモンを落とさない。
- verifier mutex は poison を回復して使う（他接続の panic で全体が wedge しない）。

## 5. 排他制御（第1ラウンド指摘1）

verifier core の**短い状態遷移（issue / cancel / verify の consume）だけ**を排他化する。
**PAM conversation 待ち・Transport(iPhone) I/O・socket read/write 中は lock を保持しない**（1 フローが最大 30 秒
全認証を止めるのを防ぎ、§15.3 の複数 pending 設計を活かす）。
- 構造: I/O 前に lock 解放 → I/O → 戻った response を再 lock して atomic consume/verify。
- actor 方式なら、各フローの I/O は actor 外で行い、**状態コマンド（issue/cancel/verify）だけ**を actor が直列処理する。

## 6. セキュリティ境界（設計 §4.5・§7）

- root 専用 socket + peer uid==0 で非特権プロセスは接続不可。root は信頼境界（設計 §4.2）。
- 未検証 `success` を peer から受け取らない。最終判定は core の verify_response のみ。
- 「同一 UID 偽 helper は DoS/閲覧はできても、未検証 success 捏造・challenge 改変では成功できない」は B 側の性質
  （署名検証で成立）。**B のタスクの完了条件でテスト**する。
- 不正入力（過大長・truncated・不正 CBOR・型不一致・zero-length）で daemon がクラッシュしない、をテスト。

## 7. 完了条件（0008）
- A の issue→confirmation→display-ack→dispatch→outcome が mock-iphone アダプタ経由で E2E 成功。
- DisplayAck 成功前に Transport が呼ばれないこと、成功判定が core.verify_response のみに依ることを検証。
- Transport が deadline/cancellation を引数で受け、応答後の verify/Outcome 送信失敗を安全に terminal 化し、
  PAM へ成功が届かなければ外部成功にしないことを検証（追補B）。
- 全失敗経路（Ack=false/不一致/順序違反/EOF/decode/各timeout/transport error/送信失敗）で pending が cancel され、
  遅延メッセージが UnknownOrConsumed になること。cleanup guard の冪等性（二重 consume なし）を検証（追補A）。
- IPC schema の golden/negative: 各 text フィールドの byte 上限・UTF-8/NFC/未割当拒否・OutcomeCode 未知値拒否・
  過大長/truncated/不正CBOR/zero-length で daemon がクラッシュしないこと（追補D）。
- systemd 受領 FD 検証（FD数=1 / 期待path / SO_ACCEPTCONN / AF_UNIX / SOCK_STREAM）と unit ファイル（追補C）。
- overall deadline とロック非保持 I/O の構造。cargo test / clippy -D warnings 緑。
