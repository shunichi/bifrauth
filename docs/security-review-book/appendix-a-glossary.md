# 付録 A 用語集

本書で使う用語の正式な表記（canonical な日本語表記）と、対応する英語を定める。

- **この用語集は表記の正（source of truth）である。** 各章は同じ概念に別表記を使わない。
- 日本語で日常的に使わない専門用語には、対応する英語を併記する。英語文献を読むときの手がかりになる。
- PAM や polkit、nonce のように英語（略語・固有名）のまま使う語は、無理に日本語訳を作らない。
- 各章では、専門用語が初めて出てくるときに `日本語の用語（English）` の形で併記する。
- 新しい専門用語を章へ導入したら、この用語集にも追記する。

英語がそのまま見出しになる語（PAM、polkit など）は、日本語見出しの代わりに英語を見出しにする。

---

## プロジェクト名

- **bifrauth（BifrAuth）**：本書が対象とするプロジェクトの名前。発音は **「BIF-rawth」**（ビフロース）。北欧神話で異なる世界をつなぐ橋 **Bifröst**（ビフレスト）と **auth**（authentication、認証）を組み合わせた造語で、Linux の認証要求を信頼できる暗号デバイス（iPhone）へ橋渡しする役割を表す。リポジトリ名やパッケージ名は小文字（`bifrauth`）、文書上のブランディングはキャメルケース（BifrAuth）を用いる。

---

## OS とプロセスの基礎

- **UID（user identifier）**：カーネルが権限判断に使うユーザーの数値識別子。
- **root**：UID `0` を持つ管理者。通常のパーミッション判定をほぼ素通りする。
- **プロセス（process）**：実行中のプログラム。権限は（実効）UID を単位に判断される。
- **実効 UID（effective UID）**：カーネルがアクセス可否の判断に使う UID。本書では簡略化して単に「プロセスの UID」と呼ぶことがある。
- **資格情報（credentials）**：プロセスの UID・GID など、カーネルが権限判断に使う素性の情報。`SO_PEERCRED` が返すのもこれ。
- **ファイルディスクリプタ（file descriptor）**：プロセスが開いたファイルやソケットを参照する小さな整数。
- **パーミッション（permission）／mode**：ファイルの owner／group／other に対する read／write／execute の許可設定。
- **DAC（任意アクセス制御、discretionary access control）**：所有者と mode でアクセスを決める方式。
- **デーモン（daemon）**：常駐して要求を待ち続けるプロセス。
- **サービス（service）**：デーモンが提供する機能の単位。PAM ではアプリが名乗る名前でもある。
- **systemd**：Linux のサービス（デーモン）を管理する仕組み。
- **ソケットアクティベーション（socket activation）**：systemd が待ち受けソケットを先に用意し、接続が来たらサービス本体を起動して待ち受けソケットを渡す仕組み。
- **NSS（Name Service Switch）**：ユーザー名から UID を引くなど、名前解決の共通機構。

## 信頼と脅威

- **TCB（信頼される計算基盤、trusted computing base）**：侵害されていない前提で信頼する側。bifrauth では root 側。
- **信頼境界（trust boundary）**：信頼する側と信頼しない側を分ける線。
- **脅威モデル（threat model）**：何を、誰から、どこまで守るかを言葉にしたもの。
- **資産（asset）**：守る対象。
- **敵（adversary）**：想定する攻撃者と、その能力。
- **守るべき性質（security goal／invariant）**：資産について成り立ってほしい性質。
- **前提（assumption）**：成り立つと仮定して設計する条件。
- **非ゴール（non-goal）**：そもそも作らないと決めた機能。
- **範囲外の脅威（out-of-scope threat）**：この設計では守らないと宣言した攻撃。
- **残余リスク（residual risk）**：範囲内の対策をしてもなお残る確率や影響。

## 認証・認可

- **認証（authentication）**：あなたは誰か、を確かめること。
- **認可（authorization）**：ある操作を許すか、を決めること。
- **なりすまし（impersonation）**：攻撃者が正規のユーザーとして扱われてしまう結果。
- **リプレイ（replay）**：過去の正しいやり取りをそのまま再送する手法。
- **新しさ（freshness）**：その要求が今回のために新しく作られたか、という性質。
- **文脈への束縛（context binding／audience binding）**：要求を、相手・用途・端末・期限などの文脈へ結び付けること。
- **authenticity（正しい相手が作った裏付け）**：署名などで、要求が本物の発行者のものだと確かめられる性質。

## PAM

- **PAM（Pluggable Authentication Modules）**：Linux の着脱可能な認証の仕組み。
- **アプリケーション（application）**：PAM に本人確認を依頼する側（`login`／`sudo`／`polkit-agent-helper-1` など）。
- **モジュール（module）**：PAM に差し込む、実際に確かめる処理を担う `.so`。
- **conversation**：モジュールがユーザーと言葉をやり取りするための通り道。アプリケーションが提供する。
- **管理グループ（management group）**：auth／account／password／session の四区分。
- **コントロールフラグ（control flag）**：`required`／`requisite`／`sufficient`／`optional` など、モジュールの結果を全体へどう反映するかの指定。
- **スタック（stack）**：ある管理グループに並べたモジュールの列。
- **フォールバック（fallback）**：ある認証が使えないとき、下段の別の認証（パスワードなど）へ落ちること。
- **PAM_SERVICE**：モジュールが受け取るサービス名。アプリ起点の値。

## polkit

- **polkit**：操作ごとの認可をシステム全体で調停する仕組み。
- **action／action ID**：polkit が扱う操作と、その識別子。
- **認証エージェント（authentication agent）**：polkit が本人確認を促すためにユーザーへ尋ねる、ユーザーセッション内の部品。
- **polkit-agent-helper-1**：認証エージェントから呼ばれ、PAM を起動する特権ヘルパー（対象環境での実装経路）。
- **一時的な認可（temporary authorization）**：`auth_self_keep`／`auth_admin_keep` などで、一定時間その action の再認証を省く仕組み。

## 暗号

- **署名（signature）**：秘密鍵で作り、公開鍵で検証する、出所と完全性を示す仕組み。
- **鍵ペア（key pair）**：対になった秘密鍵と公開鍵。
- **秘密鍵（private key）**：持ち主だけが握る鍵。署名の作成に使う。
- **公開鍵（public key）**：誰に見せてもよい鍵。署名の検証に使う。
- **ハッシュ（hash）**：任意長のデータを固定長の値へ変換する一方向の関数。本書では SHA-256。
- **原像計算困難性（preimage resistance）**：ハッシュ値から入力を見つけるのが困難な性質。
- **第二原像計算困難性（second-preimage resistance）**：ある入力と同じハッシュ値になる別の入力を見つけるのが困難な性質。
- **衝突困難性（collision resistance）**：同じハッシュ値になる二つの入力の組を見つけるのが困難な性質。
- **なだれ効果（avalanche）**：入力のわずかな変化で出力が大きく変わるよう設計された性質。
- **nonce（number used once）**：一度だけ使う、推測できない乱数。要求ごとに作り直す。
- **チャレンジレスポンス（challenge-response）**：毎回新しい問いかけへ、鍵で答えを返させる方式。
- **Ed25519**：本書で verifier が challenge に署名するのに使う楕円曲線署名方式。
- **ECDSA P-256**：本書で iPhone が応答に署名するのに使う楕円曲線署名方式（曲線 P-256、ハッシュ SHA-256）。
- **Secure Enclave**：iPhone のハードウェア内で鍵を守る独立領域。鍵は原則取り出せない。
- **Face ID**：本書では、Secure Enclave の鍵の使用を許可するゲートとして使う（認証の結果としては使わない）。

## トランスポートとペアリング

- **MITM（中間者攻撃、man-in-the-middle attack）**：通信の間に割り込み、盗聴・改ざんする攻撃。
- **SAS（短い認証文字列、short authenticated string）**：ペアリング時に双方で見比べる短い比較コード。
- **mTLS（相互 TLS 認証、mutual TLS authentication）**：通信の両端が互いに証明書で認証する TLS。
- **Noise（Noise Protocol Framework）**：暗号化通信路を構成する枠組みの一つ。bifrauth では TLS 1.3 mTLS と並ぶ未決の候補。

## データ表現

- **正規化（canonicalization）**：エンコーディングで、実装が違っても同じ値が同じバイト列になるよう表現を一意に定めること（決定論的 CBOR など）。次の Unicode 正規化とは別の話。
- **Unicode 正規化（Unicode normalization）**：Unicode の文字列について、正準等価な複数の表現を一つに揃えること（NFC など）。見た目が似ただけの別文字は揃えない。
- **バイト列の一致（byte-exact match）**：意味の一致ではなく、バイト単位で完全に同じであること。署名の前提。
- **canonical challenge**：正規化済みの問いかけのバイト列。署名の対象。
- **CBOR（Concise Binary Object Representation）**：JSON に似た構造をバイナリで表す形式。
- **決定論的 CBOR（deterministic CBOR）**：同じ値が必ず同じバイト列になるよう規則を絞った CBOR。
- **allowlist（許可リスト）**：使ってよいもの（型など）だけを列挙し、それ以外を拒否する方式。
- **NFC（Unicode 正規化形式 C、Normalization Form C）**：正準等価な文字表現（合成済みの「é」と「e＋結合アクセント」など）を一意のバイト列へ揃える Unicode 正規化形式。見た目が似ただけの別文字（homoglyph）は揃えない。
- **message_type**：メッセージの種別を表す識別子。スキーマを変えるときは新しい値にする（例 `bifrauth.challenge.v2`）。
- **downgrade 攻撃（downgrade attack）**：より弱い版・方式へ引き下げさせる攻撃。
- **fail-closed（フェイルクローズ）**：判断に迷う・異常が起きたとき、安全側に倒して拒否・停止する設計。反対は fail-open。

## ローカル IPC とファイル

- **IPC（プロセス間通信、inter-process communication）**：別々のプロセスが情報をやり取りすること。
- **Unix domain socket（Unix ドメインソケット）**：同じマシン内のプロセス同士をつなぐ通信路。
- **SO_PEERCRED**：接続してきた相手の UID／PID／GID を OS へ問い合わせる、Unix ドメインソケットの機能（Linux 固有）。
- **TOCTOU（time-of-check to time-of-use）**：確認と使用の間の隙を突くすり替え攻撃。
- **symlink（シンボリックリンク、symbolic link）**：別の場所を指す名前。すり替えに悪用されうる。
- **アトミックな公開（atomic publish）**：一時ファイルへ書いてから rename で不可分に差し替える書き方。
- **crash consistency**：途中でマシンが落ちても壊れた状態が残らない性質。
- **耐久性（durability）**：書いた内容が電源断後も失われない性質。`fsync` で確実にする。
- **tombstone（墓標）**：レコードを削除せず「失効した」印を残す方式。
- **ロールバック（rollback）**：状態を過去のものへ巻き戻すこと。

## bifrauth のコンポーネント

- **verifier**：認証の可否を最終判断する root 所有のコンポーネント（`bifrauthd`）。
- **transport helper（`bifrauth-transport`）**：iPhone と通信する非特権のヘルパー。認証の可否は決めない。
- **request ID**：要求を識別する、独立に生成する乱数。使い切りにする。
- **number matching**：PAM 側に表示した確認コードを iPhone 側で入力・照合させ、反射的な承認を抑える仕組み。
- **確認コード（confirmation code）**：number matching で使う 6 桁の数字。要求ごとに生成する。
- **デバイスレジストリ（device registry）**：登録済み iPhone 公開鍵などを保存する、root だけが書けるファイル群。
