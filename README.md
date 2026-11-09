# nuage-honeytrap

Nuage Cluster 向けのマルチプロトコル侵入検知ハニーポットである。
クラスタ内（および外部公開時）に足がかりを得た攻撃者が真っ先に探索・横展開を試みる SSH、HTTP、PostgreSQL の各プロトコルを単一の軽量バイナリで待ち受け、攻撃の試行情報を構造化 JSON ログとして記録する。

## 特徴と設計原則

1. **ゼロ侵害リスク（安全性の担保）**:
   - 攻撃者に対して本物のシェルやデータベース接続、OS リソースへのアクセスを一切許可しない。
   - プロトコルの初期ハンドシェイクと認証試行のみをエミュレートし、認証情報を取得した上で確実に拒否・切断する。
2. **完全非特権コンテナ**:
   - コンテナ内では非特権ポート（2222, 8080, 5432）でリッスンし、Kubernetes Service にて標準ポート（22, 80, 5432）へルーティングする。
   - Pod Security Admission (PSA) の `restricted` レベルに準拠（非 root 実行、capability 制限、ReadOnlyRootFilesystem）。
   - コンテナイメージは `scratch` ベースであり、攻撃者が利用可能なシェルやツールが存在しない。
3. **構造化 JSON ログ**:
   - 標準出力に 1 行 1 JSON 形式で攻撃イベントを出力。VictoriaLogs などのログ収集基盤で容易にパース・可視化できる。

## 対応プロトコルと擬態仕様

### 1. SSH トラップ (標準 Port 22 / コンテナ Port 2222)
- **バナー**: `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2`
- **擬態対象**: 社内踏み台サーバー（bastion）
- **検知情報**:
  - 接続元 IP・ポート
  - クライアント SSH バージョン文字列
  - パスワード認証試行（ユーザー名、平文パスワード）
  - 公開鍵認証試行（ユーザー名、鍵タイプ、公開鍵フィンガープリント）
- **動作**: 全ての認証試行を記録した上で拒否（Permission denied）を返し、セッション開始を遮断する。

### 2. HTTP トラップ (標準 Port 80 / コンテナ Port 8080)
- **偽装ヘッダー**: `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: PHP/7.4.3`
- **擬態対象**: 社内ステージング管理ポータル（Nuage Internal Portal v0.8.2-beta）
- **エンドポイント**:
  - `/`: 社内ステージング管理画面風 HTML を返却。HTML コメントにデフォルト認証情報のヒントを配置して攻撃者の入力を誘引。
  - `/robots.txt`: `Disallow: /.env`, `Disallow: /admin/`, `Disallow: /backup.sql` などのトラップパスを記載。
  - `/healthz`: Kubernetes ヘルスチェック用エンドポイント（攻撃ログは出力しない）。
  - その他（`/.env`, `/admin/...` 等）: Apache 風の 404 Not Found を返却。
- **検知情報**: メソッド、URL パス、Query パラメータ、User-Agent、リクエストヘッダー、POST 本文（最大 4KB）。

### 3. PostgreSQL トラップ (標準 Port 5432 / コンテナ Port 5432)
- **擬態対象**: 社内ステージングデータベース
- **ハンドシェイク**:
  - SSLRequest / GSSENCRequest を受信した場合は `N`（非サポート）を返却し、平文での StartupMessage 送信へ誘導。
  - StartupMessage から要求ユーザー名、データベース名、クライアントオプションをパース。
- **動作**: 接続情報をログ記録後、標準の PostgreSQL 認証エラーパケット（`FATAL: password authentication failed for user "xxx"`、SQLSTATE: 28P01）を返して安全に切断する。

## ログフォーマット

標準出力に 1 行 1 JSON で出力される:

```json
{
  "timestamp": "2026-11-10T02:00:00Z",
  "event": "honeypot_attack",
  "protocol": "ssh",
  "src_ip": "10.244.0.123",
  "dst_port": 2222,
  "service": "bastion-dev",
  "details": {
    "auth_method": "password",
    "client_version": "SSH-2.0-libssh_0.9.0",
    "password": "secret_password",
    "remote_addr": "10.244.0.123:45678",
    "username": "root"
  }
}
```

## アーキテクチャ

```
[攻撃者 / スキャナ]
       │
       ▼
[Kubernetes Service: nuage-honeytrap]
  ├─ 22:TCP   ──────────►  2222:TCP (SSH Trap)
  ├─ 80:TCP   ──────────►  8080:TCP (HTTP Trap)
  └─ 5432:TCP ──────────►  5432:TCP (PostgreSQL Trap)
                                │
                                ▼
                   [Pod: nuage-honeytrap]
                   (Scratch, Non-Root UID:10001)
                                │
                                ▼ stdout (JSON)
                    [VictoriaLogs / Vector]
```

## 開発と実行

### 必須要件
- Go 1.22 以上（推奨: Go 1.26）
- Docker または Podman
- kubectl / kustomize

### ローカルでのビルドとテスト
```bash
# テストの実行
go test -v -race ./...

# バイナリのビルド
go build -o bin/honeytrap ./cmd/honeytrap

# ローカルでの起動
./bin/honeytrap
```

### 環境変数設定
| 環境変数 | 既定値 | 説明 |
| :--- | :--- | :--- |
| `HONEYTRAP_SSH_PORT` | `2222` | SSH トラップの待受ポート |
| `HONEYTRAP_HTTP_PORT` | `8080` | HTTP トラップの待受ポート |
| `HONEYTRAP_POSTGRES_PORT` | `5432` | PostgreSQL トラップの待受ポート |
| `HONEYTRAP_SSH_SERVICE` | `bastion-dev` | SSH トラップのログ用サービス名 |
| `HONEYTRAP_HTTP_SERVICE` | `portal-staging` | HTTP トラップのログ用サービス名 |
| `HONEYTRAP_POSTGRES_SERVICE` | `postgres-staging` | PostgreSQL トラップのログ用サービス名 |

### Kubernetes マニフェストの検証
```bash
kubectl kustomize k8s/overlays/prod
```
