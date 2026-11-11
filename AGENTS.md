# AGENTS.md

このファイルは、AI Agent が `nuage-honeytrap` リポジトリで開発・保守を行う際の固有ルールとコマンドを定義する。

## 1. リポジトリ概要

`nuage-honeytrap` は、Nuage Cluster 向けのマルチプロトコル侵入検知ハニーポットである。
攻撃者の探索・横展開の初期段階（SSH, HTTP, PostgreSQL）を検知し、構造化 JSON ログを標準出力経由で VictoriaLogs に集約する。

## 2. 開発コマンド

### テスト
```bash
# 全ユニットテストの実行（race detector 有効）
go test -v -race ./...

# キャッシュを無視して実行
go test -count=1 ./...
```

### ビルド
```bash
# バイナリのビルド
CGO_ENABLED=0 go build -o bin/honeytrap ./cmd/honeytrap
```

### 静的解析・フォーマット
```bash
# フォーマット確認
test -z "$(gofmt -s -l .)"

# go vet
go vet ./...
```

### Kubernetes マニフェストの検証
```bash
kubectl kustomize k8s/overlays/prod
```

## 3. ディレクトリ構成

- `cmd/honeytrap`: エントリポイント（シグナルハンドリング・Graceful Shutdown）
- `cmd/registrar`: 囮ドメインを urlscan.io に登録する CronJob のエントリポイント（`Dockerfile.registrar` で別イメージ）
- `internal/config`: 環境変数読み込みと設定管理
- `internal/logger`: 1行1JSON形式の構造化ログ出力（VictoriaLogs 互換）
- `internal/registrar`: 登録先ごとの Submitter（urlscan.io）と実行ループ
- `internal/honeypot`: プロトコル統合マネージャー
  - `ssh/`: SSH トラップサーバー（OpenSSH バナー偽装、クレデンシャル収集、常時拒否）
  - `http/`: HTTP トラップサーバー（Apache/PHP 偽装、ステージングポータル HTML、robots.txt）
  - `postgres/`: PostgreSQL トラップサーバー（SSLRequest ハンドシェイク、StartupMessage パース、認証エラー切断）
- `k8s/`: Kubernetes マニフェスト
  - `base/`: Deployment、Service、Kustomization
  - `overlays/prod/`: 本番 overlay（Namespace: `nuage-honeytrap`）
- `.github/workflows/`: CI およびコンテナビルドワークフロー

## 4. 設計原則と制約事項

1. **ゼロ侵害リスクの維持**:
   - 攻撃者に実際のシェル、ファイルシステム、データベースセッションを開放してはならない。
   - すべてのプロトコルハンドラは情報を抜き取った後、必ず拒否またはエラー切断で終結させる。
2. **完全非特権コンテナ**:
   - Pod Security Admission (PSA) `restricted` 準拠を維持する。
   - コンテナ内ポートは非特権（2222, 8080, 5432）で待受し、Kubernetes Service で標準ポート（22, 80, 5432）にルーティングする。
   - `scratch` イメージをベースとし、コンテナ内に余分なツールやシェルを配置しない。
3. **機密情報のコミット禁止**:
   - API キー、パスワード、秘密鍵などの機密情報をコードやコミットに含めない。
4. **GitOps 原則**:
   - マージおよびデプロイは GitOps 経路（Argo CD）で行われるため、本番環境への直接変更を行わない。
