// Package main は idproxy DynamoDB Store と利用側独自データ（同テーブル + 独自 GSI）の
// 共存サンプルです。
//
// シナリオ:
//
//   - 単一の DynamoDB テーブルに idproxy のセッション・トークン・refresh token・client と、
//     利用側アプリケーションの業務データ（例: tenant 設定、外部 OAuth token）を同居させる。
//   - idproxy は PK が `session:`, `authcode:`, `accesstoken:`, `client:`, `refreshtoken:`,
//     `familyrevoked:` で始まるアイテムを使う（lowercase、属性名: `pk`, `data`, `ttl`, `used`）。
//   - 利用側は `_app:` 等の独立した PK プレフィクスを採用し名前空間衝突を回避する。
//   - 利用側だけが必要とする GSI（例: 利用側の `_app:user:<email>` を逆引きするインデックス）を
//     後付けで追加できる。
//
// 環境変数:
//
//	AWS_REGION         - 例: us-east-1（必須）
//	DYNAMODB_TABLE     - テーブル名（必須）
//	EXTERNAL_URL       - 外部公開 URL（必須）
//	COOKIE_SECRET      - Cookie 暗号化キー、hex エンコード 32 バイト以上（必須）
//	OIDC_ISSUER        - OIDC Issuer URL（必須）
//	OIDC_CLIENT_ID     - OAuth Client ID（必須）
//	OIDC_CLIENT_SECRET - OAuth Client Secret（オプション）
//	PORT               - リッスンポート（デフォルト: 8080）
//
// 起動前に table.json を参考にテーブルを作成しておくこと:
//
//	aws dynamodb create-table --cli-input-json file://table.json
package main

import (
	"context"
	"encoding/hex"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	idproxy "github.com/youyo/idproxy"
	idpstore "github.com/youyo/idproxy/store"
)

func main() {
	region := mustEnv("AWS_REGION")
	tableName := mustEnv("DYNAMODB_TABLE")
	externalURL := mustEnv("EXTERNAL_URL")
	cookieSecretHex := mustEnv("COOKIE_SECRET")
	oidcIssuer := mustEnv("OIDC_ISSUER")
	oidcClientID := mustEnv("OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	cookieSecret, err := hex.DecodeString(cookieSecretHex)
	if err != nil {
		log.Fatalf("COOKIE_SECRET: invalid hex: %v", err)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	// **重要**：同じ DynamoDB client を idproxy Store と利用側アプリで共有する。
	// idproxy.Store は Close() しても client を閉じないため、利用側の業務クエリにも安全に使い回せる。
	ddb := dynamodb.NewFromConfig(awsCfg)

	idproxyStore := idpstore.NewDynamoDBStoreWithClient(ddb, tableName)

	cfg := idproxy.Config{
		Providers: []idproxy.OIDCProvider{
			{
				Issuer:       oidcIssuer,
				ClientID:     oidcClientID,
				ClientSecret: oidcClientSecret,
			},
		},
		ExternalURL:  externalURL,
		CookieSecret: cookieSecret,
		Store:        idproxyStore,
	}

	auth, err := idproxy.New(context.Background(), cfg)
	if err != nil {
		log.Fatalf("idproxy.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, "no user", http.StatusInternalServerError)
			return
		}
		// 同じ DynamoDB client を使った業務クエリ例：
		// utility 用に _app: プレフィクスを採用（idproxy の `session:` 等と衝突しない名前空間）
		_, _ = ddb.GetItem(r.Context(), &dynamodb.GetItemInput{
			TableName: aws.String(tableName),
			Key:       appPK(user.Email),
		})
		_, _ = w.Write([]byte("hello, " + user.Email))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s table=%s region=%s", port, tableName, region)
	if err := http.ListenAndServe(":"+port, auth.Wrap(mux)); err != nil { //nolint:gosec
		log.Fatal(err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

// appPK は利用側独自データ用の PK を構築する。idproxy のキー空間（`session:`, `authcode:`,
// `accesstoken:`, `client:`, `refreshtoken:`, `familyrevoked:`）と衝突しないよう
// `_app:` プレフィクスを採用している。
func appPK(email string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"pk": &ddbtypes.AttributeValueMemberS{Value: "_app:user:" + email},
	}
}
