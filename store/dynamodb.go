package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/youyo/idproxy"
)

// errDynamoDBStoreClosed は Close 済みの DynamoDBStore への操作時に返されるエラー。
var errDynamoDBStoreClosed = errors.New("dynamodb store: store is closed")

// DynamoDBClient は DynamoDB クライアントが満たすべき最小インターフェース。
// テスト時にモック注入するために定義する。
type DynamoDBClient interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// コンパイル時にインターフェース実装を保証する。
var _ idproxy.Store = (*DynamoDBStore)(nil)

// DynamoDBStore は DynamoDB ベースの idproxy.Store 実装。
//
// 用途:
//   - Lambda マルチコンテナ環境でのコンテナ間状態共有
//   - コールドスタート跨ぎでの状態永続化
//
// テーブル設計:
//   - PK: "session:<id>", "authcode:<code>", "accesstoken:<jti>", "client:<clientID>"
//   - data: JSON シリアライズしたエンティティ (String)
//   - ttl: Unix epoch 秒 (Number)。DynamoDB TTL 属性。Client は TTL なし。
type DynamoDBStore struct {
	client    DynamoDBClient
	tableName string
	now       func() time.Time // テスト時に時刻注入。本番は time.Now
	closeOnce sync.Once
	closed    atomic.Bool // Close 後の操作ブロック用
}

// NewDynamoDBStore は新しい DynamoDBStore を返す。
// AWS SDK v2 のデフォルト設定から DynamoDB クライアントを生成する。
// region には us-east-1 等のリージョン文字列を指定する。
func NewDynamoDBStore(tableName, region string) (*DynamoDBStore, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("dynamodb store: load config: %w", err)
	}
	client := dynamodb.NewFromConfig(cfg)
	return &DynamoDBStore{
		client:    client,
		tableName: tableName,
		now:       time.Now,
	}, nil
}

// NewDynamoDBStoreWithClient はテスト用コンストラクタで、DynamoDBClient の任意実装を注入できる。
func NewDynamoDBStoreWithClient(client DynamoDBClient, tableName string) *DynamoDBStore {
	return &DynamoDBStore{
		client:    client,
		tableName: tableName,
		now:       time.Now,
	}
}

// --- PK 生成ヘルパー ---

func sessionPK(id string) string      { return "session:" + id }
func authCodePK(code string) string   { return "authcode:" + code }
func accessTokenPK(jti string) string { return "accesstoken:" + jti }
func clientPK(clientID string) string { return "client:" + clientID }

// --- 属性生成ヘルパー ---

// stringAttr は DynamoDB の String 型属性を生成する。
func stringAttr(s string) *types.AttributeValueMemberS {
	return &types.AttributeValueMemberS{Value: s}
}

// numberAttr は DynamoDB の Number 型属性を生成する。
func numberAttr(n int64) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

// --- 汎用 CRUD ヘルパー ---

// putItemJSON は任意の値を JSON シリアライズして DynamoDB に PutItem する。
// 常に `ttl` 属性を `now + ttl` として付与する。ttl == 0 の場合は即時期限切れのアイテムとして記録される。
func (s *DynamoDBStore) putItemJSON(ctx context.Context, pk string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	item := map[string]types.AttributeValue{
		"pk":   stringAttr(pk),
		"data": stringAttr(string(b)),
	}

	// TTL 属性: セッション/認可コード/アクセストークン用。
	// time.Duration(0) は「即時期限切れ」として ttl=now に設定する。
	expireAt := s.now().UTC().Add(ttl)
	item["ttl"] = numberAttr(expireAt.Unix())

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.tableName,
		Item:      item,
	})
	return err
}

// putItemJSONNoTTL は TTL なしで JSON シリアライズして DynamoDB に PutItem する (Client 用)。
func (s *DynamoDBStore) putItemJSONNoTTL(ctx context.Context, pk string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	item := map[string]types.AttributeValue{
		"pk":   stringAttr(pk),
		"data": stringAttr(string(b)),
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.tableName,
		Item:      item,
	})
	return err
}

// getItemJSON は DynamoDB から GetItem し、JSON デシリアライズして返す。
// アイテムが存在しない場合は (nil, nil) を返す。
// TTL 検証を行い、期限切れの場合も (nil, nil) を返す (DynamoDB TTL ラグ対策)。
// hasTTL が false の場合は TTL チェックをスキップする (Client 用)。
func (s *DynamoDBStore) getItemJSON(ctx context.Context, pk string, consistentRead bool, hasTTL bool, target any) (bool, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &s.tableName,
		ConsistentRead: &consistentRead,
		Key: map[string]types.AttributeValue{
			"pk": stringAttr(pk),
		},
	})
	if err != nil {
		return false, err
	}

	if len(out.Item) == 0 {
		return false, nil
	}

	// TTL ラグ対策: 取得したアイテムの ttl と現在時刻を比較する。
	if hasTTL {
		ttlAttr, ok := out.Item["ttl"]
		if ok {
			if nAttr, ok := ttlAttr.(*types.AttributeValueMemberN); ok {
				ttlUnix, err := strconv.ParseInt(nAttr.Value, 10, 64)
				if err != nil {
					// ttl 属性が不正な場合はフェイルセーフで期限切れ扱い
					return false, nil
				}
				if s.now().UTC().Unix() >= ttlUnix {
					// 期限切れ
					return false, nil
				}
			}
		}
	}

	dataAttr, ok := out.Item["data"]
	if !ok {
		return false, errors.New("data attribute not found")
	}
	sAttr, ok := dataAttr.(*types.AttributeValueMemberS)
	if !ok {
		return false, errors.New("data attribute is not a string")
	}

	if err := json.Unmarshal([]byte(sAttr.Value), target); err != nil {
		return false, fmt.Errorf("unmarshal: %w", err)
	}

	return true, nil
}

// deleteItem は DynamoDB からアイテムを削除する。冪等。
func (s *DynamoDBStore) deleteItem(ctx context.Context, pk string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.tableName,
		Key: map[string]types.AttributeValue{
			"pk": stringAttr(pk),
		},
	})
	return err
}

// --- 共通チェック ---

// checkAvailable は ctx キャンセルおよびストアクローズをチェックする。
func (s *DynamoDBStore) checkAvailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return errDynamoDBStoreClosed
	}
	return nil
}

// --- Session CRUD ---

// SetSession はセッションを保存する。同一 ID が存在する場合は上書きする。
// time.Time フィールドは UTC に正規化してからシリアライズする。
func (s *DynamoDBStore) SetSession(ctx context.Context, id string, session *idproxy.Session, ttl time.Duration) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	// UTC 正規化コピーを作成する。
	normalized := *session
	normalized.CreatedAt = session.CreatedAt.UTC()
	normalized.ExpiresAt = session.ExpiresAt.UTC()

	if err := s.putItemJSON(ctx, sessionPK(id), &normalized, ttl); err != nil {
		return fmt.Errorf("dynamodb store: set session: %w", err)
	}
	return nil
}

// GetSession はセッションを取得する。
// 存在しない場合または期限切れの場合は (nil, nil) を返す。
// ConsistentRead を有効にして書き込み直後の読み込みに対応する。
func (s *DynamoDBStore) GetSession(ctx context.Context, id string) (*idproxy.Session, error) {
	if err := s.checkAvailable(ctx); err != nil {
		return nil, err
	}

	var session idproxy.Session
	found, err := s.getItemJSON(ctx, sessionPK(id), true, true, &session)
	if err != nil {
		return nil, fmt.Errorf("dynamodb store: get session: %w", err)
	}
	if !found {
		return nil, nil
	}
	return &session, nil
}

// DeleteSession はセッションを削除する。存在しない ID の削除はエラーにならない（冪等）。
func (s *DynamoDBStore) DeleteSession(ctx context.Context, id string) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	if err := s.deleteItem(ctx, sessionPK(id)); err != nil {
		return fmt.Errorf("dynamodb store: delete session: %w", err)
	}
	return nil
}

// --- AuthCode CRUD ---

// SetAuthCode は認可コードを保存する。同一コードが存在する場合は上書きする。
// time.Time フィールドは UTC に正規化してからシリアライズする。
func (s *DynamoDBStore) SetAuthCode(ctx context.Context, code string, data *idproxy.AuthCodeData, ttl time.Duration) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	// UTC 正規化コピーを作成する。
	normalized := *data
	normalized.CreatedAt = data.CreatedAt.UTC()
	normalized.ExpiresAt = data.ExpiresAt.UTC()

	if err := s.putItemJSON(ctx, authCodePK(code), &normalized, ttl); err != nil {
		return fmt.Errorf("dynamodb store: set auth code: %w", err)
	}
	return nil
}

// GetAuthCode は認可コードを取得する。
// 存在しない場合または期限切れの場合は (nil, nil) を返す。
// ConsistentRead を有効にして /authorize → /token の別コンテナ race を防ぐ。
func (s *DynamoDBStore) GetAuthCode(ctx context.Context, code string) (*idproxy.AuthCodeData, error) {
	if err := s.checkAvailable(ctx); err != nil {
		return nil, err
	}

	var data idproxy.AuthCodeData
	found, err := s.getItemJSON(ctx, authCodePK(code), true, true, &data)
	if err != nil {
		return nil, fmt.Errorf("dynamodb store: get auth code: %w", err)
	}
	if !found {
		return nil, nil
	}
	return &data, nil
}

// DeleteAuthCode は認可コードを削除する。存在しない code の削除はエラーにならない（冪等）。
func (s *DynamoDBStore) DeleteAuthCode(ctx context.Context, code string) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	if err := s.deleteItem(ctx, authCodePK(code)); err != nil {
		return fmt.Errorf("dynamodb store: delete auth code: %w", err)
	}
	return nil
}

// --- AccessToken CRUD ---

// SetAccessToken はアクセストークンを保存する。同一 JTI が存在する場合は上書きする。
// time.Time フィールドは UTC に正規化してからシリアライズする。
func (s *DynamoDBStore) SetAccessToken(ctx context.Context, jti string, data *idproxy.AccessTokenData, ttl time.Duration) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	// UTC 正規化コピーを作成する。
	normalized := *data
	normalized.IssuedAt = data.IssuedAt.UTC()
	normalized.ExpiresAt = data.ExpiresAt.UTC()

	if err := s.putItemJSON(ctx, accessTokenPK(jti), &normalized, ttl); err != nil {
		return fmt.Errorf("dynamodb store: set access token: %w", err)
	}
	return nil
}

// GetAccessToken はアクセストークンを取得する。
// 存在しない場合または期限切れの場合は (nil, nil) を返す。
func (s *DynamoDBStore) GetAccessToken(ctx context.Context, jti string) (*idproxy.AccessTokenData, error) {
	if err := s.checkAvailable(ctx); err != nil {
		return nil, err
	}

	var data idproxy.AccessTokenData
	found, err := s.getItemJSON(ctx, accessTokenPK(jti), false, true, &data)
	if err != nil {
		return nil, fmt.Errorf("dynamodb store: get access token: %w", err)
	}
	if !found {
		return nil, nil
	}
	return &data, nil
}

// DeleteAccessToken はアクセストークンを削除する。存在しない JTI の削除はエラーにならない（冪等）。
func (s *DynamoDBStore) DeleteAccessToken(ctx context.Context, jti string) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	if err := s.deleteItem(ctx, accessTokenPK(jti)); err != nil {
		return fmt.Errorf("dynamodb store: delete access token: %w", err)
	}
	return nil
}

// --- Client CRUD ---

// SetClient はクライアントを保存する。同一 clientID が存在する場合は上書きする。
// クライアントは TTL なし（明示的に削除されるまで永続）。
// time.Time フィールドは UTC に正規化してからシリアライズする。
func (s *DynamoDBStore) SetClient(ctx context.Context, clientID string, data *idproxy.ClientData) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	// UTC 正規化コピーを作成する。
	normalized := *data
	normalized.CreatedAt = data.CreatedAt.UTC()

	if err := s.putItemJSONNoTTL(ctx, clientPK(clientID), &normalized); err != nil {
		return fmt.Errorf("dynamodb store: set client: %w", err)
	}
	return nil
}

// GetClient はクライアントを取得する。
// 存在しない場合は (nil, nil) を返す。
// Client は eventually consistent read で十分 (DCR 登録→利用まで間隔あり)。
func (s *DynamoDBStore) GetClient(ctx context.Context, clientID string) (*idproxy.ClientData, error) {
	if err := s.checkAvailable(ctx); err != nil {
		return nil, err
	}

	var data idproxy.ClientData
	found, err := s.getItemJSON(ctx, clientPK(clientID), false, false, &data)
	if err != nil {
		return nil, fmt.Errorf("dynamodb store: get client: %w", err)
	}
	if !found {
		return nil, nil
	}
	return &data, nil
}

// DeleteClient はクライアントを削除する。存在しない clientID の削除はエラーにならない（冪等）。
func (s *DynamoDBStore) DeleteClient(ctx context.Context, clientID string) error {
	if err := s.checkAvailable(ctx); err != nil {
		return err
	}

	if err := s.deleteItem(ctx, clientPK(clientID)); err != nil {
		return fmt.Errorf("dynamodb store: delete client: %w", err)
	}
	return nil
}

// --- Cleanup / Close ---

// Cleanup は no-op。DynamoDB の TTL 機能によるバックグラウンド削除に委譲する。
// DynamoDB TTL のラグ (最大 48h) は Get 時の TTL チェックで補完する。
func (s *DynamoDBStore) Cleanup(_ context.Context) error {
	return nil
}

// Close はストアを閉じる。以降の操作は errDynamoDBStoreClosed を返す。
// 二重呼び出しは安全（sync.Once + atomic.Bool で保護）。
func (s *DynamoDBStore) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
	})
	return nil
}
