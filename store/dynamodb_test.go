package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/youyo/idproxy"
)

// --- fakeDynamoDBClient: テスト用モック DynamoDB クライアント ---

// fakeDynamoDBClient は DynamoDBClient インターフェースのインメモリ実装。
// map-backed でスレッドセーフ、エラー注入フック付き。
type fakeDynamoDBClient struct {
	mu            sync.Mutex
	items         map[string]map[string]types.AttributeValue // pk -> full item
	getItemErr    error
	putItemErr    error
	deleteItemErr error
	// PutItem に渡された最後のアイテムを記録 (T04 検証用)
	lastPutItem map[string]types.AttributeValue
}

func newFakeDynamoDBClient() *fakeDynamoDBClient {
	return &fakeDynamoDBClient{
		items: make(map[string]map[string]types.AttributeValue),
	}
}

func (f *fakeDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.getItemErr != nil {
		return nil, f.getItemErr
	}

	pkAttr, ok := params.Key["pk"]
	if !ok {
		return &dynamodb.GetItemOutput{}, nil
	}
	pkVal, ok := pkAttr.(*types.AttributeValueMemberS)
	if !ok {
		return &dynamodb.GetItemOutput{}, nil
	}

	item, exists := f.items[pkVal.Value]
	if !exists {
		return &dynamodb.GetItemOutput{}, nil
	}

	// アイテムのコピーを返す
	copied := make(map[string]types.AttributeValue, len(item))
	for k, v := range item {
		copied[k] = v
	}
	return &dynamodb.GetItemOutput{Item: copied}, nil
}

func (f *fakeDynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.putItemErr != nil {
		return nil, f.putItemErr
	}

	pkAttr, ok := params.Item["pk"]
	if !ok {
		return &dynamodb.PutItemOutput{}, nil
	}
	pkVal, ok := pkAttr.(*types.AttributeValueMemberS)
	if !ok {
		return &dynamodb.PutItemOutput{}, nil
	}

	// ConditionExpression の評価
	if params.ConditionExpression != nil {
		switch *params.ConditionExpression {
		case "attribute_exists(pk)":
			// pk が存在しない場合は ConditionalCheckFailedException を返す
			if _, exists := f.items[pkVal.Value]; !exists {
				return nil, &types.ConditionalCheckFailedException{
					Message: stringPtr("The conditional request failed"),
				}
			}
		case "attribute_exists(pk) AND used = :false":
			// pk が存在し、かつ top-level used 属性が false の場合のみ成功
			// この評価は mutex 保護下で atomic に行われる
			existing, exists := f.items[pkVal.Value]
			if !exists {
				return nil, &types.ConditionalCheckFailedException{
					Message: stringPtr("The conditional request failed"),
				}
			}
			usedAttr, hasUsed := existing["used"]
			if !hasUsed {
				// used 属性がない = 旧フォーマット。条件失敗とする
				return nil, &types.ConditionalCheckFailedException{
					Message: stringPtr("The conditional request failed"),
				}
			}
			boolAttr, ok := usedAttr.(*types.AttributeValueMemberBOOL)
			if !ok || boolAttr.Value {
				// used が true (または型不正) → 既に消費済み
				return nil, &types.ConditionalCheckFailedException{
					Message: stringPtr("The conditional request failed"),
				}
			}
		}
	}

	// アイテムを保存
	copied := make(map[string]types.AttributeValue, len(params.Item))
	for k, v := range params.Item {
		copied[k] = v
	}
	f.items[pkVal.Value] = copied
	f.lastPutItem = copied

	return &dynamodb.PutItemOutput{}, nil
}

// stringPtr は文字列のポインタを返すヘルパー。
func stringPtr(s string) *string { return &s }

func (f *fakeDynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.deleteItemErr != nil {
		return nil, f.deleteItemErr
	}

	pkAttr, ok := params.Key["pk"]
	if !ok {
		return &dynamodb.DeleteItemOutput{}, nil
	}
	pkVal, ok := pkAttr.(*types.AttributeValueMemberS)
	if !ok {
		return &dynamodb.DeleteItemOutput{}, nil
	}

	delete(f.items, pkVal.Value)
	return &dynamodb.DeleteItemOutput{}, nil
}

// --- テストデータ生成ヘルパー ---

func testDynamoDBSession() *idproxy.Session {
	now := time.Now().UTC().Truncate(time.Second)
	return &idproxy.Session{
		ID:             "sess-ddb-001",
		User:           &idproxy.User{Email: "test@example.com", Name: "Test User", Subject: "sub-001", Issuer: "https://issuer.example.com"},
		ProviderIssuer: "https://issuer.example.com",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9.test",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
	}
}

func testDynamoDBAuthCodeData() *idproxy.AuthCodeData {
	now := time.Now().UTC().Truncate(time.Second)
	return &idproxy.AuthCodeData{
		Code:                "code-ddb-abc123",
		ClientID:            "client-ddb-001",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "profile"},
		User:                &idproxy.User{Email: "test@example.com", Subject: "sub-001"},
		Used:                false,
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
	}
}

func testDynamoDBAccessTokenData() *idproxy.AccessTokenData {
	now := time.Now().UTC().Truncate(time.Second)
	return &idproxy.AccessTokenData{
		JTI:       "jti-ddb-xyz789",
		Subject:   "sub-001",
		Email:     "test@example.com",
		ClientID:  "client-ddb-001",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Revoked:   false,
	}
}

func testDynamoDBClientData() *idproxy.ClientData {
	return &idproxy.ClientData{
		ClientID:                "client-ddb-001",
		ClientName:              "Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "openid profile",
		CreatedAt:               time.Now().UTC().Truncate(time.Second),
	}
}

// newTestDynamoDBStore はテスト用 DynamoDBStore を生成する。
// now 関数を外部から注入して時刻制御を可能にする。
func newTestDynamoDBStore(now func() time.Time) (*DynamoDBStore, *fakeDynamoDBClient) {
	client := newFakeDynamoDBClient()
	store := NewDynamoDBStoreWithClient(client, "test-table")
	if now != nil {
		store.now = now
	}
	return store, client
}

// --- N01-N04: Session CRUD ---

// N01: SetSession → GetSession で同一値が取得できること (JSON round-trip)
func TestDynamoDBStore_N01_SetGetSession(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	sess := testDynamoDBSession()

	if err := s.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
	if got.ProviderIssuer != sess.ProviderIssuer {
		t.Errorf("ProviderIssuer = %q, want %q", got.ProviderIssuer, sess.ProviderIssuer)
	}
	if got.IDToken != sess.IDToken {
		t.Errorf("IDToken = %q, want %q", got.IDToken, sess.IDToken)
	}
	if got.User == nil || got.User.Email != sess.User.Email {
		t.Errorf("User.Email = %v, want %v", got.User, sess.User.Email)
	}
}

// N02: SetSession → DeleteSession → GetSession で nil が返ること
func TestDynamoDBStore_N02_SetDeleteGetSession(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	sess := testDynamoDBSession()

	if err := s.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	if err := s.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (deleted)", got)
	}
}

// N03: 存在しない ID の GetSession は (nil, nil) を返すこと
func TestDynamoDBStore_N03_GetSession_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	got, err := s.GetSession(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil", got)
	}
}

// N04: 存在しない ID の DeleteSession はエラーにならないこと (冪等)
func TestDynamoDBStore_N04_DeleteSession_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	if err := s.DeleteSession(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteSession() error = %v, want nil", err)
	}
}

// --- N05: AuthCode CRUD ---

// N05-a: SetAuthCode → GetAuthCode で同一値 (AuthCodeData.Used 保持)
func TestDynamoDBStore_N05a_SetGetAuthCode(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBAuthCodeData()
	data.Used = true // Used フィールドが保持されることを確認

	if err := s.SetAuthCode(ctx, data.Code, data, time.Hour); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}
	got, err := s.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthCode() returned nil")
	}
	if got.Code != data.Code {
		t.Errorf("Code = %q, want %q", got.Code, data.Code)
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if !got.Used {
		t.Error("Used = false, want true")
	}
	if len(got.Scopes) != len(data.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, data.Scopes)
	}
}

// N05-b: SetAuthCode → DeleteAuthCode → GetAuthCode で nil
func TestDynamoDBStore_N05b_SetDeleteGetAuthCode(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBAuthCodeData()

	if err := s.SetAuthCode(ctx, data.Code, data, time.Hour); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}
	if err := s.DeleteAuthCode(ctx, data.Code); err != nil {
		t.Fatalf("DeleteAuthCode() error = %v", err)
	}
	got, err := s.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil", got)
	}
}

// N05-c: 存在しない code の GetAuthCode は (nil, nil)
func TestDynamoDBStore_N05c_GetAuthCode_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	got, err := s.GetAuthCode(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil", got)
	}
}

// N05-d: 存在しない code の DeleteAuthCode はエラーなし
func TestDynamoDBStore_N05d_DeleteAuthCode_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	if err := s.DeleteAuthCode(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteAuthCode() error = %v, want nil", err)
	}
}

// --- N06: AccessToken CRUD ---

// N06-a: SetAccessToken → GetAccessToken で同一値 (AccessTokenData.Revoked 保持)
func TestDynamoDBStore_N06a_SetGetAccessToken(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBAccessTokenData()
	data.Revoked = true

	if err := s.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}
	got, err := s.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessToken() returned nil")
	}
	if got.JTI != data.JTI {
		t.Errorf("JTI = %q, want %q", got.JTI, data.JTI)
	}
	if !got.Revoked {
		t.Error("Revoked = false, want true")
	}
	if len(got.Scopes) != len(data.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, data.Scopes)
	}
}

// N06-b: SetAccessToken → DeleteAccessToken → GetAccessToken で nil
func TestDynamoDBStore_N06b_SetDeleteGetAccessToken(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBAccessTokenData()

	if err := s.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}
	if err := s.DeleteAccessToken(ctx, data.JTI); err != nil {
		t.Fatalf("DeleteAccessToken() error = %v", err)
	}
	got, err := s.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil", got)
	}
}

// N06-c: 存在しない JTI の GetAccessToken は (nil, nil)
func TestDynamoDBStore_N06c_GetAccessToken_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	got, err := s.GetAccessToken(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAccessToken() = %v, want nil", got)
	}
}

// N06-d: 存在しない JTI の DeleteAccessToken はエラーなし
func TestDynamoDBStore_N06d_DeleteAccessToken_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	if err := s.DeleteAccessToken(ctx, "nonexistent"); err != nil {
		t.Errorf("DeleteAccessToken() error = %v, want nil", err)
	}
}

// --- N07: Client CRUD (TTL なし) ---

// N07: SetClient → GetClient → DeleteClient
func TestDynamoDBStore_N07_ClientCRUD(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBClientData()

	if err := s.SetClient(ctx, data.ClientID, data); err != nil {
		t.Fatalf("SetClient() error = %v", err)
	}
	got, err := s.GetClient(ctx, data.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetClient() returned nil")
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if got.ClientName != data.ClientName {
		t.Errorf("ClientName = %q, want %q", got.ClientName, data.ClientName)
	}

	// DeleteClient
	if err := s.DeleteClient(ctx, data.ClientID); err != nil {
		t.Fatalf("DeleteClient() error = %v", err)
	}
	got, err = s.GetClient(ctx, data.ClientID)
	if err != nil {
		t.Fatalf("GetClient() after Delete error = %v", err)
	}
	if got != nil {
		t.Errorf("GetClient() after Delete = %v, want nil", got)
	}
}

// --- N08: Upsert ---

// N08: SetSession を同一 ID で 2 回呼び出すと 2 回目の値が取得されること
func TestDynamoDBStore_N08_Upsert(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	sess1 := testDynamoDBSession()
	sess2 := testDynamoDBSession()
	sess2.IDToken = "updated-token"

	if err := s.SetSession(ctx, sess1.ID, sess1, time.Hour); err != nil {
		t.Fatalf("SetSession(1) error = %v", err)
	}
	if err := s.SetSession(ctx, sess1.ID, sess2, time.Hour); err != nil {
		t.Fatalf("SetSession(2) error = %v", err)
	}

	got, err := s.GetSession(ctx, sess1.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil")
	}
	if got.IDToken != "updated-token" {
		t.Errorf("IDToken = %q, want %q", got.IDToken, "updated-token")
	}
}

// --- T01-T04: TTL ケース ---

// T01: TTL が 1ns のセッションは時刻を進めると GetSession で nil が返ること
func TestDynamoDBStore_T01_Session_Expired(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		// 最初の呼び出し (SetSession) は baseTime、その後は baseTime + 1s
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		return baseTime.Add(time.Second)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	sess := testDynamoDBSession()

	if err := s.SetSession(ctx, sess.ID, sess, time.Nanosecond); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetSession() = %v, want nil (expired)", got)
	}
}

// T02: TTL が 0 の SetAuthCode → GetAuthCode で nil が返ること
func TestDynamoDBStore_T02_AuthCode_Expired_ZeroTTL(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		return baseTime.Add(time.Second)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	data := testDynamoDBAuthCodeData()

	if err := s.SetAuthCode(ctx, data.Code, data, 0); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}

	got, err := s.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetAuthCode() = %v, want nil (expired TTL=0)", got)
	}
}

// T03: TTL 1h で保存し、now + 30m で取得すると有効データが返ること
func TestDynamoDBStore_T03_AccessToken_WithinTTL(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		// +30分後に読み込む → TTL 内
		return baseTime.Add(30 * time.Minute)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	data := testDynamoDBAccessTokenData()

	if err := s.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}

	got, err := s.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessToken() returned nil, want valid data (within TTL)")
	}
	if got.JTI != data.JTI {
		t.Errorf("JTI = %q, want %q", got.JTI, data.JTI)
	}
}

// T04: PutItem 時に ttl 属性が *types.AttributeValueMemberN として設定されること
func TestDynamoDBStore_T04_TTLAttribute_IsNumber(t *testing.T) {
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return baseTime }

	s, fakeClient := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	sess := testDynamoDBSession()

	ttl := time.Hour
	if err := s.SetSession(ctx, sess.ID, sess, ttl); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	fakeClient.mu.Lock()
	lastItem := fakeClient.lastPutItem
	fakeClient.mu.Unlock()

	if lastItem == nil {
		t.Fatal("lastPutItem is nil: PutItem was not called")
	}

	ttlAttr, ok := lastItem["ttl"]
	if !ok {
		t.Fatal("ttl attribute not found in PutItem item")
	}

	nAttr, ok := ttlAttr.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("ttl attribute type = %T, want *types.AttributeValueMemberN", ttlAttr)
	}

	expectedTTL := baseTime.Add(ttl).Unix()
	expectedStr := fmt.Sprintf("%d", expectedTTL)
	if nAttr.Value != expectedStr {
		t.Errorf("ttl value = %q, want %q", nAttr.Value, expectedStr)
	}
}

// --- E01-E07: 異常系ケース ---

// E01: GetItem が AWS エラーを返す場合、"dynamodb store: get session:" で始まるエラーが返ること
func TestDynamoDBStore_E01_GetItem_Error(t *testing.T) {
	s, fakeClient := newTestDynamoDBStore(nil)
	ctx := context.Background()

	awsErr := errors.New("ResourceNotFoundException")
	fakeClient.getItemErr = awsErr

	_, err := s.GetSession(ctx, "sess-1")
	if err == nil {
		t.Fatal("GetSession() error = nil, want error")
	}
	if !errors.Is(err, awsErr) {
		t.Errorf("GetSession() error does not wrap awsErr: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "dynamodb store: get session:") {
		t.Errorf("GetSession() error = %q, want prefix 'dynamodb store: get session:'", err.Error())
	}
}

// E02: PutItem エラーが適切にラップされること
func TestDynamoDBStore_E02_PutItem_Error(t *testing.T) {
	s, fakeClient := newTestDynamoDBStore(nil)
	ctx := context.Background()

	awsErr := errors.New("ProvisionedThroughputExceededException")
	fakeClient.putItemErr = awsErr

	err := s.SetSession(ctx, "sess-1", testDynamoDBSession(), time.Hour)
	if err == nil {
		t.Fatal("SetSession() error = nil, want error")
	}
	if !errors.Is(err, awsErr) {
		t.Errorf("SetSession() error does not wrap awsErr: %v", err)
	}
}

// E03: DeleteItem エラーが適切にラップされること
func TestDynamoDBStore_E03_DeleteItem_Error(t *testing.T) {
	s, fakeClient := newTestDynamoDBStore(nil)
	ctx := context.Background()

	awsErr := errors.New("ConditionalCheckFailedException")
	fakeClient.deleteItemErr = awsErr

	err := s.DeleteSession(ctx, "sess-1")
	if err == nil {
		t.Fatal("DeleteSession() error = nil, want error")
	}
	if !errors.Is(err, awsErr) {
		t.Errorf("DeleteSession() error does not wrap awsErr: %v", err)
	}
}

// E04: GetItem が item を返すが data が不正 JSON の場合、unmarshal エラーが返ること
func TestDynamoDBStore_E04_InvalidJSON_Error(t *testing.T) {
	s, fakeClient := newTestDynamoDBStore(nil)
	ctx := context.Background()

	// 不正な JSON を持つアイテムを直接挿入
	fakeClient.mu.Lock()
	fakeClient.items["session:bad-json"] = map[string]types.AttributeValue{
		"pk":   &types.AttributeValueMemberS{Value: "session:bad-json"},
		"data": &types.AttributeValueMemberS{Value: "not-valid-json{{{"},
		"ttl":  &types.AttributeValueMemberN{Value: "9999999999"},
	}
	fakeClient.mu.Unlock()

	_, err := s.GetSession(ctx, "bad-json")
	if err == nil {
		t.Fatal("GetSession() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "dynamodb store:") {
		t.Errorf("GetSession() error = %q, want 'dynamodb store:' prefix", err.Error())
	}
}

// E05: ctx がキャンセル済みの場合、ctx.Err() を返すこと (全 CRUD メソッド)
func TestDynamoDBStore_E05_ContextCanceled(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess := testDynamoDBSession()
	data := testDynamoDBAuthCodeData()
	token := testDynamoDBAccessTokenData()
	client := testDynamoDBClientData()

	// SetSession
	if err := s.SetSession(ctx, sess.ID, sess, time.Hour); err != context.Canceled {
		t.Errorf("SetSession() error = %v, want context.Canceled", err)
	}
	// GetSession
	if _, err := s.GetSession(ctx, sess.ID); err != context.Canceled {
		t.Errorf("GetSession() error = %v, want context.Canceled", err)
	}
	// DeleteSession
	if err := s.DeleteSession(ctx, sess.ID); err != context.Canceled {
		t.Errorf("DeleteSession() error = %v, want context.Canceled", err)
	}
	// SetAuthCode
	if err := s.SetAuthCode(ctx, data.Code, data, time.Hour); err != context.Canceled {
		t.Errorf("SetAuthCode() error = %v, want context.Canceled", err)
	}
	// GetAuthCode
	if _, err := s.GetAuthCode(ctx, data.Code); err != context.Canceled {
		t.Errorf("GetAuthCode() error = %v, want context.Canceled", err)
	}
	// DeleteAuthCode
	if err := s.DeleteAuthCode(ctx, data.Code); err != context.Canceled {
		t.Errorf("DeleteAuthCode() error = %v, want context.Canceled", err)
	}
	// SetAccessToken
	if err := s.SetAccessToken(ctx, token.JTI, token, time.Hour); err != context.Canceled {
		t.Errorf("SetAccessToken() error = %v, want context.Canceled", err)
	}
	// GetAccessToken
	if _, err := s.GetAccessToken(ctx, token.JTI); err != context.Canceled {
		t.Errorf("GetAccessToken() error = %v, want context.Canceled", err)
	}
	// DeleteAccessToken
	if err := s.DeleteAccessToken(ctx, token.JTI); err != context.Canceled {
		t.Errorf("DeleteAccessToken() error = %v, want context.Canceled", err)
	}
	// SetClient
	if err := s.SetClient(ctx, client.ClientID, client); err != context.Canceled {
		t.Errorf("SetClient() error = %v, want context.Canceled", err)
	}
	// GetClient
	if _, err := s.GetClient(ctx, client.ClientID); err != context.Canceled {
		t.Errorf("GetClient() error = %v, want context.Canceled", err)
	}
	// DeleteClient
	if err := s.DeleteClient(ctx, client.ClientID); err != context.Canceled {
		t.Errorf("DeleteClient() error = %v, want context.Canceled", err)
	}
}

// E06: Close() 後に SetSession を呼び出すと errDynamoDBStoreClosed が返ること
func TestDynamoDBStore_E06_ClosedStore(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	err := s.SetSession(ctx, "sess-1", testDynamoDBSession(), time.Hour)
	if !errors.Is(err, errDynamoDBStoreClosed) {
		t.Errorf("SetSession() after Close error = %v, want errDynamoDBStoreClosed", err)
	}
}

// E07: Close() を 2 回呼び出しても両方 nil が返ること (冪等)
func TestDynamoDBStore_E07_Close_Idempotent(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)

	if err := s.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

// --- C01-C02: 並行アクセスケース ---

// C01: 100 goroutine が同一 DynamoDBStore に対し異なる PK で SetSession (race なし)
func TestDynamoDBStore_C01_Concurrent_SetSession(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		id := fmt.Sprintf("sess-%d", i)
		sess := &idproxy.Session{
			ID:   id,
			User: &idproxy.User{Email: id + "@example.com"},
		}
		go func() {
			defer wg.Done()
			if err := s.SetSession(ctx, id, sess, time.Hour); err != nil {
				t.Errorf("SetSession(%s) error = %v", id, err)
			}
		}()
	}
	wg.Wait()

	// 全件取得可能であることを確認
	for i := range goroutines {
		id := fmt.Sprintf("sess-%d", i)
		got, err := s.GetSession(ctx, id)
		if err != nil {
			t.Errorf("GetSession(%s) error = %v", id, err)
			continue
		}
		if got == nil {
			t.Errorf("GetSession(%s) = nil, want session", id)
		}
	}
}

// C02: 50 goroutine が SetClient + 50 goroutine が GetClient (別 PK, race なし)
func TestDynamoDBStore_C02_Concurrent_SetGetClient(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := range goroutines {
		setID := fmt.Sprintf("set-client-%d", i)
		getID := fmt.Sprintf("get-client-%d", i)

		setData := &idproxy.ClientData{ClientID: setID}
		go func() {
			defer wg.Done()
			if err := s.SetClient(ctx, setID, setData); err != nil {
				t.Errorf("SetClient(%s) error = %v", setID, err)
			}
		}()

		go func() {
			defer wg.Done()
			// 別の PK で GetClient (存在しなくてもエラーでない)
			_, _ = s.GetClient(ctx, getID)
		}()
	}
	wg.Wait()
}

// --- G01-G03: エッジケース ---

// G01: PK に ":" を含む ID (例: sess-a:b) は正常動作すること
func TestDynamoDBStore_G01_ColonInID(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	sess := testDynamoDBSession()
	sess.ID = "sess-a:b" // コロンを含む ID

	if err := s.SetSession(ctx, sess.ID, sess, time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}
	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() returned nil for colon-containing ID")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
}

// G02: 空文字列 ID ("") は正常動作すること (MemoryStore と同挙動)
func TestDynamoDBStore_G02_EmptyID(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	sess := testDynamoDBSession()
	sess.ID = ""

	if err := s.SetSession(ctx, "", sess, time.Hour); err != nil {
		t.Fatalf("SetSession(empty) error = %v", err)
	}
	got, err := s.GetSession(ctx, "")
	if err != nil {
		t.Fatalf("GetSession(empty) error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession(empty) returned nil")
	}
}

// --- RT: RefreshToken テスト ---

func testDynamoDBRefreshTokenData() *idproxy.RefreshTokenData {
	now := time.Now().UTC().Truncate(time.Second)
	return &idproxy.RefreshTokenData{
		ID:        "rt-ddb-opaque-001",
		FamilyID:  "family-ddb-uuid-001",
		ClientID:  "client-ddb-001",
		Subject:   "sub-001",
		Email:     "test@example.com",
		Name:      "Test User",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		Used:      false,
	}
}

// RT01: SetRefreshToken → GetRefreshToken で同一値が取得できること
func TestDynamoDBStore_RT01_SetGetRefreshToken(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := s.GetRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshToken() returned nil")
	}
	if got.ID != data.ID {
		t.Errorf("ID = %q, want %q", got.ID, data.ID)
	}
	if got.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q", got.FamilyID, data.FamilyID)
	}
	if got.ClientID != data.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, data.ClientID)
	}
	if got.Used {
		t.Error("Used = true, want false")
	}
}

// RT02: GetRefreshToken 未登録は (nil, nil)
func TestDynamoDBStore_RT02_GetRefreshToken_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	got, err := s.GetRefreshToken(ctx, "nonexistent-rt")
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetRefreshToken() = %v, want nil", got)
	}
}

// RT03: GetRefreshToken TTL 切れは (nil, nil)
func TestDynamoDBStore_RT03_GetRefreshToken_Expired(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		return baseTime.Add(time.Second)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Nanosecond); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := s.GetRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}
	if got != nil {
		t.Errorf("GetRefreshToken() = %v, want nil (expired)", got)
	}
}

// RT04: ConsumeRefreshToken 初回消費 — Used=true に更新され、data が返る
func TestDynamoDBStore_RT04_ConsumeRefreshToken_FirstConsume(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := s.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("ConsumeRefreshToken() returned nil")
	}
	if !got.Used {
		t.Error("Used = false, want true (should be marked as used)")
	}
	if got.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q", got.FamilyID, data.FamilyID)
	}

	// Store 上のエントリも Used=true になっていること
	stored, _ := s.GetRefreshToken(ctx, data.ID)
	if stored == nil {
		t.Fatal("GetRefreshToken() after consume returned nil")
	}
	if !stored.Used {
		t.Error("stored Used = false, want true after consume")
	}
}

// RT05: ConsumeRefreshToken 2回目 — (data, ErrRefreshTokenAlreadyConsumed) が返る
func TestDynamoDBStore_RT05_ConsumeRefreshToken_SecondConsume(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	// 1回目の消費
	got1, err := s.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("first ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got1 == nil {
		t.Fatal("first ConsumeRefreshToken() returned nil")
	}

	// 2回目の消費
	got2, err := s.ConsumeRefreshToken(ctx, data.ID)
	if err == nil {
		t.Fatal("second ConsumeRefreshToken() error = nil, want ErrRefreshTokenAlreadyConsumed")
	}
	if err != idproxy.ErrRefreshTokenAlreadyConsumed {
		t.Errorf("second ConsumeRefreshToken() error = %v, want %v", err, idproxy.ErrRefreshTokenAlreadyConsumed)
	}
	if got2 == nil {
		t.Fatal("second ConsumeRefreshToken() returned nil data, want data with FamilyID")
	}
	if got2.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q (for replay detection)", got2.FamilyID, data.FamilyID)
	}
}

// RT06: ConsumeRefreshToken 未登録 — (nil, nil)
func TestDynamoDBStore_RT06_ConsumeRefreshToken_NotFound(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	got, err := s.ConsumeRefreshToken(ctx, "nonexistent-rt")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ConsumeRefreshToken() = %v, want nil", got)
	}
}

// RT07: ConsumeRefreshToken TTL 切れ — (nil, nil)
func TestDynamoDBStore_RT07_ConsumeRefreshToken_Expired(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		return baseTime.Add(time.Second)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Nanosecond); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	got, err := s.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ConsumeRefreshToken() = %v, want nil (expired)", got)
	}
}

// RT08: SetFamilyRevocation → IsFamilyRevoked=true
func TestDynamoDBStore_RT08_SetFamilyRevocation(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	familyID := "family-ddb-uuid-001"

	if err := s.SetFamilyRevocation(ctx, familyID, time.Hour); err != nil {
		t.Fatalf("SetFamilyRevocation() error = %v", err)
	}

	revoked, err := s.IsFamilyRevoked(ctx, familyID)
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if !revoked {
		t.Error("IsFamilyRevoked() = false, want true")
	}
}

// RT09: 未設定 family → IsFamilyRevoked=false
func TestDynamoDBStore_RT09_IsFamilyRevoked_NotSet(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	revoked, err := s.IsFamilyRevoked(ctx, "unknown-family")
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if revoked {
		t.Error("IsFamilyRevoked() = true, want false")
	}
}

// RT10: SetFamilyRevocation TTL 切れ → IsFamilyRevoked=false
func TestDynamoDBStore_RT10_IsFamilyRevoked_Expired(t *testing.T) {
	baseTime := time.Now().UTC()
	callCount := int32(0)
	nowFn := func() time.Time {
		if atomic.AddInt32(&callCount, 1) <= 1 {
			return baseTime
		}
		return baseTime.Add(time.Second)
	}

	s, _ := newTestDynamoDBStore(nowFn)
	ctx := context.Background()
	familyID := "family-ddb-uuid-expired"

	if err := s.SetFamilyRevocation(ctx, familyID, time.Nanosecond); err != nil {
		t.Fatalf("SetFamilyRevocation() error = %v", err)
	}

	revoked, err := s.IsFamilyRevoked(ctx, familyID)
	if err != nil {
		t.Fatalf("IsFamilyRevoked() error = %v", err)
	}
	if revoked {
		t.Error("IsFamilyRevoked() = true, want false (expired)")
	}
}

// RT11: ConsumeRefreshToken — CAS 失敗後、追加 GetItem で found → (data, ErrRefreshTokenAlreadyConsumed)
//
// シミュレーション: PutItem を ConditionalCheckFailedException に設定し、items を残したまま。
// 追加 GetItem が成功してデータと ErrRefreshTokenAlreadyConsumed を返すことを検証する。
func TestDynamoDBStore_RT11_ConsumeRefreshToken_CASFailure_RetryFound(t *testing.T) {
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()
	futureUnix := data.ExpiresAt.Unix()
	itemJSON := fmt.Sprintf(
		`{"ID":%q,"FamilyID":%q,"ClientID":%q,"Subject":%q,"Email":%q,"Name":%q,"Scopes":["openid","profile"],"IssuedAt":%q,"ExpiresAt":%q,"Used":false}`,
		data.ID, data.FamilyID, data.ClientID, data.Subject, data.Email, data.Name,
		data.IssuedAt.Format(time.RFC3339), data.ExpiresAt.Format(time.RFC3339),
	)

	fc := newFakeDynamoDBClient()
	store := NewDynamoDBStoreWithClient(fc, "test-table")

	fc.mu.Lock()
	fc.items["refreshtoken:"+data.ID] = map[string]types.AttributeValue{
		"pk":   &types.AttributeValueMemberS{Value: "refreshtoken:" + data.ID},
		"data": &types.AttributeValueMemberS{Value: itemJSON},
		"ttl":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", futureUnix)},
	}
	// PutItem は CAS 失敗を返す（items は残したまま → 追加 GetItem で found）
	fc.putItemErr = &types.ConditionalCheckFailedException{
		Message: stringPtr("The conditional request failed"),
	}
	fc.mu.Unlock()

	got, err := store.ConsumeRefreshToken(ctx, data.ID)
	if err == nil {
		t.Fatal("ConsumeRefreshToken() error = nil, want ErrRefreshTokenAlreadyConsumed")
	}
	if err != idproxy.ErrRefreshTokenAlreadyConsumed {
		t.Errorf("error = %v, want ErrRefreshTokenAlreadyConsumed", err)
	}
	if got == nil {
		t.Fatal("ConsumeRefreshToken() returned nil data, want data")
	}
	if got.FamilyID != data.FamilyID {
		t.Errorf("FamilyID = %q, want %q", got.FamilyID, data.FamilyID)
	}
}

// RT11E: ConsumeRefreshToken CAS 失敗後、TTL 消滅（追加 GetItem → not found）→ (nil, nil)
// countingFakeDynamoDBClient を使用: GetItem 1回目=found, PutItem=CAS失敗, GetItem 2回目=not found
func TestDynamoDBStore_RT11E_ConsumeRefreshToken_CASFailure_TTLExpired(t *testing.T) {
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()
	futureUnix := data.ExpiresAt.Unix()
	itemJSON := fmt.Sprintf(
		`{"ID":%q,"FamilyID":%q,"ClientID":%q,"Subject":%q,"Email":%q,"Name":%q,"Scopes":["openid","profile"],"IssuedAt":%q,"ExpiresAt":%q,"Used":false}`,
		data.ID, data.FamilyID, data.ClientID, data.Subject, data.Email, data.Name,
		data.IssuedAt.Format(time.RFC3339), data.ExpiresAt.Format(time.RFC3339),
	)
	item := map[string]types.AttributeValue{
		"pk":   &types.AttributeValueMemberS{Value: "refreshtoken:" + data.ID},
		"data": &types.AttributeValueMemberS{Value: itemJSON},
		"ttl":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", futureUnix)},
	}

	store := NewDynamoDBStoreWithClient(
		newGetOnceDeleteAfterPutFakeClient(item),
		"test-table",
	)

	got, err := store.ConsumeRefreshToken(ctx, data.ID)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ConsumeRefreshToken() = %v, want nil (TTL expired after CAS)", got)
	}
}

// getOnceDeleteAfterPutFakeClient は DynamoDBClient の特殊実装。
// GetItem の 1回目は指定アイテムを返し、PutItem は CAS 失敗を返しつつアイテムを削除し、
// 2回目以降の GetItem は not found を返す。
type getOnceDeleteAfterPutFakeClient struct {
	mu      sync.Mutex
	item    map[string]types.AttributeValue
	putSeen bool
}

func newGetOnceDeleteAfterPutFakeClient(item map[string]types.AttributeValue) *getOnceDeleteAfterPutFakeClient {
	return &getOnceDeleteAfterPutFakeClient{item: item}
}

func (c *getOnceDeleteAfterPutFakeClient) GetItem(_ context.Context, params *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.putSeen || c.item == nil {
		// PutItem 後 または アイテム未設定 → not found
		return &dynamodb.GetItemOutput{}, nil
	}
	// 初回: アイテムのコピーを返す
	copied := make(map[string]types.AttributeValue, len(c.item))
	for k, v := range c.item {
		copied[k] = v
	}
	return &dynamodb.GetItemOutput{Item: copied}, nil
}

func (c *getOnceDeleteAfterPutFakeClient) PutItem(_ context.Context, _ *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putSeen = true
	return nil, &types.ConditionalCheckFailedException{
		Message: stringPtr("The conditional request failed"),
	}
}

func (c *getOnceDeleteAfterPutFakeClient) DeleteItem(_ context.Context, _ *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return &dynamodb.DeleteItemOutput{}, nil
}

// G03: Cleanup(ctx) を呼び出すと nil が返ること (no-op)
func TestDynamoDBStore_G03_Cleanup_NoOp(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	if err := s.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup() error = %v, want nil", err)
	}
}

// Race: 20 goroutine が同一 refresh_token を同時 ConsumeRefreshToken
// 期待: 成功 (err==nil) は正確に 1 個、残り 19 個は ErrRefreshTokenAlreadyConsumed
// fake client は PutItem の ConditionExpression を atomic に評価する必要がある
func TestDynamoDBStore_ConsumeRefreshToken_Race(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()
	data := testDynamoDBRefreshTokenData()

	if err := s.SetRefreshToken(ctx, data.ID, data, time.Hour); err != nil {
		t.Fatalf("SetRefreshToken() error = %v", err)
	}

	const goroutines = 20
	// startGate で全 goroutine を同時にリリース
	var startGate sync.WaitGroup
	startGate.Add(1)

	type result struct {
		data *idproxy.RefreshTokenData
		err  error
	}
	results := make([]result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			startGate.Wait() // 全 goroutine が揃うまで待機
			d, err := s.ConsumeRefreshToken(ctx, data.ID)
			results[idx] = result{data: d, err: err}
		}(i)
	}

	startGate.Done() // 全 goroutine を同時リリース
	wg.Wait()

	successCount := 0
	alreadyConsumedCount := 0
	for _, r := range results {
		if r.err == nil {
			successCount++
			if r.data == nil {
				t.Error("success result: data is nil, want non-nil")
			} else if !r.data.Used {
				t.Error("success result: data.Used = false, want true")
			}
		} else if errors.Is(r.err, idproxy.ErrRefreshTokenAlreadyConsumed) {
			alreadyConsumedCount++
			if r.data == nil {
				t.Error("ErrRefreshTokenAlreadyConsumed result: data is nil, want non-nil with FamilyID")
			}
		} else {
			t.Errorf("unexpected error: %v", r.err)
		}
	}

	if successCount != 1 {
		t.Errorf("success count = %d, want exactly 1", successCount)
	}
	if alreadyConsumedCount != goroutines-1 {
		t.Errorf("alreadyConsumed count = %d, want %d", alreadyConsumedCount, goroutines-1)
	}
}

// --- UTC 正規化テスト ---

// UTC01: SetSession に非 UTC time.Time を渡すと、取得後の time.Time が UTC であること
func TestDynamoDBStore_UTC01_Session_TimeNormalized(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	// JST (UTC+9) で時刻を作成
	createdAt := time.Date(2025, 6, 1, 12, 0, 0, 0, jst)
	expiresAt := time.Date(2025, 6, 1, 24, 0, 0, 0, jst)

	sess := &idproxy.Session{
		ID:        "utc-test-session",
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	if err := s.SetSession(ctx, sess.ID, sess, 24*time.Hour); err != nil {
		t.Fatalf("SetSession() error = %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSession() = nil, want session")
	}

	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt.Location() = %v, want UTC", got.CreatedAt.Location())
	}
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt.Location() = %v, want UTC", got.ExpiresAt.Location())
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt = %v, want %v (same instant)", got.CreatedAt, createdAt)
	}
}

// UTC02: SetAuthCode に非 UTC time.Time を渡すと、取得後の time.Time が UTC であること
func TestDynamoDBStore_UTC02_AuthCode_TimeNormalized(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	createdAt := time.Date(2025, 6, 1, 12, 0, 0, 0, jst)
	expiresAt := time.Date(2025, 6, 1, 12, 10, 0, 0, jst)

	data := &idproxy.AuthCodeData{
		Code:      "utc-test-code",
		ClientID:  "client-1",
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	if err := s.SetAuthCode(ctx, data.Code, data, 10*time.Minute); err != nil {
		t.Fatalf("SetAuthCode() error = %v", err)
	}

	got, err := s.GetAuthCode(ctx, data.Code)
	if err != nil {
		t.Fatalf("GetAuthCode() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthCode() = nil, want data")
	}

	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt.Location() = %v, want UTC", got.CreatedAt.Location())
	}
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt.Location() = %v, want UTC", got.ExpiresAt.Location())
	}
}

// UTC03: SetAccessToken に非 UTC time.Time を渡すと、取得後の time.Time が UTC であること
func TestDynamoDBStore_UTC03_AccessToken_TimeNormalized(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	issuedAt := time.Date(2025, 6, 1, 12, 0, 0, 0, jst)
	expiresAt := time.Date(2025, 6, 1, 13, 0, 0, 0, jst)

	data := &idproxy.AccessTokenData{
		JTI:       "utc-test-jti",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}

	if err := s.SetAccessToken(ctx, data.JTI, data, time.Hour); err != nil {
		t.Fatalf("SetAccessToken() error = %v", err)
	}

	got, err := s.GetAccessToken(ctx, data.JTI)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessToken() = nil, want data")
	}

	if got.IssuedAt.Location() != time.UTC {
		t.Errorf("IssuedAt.Location() = %v, want UTC", got.IssuedAt.Location())
	}
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt.Location() = %v, want UTC", got.ExpiresAt.Location())
	}
}

// UTC04: SetClient に非 UTC time.Time を渡すと、取得後の time.Time が UTC であること
func TestDynamoDBStore_UTC04_Client_TimeNormalized(t *testing.T) {
	s, _ := newTestDynamoDBStore(nil)
	ctx := context.Background()

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	createdAt := time.Date(2025, 6, 1, 12, 0, 0, 0, jst)

	data := &idproxy.ClientData{
		ClientID:  "utc-test-client",
		CreatedAt: createdAt,
	}

	if err := s.SetClient(ctx, data.ClientID, data); err != nil {
		t.Fatalf("SetClient() error = %v", err)
	}

	got, err := s.GetClient(ctx, data.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetClient() = nil, want data")
	}

	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt.Location() = %v, want UTC", got.CreatedAt.Location())
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt = %v, want %v (same instant)", got.CreatedAt, createdAt)
	}
}
