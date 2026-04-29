package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/youyo/idproxy/store"
	sqlitestore "github.com/youyo/idproxy/store/sqlite"
)

func TestLoadStore_DefaultMemory(t *testing.T) {
	t.Setenv("STORE_BACKEND", "")
	s, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, ok := s.(*store.MemoryStore); !ok {
		t.Errorf("expected MemoryStore, got %T", s)
	}
}

func TestLoadStore_Memory(t *testing.T) {
	t.Setenv("STORE_BACKEND", "memory")
	s, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	_ = s.Close()
}

func TestLoadStore_SQLite(t *testing.T) {
	t.Setenv("STORE_BACKEND", "sqlite")
	t.Setenv("SQLITE_PATH", filepath.Join(t.TempDir(), "store.db"))
	s, err := loadStore()
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, ok := s.(*sqlitestore.Store); !ok {
		t.Errorf("expected sqlite Store, got %T", s)
	}
}

func TestLoadStore_DynamoDBMissingEnv(t *testing.T) {
	t.Setenv("STORE_BACKEND", "dynamodb")
	t.Setenv("DYNAMODB_TABLE_NAME", "")
	_, err := loadStore()
	if err == nil || !strings.Contains(err.Error(), "DYNAMODB_TABLE_NAME") {
		t.Errorf("expected DYNAMODB_TABLE_NAME error, got %v", err)
	}
}

func TestLoadStore_RedisMissingAddr(t *testing.T) {
	t.Setenv("STORE_BACKEND", "redis")
	t.Setenv("REDIS_ADDR", "")
	_, err := loadStore()
	if err == nil || !strings.Contains(err.Error(), "REDIS_ADDR") {
		t.Errorf("expected REDIS_ADDR error, got %v", err)
	}
}

func TestLoadStore_RedisInvalidDB(t *testing.T) {
	t.Setenv("STORE_BACKEND", "redis")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("REDIS_DB", "abc")
	_, err := loadStore()
	if err == nil || !strings.Contains(err.Error(), "REDIS_DB") {
		t.Errorf("expected REDIS_DB error, got %v", err)
	}
}

func TestLoadStore_Unknown(t *testing.T) {
	t.Setenv("STORE_BACKEND", "wat")
	_, err := loadStore()
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected unsupported error, got %v", err)
	}
}
