package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/types"
)

func TestAPIKeyGenerateAndHash(t *testing.T) {
	t.Parallel()

	key1 := core.GenerateAPIKey()
	key2 := core.GenerateAPIKey()

	if !strings.HasPrefix(key1, core.APIKeyPrefix) {
		t.Fatalf("Expected key to have %q prefix, got %q", core.APIKeyPrefix, key1)
	}
	if len(key1) != len(core.APIKeyPrefix)+40 {
		t.Fatalf("Expected key length %d, got %d", len(core.APIKeyPrefix)+40, len(key1))
	}
	if key1 == key2 {
		t.Fatal("Expected two generated keys to differ")
	}

	h1 := core.HashAPIKey(key1)
	if len(h1) != 64 {
		t.Fatalf("Expected 64 chars hex digest, got %d", len(h1))
	}
	if h1 == key1 {
		t.Fatal("The digest must not match the plaintext")
	}
	// determinism and normalization (whitespace)
	if h1 != core.HashAPIKey("  "+key1+"\n") {
		t.Fatal("Expected whitespace trimmed before hashing")
	}
	if !core.EqualKeyHash(h1, key1) {
		t.Fatal("Expected EqualKeyHash to match")
	}
	if core.EqualKeyHash(h1, key2) {
		t.Fatal("Expected EqualKeyHash to reject a different key")
	}
	if !core.IsAPIKeyToken(key1) {
		t.Fatal("Expected IsAPIKeyToken to recognize the generated key")
	}
	if core.IsAPIKeyToken("eyJhbGciOiJIUzI1NiJ9.something") {
		t.Fatal("JWT-like token must not be recognized as API key")
	}
}

func TestAPIKeyHasExpiredClockBoundary(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	now := time.Now()

	key := core.NewAPIKey(app)

	// no expiration -> never expires
	if key.HasExpired(now) {
		t.Fatal("Key without expiration must not be expired")
	}

	expires := types.NowDateTime()
	key.SetExpiresAt(expires)

	// strictly before the boundary -> still valid
	if key.HasExpired(expires.Time().Add(-time.Nanosecond)) {
		t.Fatal("Expected key to be valid an instant before expiration")
	}

	// AT the boundary -> expired (inclusive boundary)
	if !key.HasExpired(expires.Time()) {
		t.Fatal("Expected key to be expired exactly at the expiration boundary")
	}

	// after -> expired
	if !key.HasExpired(expires.Time().Add(time.Second)) {
		t.Fatal("Expected key to be expired after expiration")
	}
}

func TestAPIKeyCanAccess(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	key := core.NewAPIKey(app)

	// no scopes -> nothing
	if key.CanAccess("col1", "demo1", "view") {
		t.Fatal("Key without scopes must not allow anything")
	}

	key.SetScopes([]string{"demo1/view", "*/delete"})

	cases := []struct {
		colID, colName, action string
		expect                 bool
	}{
		{"wsmn24bux7wo113", "demo1", "view", true},   // match by id
		{"wsmn24bux7wo113", "demo1", "delete", true}, // wildcard collection
		{"other-id", "demo1", "view", true},          // match by name
		{"wsmn24bux7wo113", "demo1", "create", false},
		{"x", "demo2", "view", false},
		{"x", "demo2", "delete", true},
	}

	for _, c := range cases {
		got := key.CanAccess(c.colID, c.colName, c.action)
		if got != c.expect {
			t.Fatalf("%s/%s %s: expected %v, got %v", c.colName, c.colID, c.action, c.expect, got)
		}
	}

	// wildcard action
	key.SetScopes([]string{"demo1/*"})
	if !key.CanAccess("x", "demo1", "create") {
		t.Fatal("Expected wildcard action to match")
	}

	// malformed entries are ignored
	key.SetScopes([]string{"garbage", "demo1"})
	if key.CanAccess("x", "demo1", "view") {
		t.Fatal("Malformed scopes must be ignored")
	}
}

func TestAPIKeyCRUDAndRevoke(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetName("ci job")
	key.SetScopes([]string{"*/view"})
	plaintext := key.GenerateKey()

	if err := app.Save(key); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}
	if key.Id == "" {
		t.Fatal("Expected key to have an id after save")
	}

	// resolve by plaintext
	resolved, err := app.FindAPIKeyByToken(plaintext)
	if err != nil {
		t.Fatalf("Expected to resolve the key by token, got %v", err)
	}
	if resolved.Id != key.Id {
		t.Fatalf("Resolved id mismatch %q != %q", resolved.Id, key.Id)
	}
	if resolved.KeyHash() == plaintext {
		t.Fatal("The persisted value must not be the plaintext key")
	}

	// hash lookup
	resolved2, err := app.FindAPIKeyByHash(core.HashAPIKey(plaintext))
	if err != nil || resolved2.Id != key.Id {
		t.Fatalf("FindAPIKeyByHash failed: %v", err)
	}

	// unknown key
	if _, err := app.FindAPIKeyByToken(core.GenerateAPIKey()); err == nil {
		t.Fatal("Expected error for unknown API key")
	}
	if _, err := app.FindAPIKeyByToken("not-an-api-key"); err == nil {
		t.Fatal("Expected error for non-API-key token")
	}

	// revoke (delete)
	if err := app.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAPIKeyByToken(plaintext); err == nil {
		t.Fatal("Revoked key must not resolve")
	}
	if _, err := app.FindAPIKeyById(key.Id); err == nil {
		t.Fatal("Revoked key must not be found by id")
	}
}

func TestAPIKeyExpiredLookup(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetName("expired job")
	key.SetScopes([]string{"*/view"})
	key.SetExpiresAt(types.NowDateTime().Add(-time.Minute))
	plaintext := key.GenerateKey()

	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindAPIKeyByToken(plaintext); err == nil {
		t.Fatal("Expired key must not resolve as active")
	}

	// it still exists in the table (cleanup happens via the cron job)
	if _, err := app.FindAPIKeyById(key.Id); err != nil {
		t.Fatalf("Expired key should still exist until cleanup, got %v", err)
	}

	if err := app.DeleteExpiredAPIKeys(); err != nil {
		t.Fatalf("DeleteExpiredAPIKeys failed: %v", err)
	}
	if _, err := app.FindAPIKeyById(key.Id); err == nil {
		t.Fatal("Expected expired key to be deleted by cleanup")
	}
}

func TestAPIKeyCascadeOnRecordDelete(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	user, err := app.FindFirstRecordByData("users", "email", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	key := core.NewAPIKey(app)
	key.SetName("user-bound")
	key.SetScopes([]string{"*/view"})
	key.SetCollectionRef(user.Collection().Id)
	key.SetRecordRef(user.Id)
	key.GenerateKey()
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	if err := app.Delete(user); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindAPIKeyById(key.Id); err == nil {
		t.Fatal("Expected the key to be cascade deleted with the linked record")
	}
}

func TestTouchAPIKey(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetName("touch")
	key.SetScopes([]string{"*/view"})
	key.GenerateKey()
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	if !key.LastUsedAt().IsZero() {
		t.Fatal("Expected zero lastUsedAt on new key")
	}

	if err := app.TouchAPIKey(key, "203.0.113.7"); err != nil {
		t.Fatalf("TouchAPIKey failed: %v", err)
	}

	refreshed, err := app.FindAPIKeyById(key.Id)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.LastUsedAt().IsZero() {
		t.Fatal("Expected lastUsedAt to be updated")
	}
	if refreshed.LastUsedByIP() != "203.0.113.7" {
		t.Fatalf("Expected lastUsedByIP to be set, got %q", refreshed.LastUsedByIP())
	}
}
