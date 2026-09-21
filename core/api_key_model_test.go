package core_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestNewAPIKey(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)

	if key.Collection().Name != core.CollectionNameAPIKeys {
		t.Fatalf("Expected record with %q collection, got %q", core.CollectionNameAPIKeys, key.Collection().Name)
	}
}

func TestGenerateAPIKeySecret(t *testing.T) {
	t.Parallel()

	a, err := core.GenerateAPIKeySecret()
	if err != nil {
		t.Fatal(err)
	}

	b, err := core.GenerateAPIKeySecret()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(a, core.APIKeyPrefix) {
		t.Fatalf("Expected key to start with %q, got %q", core.APIKeyPrefix, a)
	}

	if a == b {
		t.Fatal("Expected two generated keys to be different")
	}

	expectedLen := len(core.APIKeyPrefix) + core.APIKeySecretLength
	if len(a) != expectedLen {
		t.Fatalf("Expected key length %d, got %d", expectedLen, len(a))
	}
}

func TestAPIKeySetAndVerifySecret(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetName("test")
	key.SetScopes([]string{"*:*"})

	plaintext, err := key.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}

	if !key.VerifySecret(plaintext) {
		t.Fatal("Expected the plaintext key to match the stored digest")
	}

	if key.VerifySecret(plaintext + "x") {
		t.Fatal("Expected a tampered key not to match")
	}

	if key.VerifySecret("") {
		t.Fatal("Expected empty key not to match")
	}

	// secret material must never be stored
	for _, field := range []string{"keyHash", "keySalt"} {
		if strings.Contains(key.GetString(field), plaintext) {
			t.Fatalf("The plaintext key leaked into %s", field)
		}
	}

	// two keys with the same plaintext must have different digests (different salts)
	other := core.NewAPIKey(app)
	if err := other.SetSecret(plaintext); err != nil {
		t.Fatal(err)
	}
	if other.KeyHash() == key.KeyHash() {
		t.Fatal("Expected different salts to produce different hashes")
	}
}

func TestAPIKeySecretPrefix(t *testing.T) {
	t.Parallel()

	plaintext, err := core.GenerateAPIKeySecret()
	if err != nil {
		t.Fatal(err)
	}

	prefix := core.APIKeySecretPrefix(plaintext)
	if len(prefix) != core.APIKeyPrefixLength {
		t.Fatalf("Expected prefix length %d, got %d", core.APIKeyPrefixLength, len(prefix))
	}

	if core.APIKeySecretPrefix("invalid") != "" {
		t.Fatal("Expected empty prefix for invalid key format")
	}
}

func TestParseAPIKeyScope(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		scope      string
		collection string
		action     string
		ok         bool
	}{
		{"posts:view", "posts", "view", true},
		{"  posts : view ", "posts", "view", true},
		{"*:*", "*", "*", true},
		{"*:list", "*", "list", true},
		{"posts:unknown", "", "", false},
		{"posts", "", "", false},
		{":view", "", "", false},
		{"posts:", "", "", false},
		{"", "", "", false},
	}

	for _, s := range scenarios {
		t.Run(s.scope, func(t *testing.T) {
			c, a, ok := core.ParseAPIKeyScope(s.scope)
			if ok != s.ok {
				t.Fatalf("Expected ok %v, got %v", s.ok, ok)
			}
			if ok && (c != s.collection || a != s.action) {
				t.Fatalf("Expected (%q,%q), got (%q,%q)", s.collection, s.action, c, a)
			}
		})
	}
}

func TestAPIKeyCanAccess(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	posts, err := app.FindCachedCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}

	demo2, err := app.FindCachedCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	key := core.NewAPIKey(app)

	// no scopes
	if key.CanAccess(posts, "view") {
		t.Fatal("Expected key without scopes to have no access")
	}

	key.SetScopes([]string{"demo1:view", "demo1:list"})

	if !key.CanAccess(posts, "view") {
		t.Fatal("Expected access to demo1:view")
	}
	if key.CanAccess(posts, "create") {
		t.Fatal("Expected no access to demo1:create")
	}
	if key.CanAccess(demo2, "view") {
		t.Fatal("Expected no access to demo2:view")
	}

	// collection id should work too
	key.SetScopes([]string{posts.Id + ":delete"})
	if !key.CanAccess(posts, "delete") {
		t.Fatal("Expected access via collection id")
	}

	// wildcard collection
	key.SetScopes([]string{"*:view"})
	if !key.CanAccess(demo2, "view") {
		t.Fatal("Expected wildcard collection access")
	}
	if key.CanAccess(demo2, "delete") {
		t.Fatal("Expected wildcard collection to apply only to the specified action")
	}

	// wildcard action
	key.SetScopes([]string{"demo1:*"})
	for _, action := range core.APIKeyAllActions {
		if !key.CanAccess(posts, action) {
			t.Fatalf("Expected wildcard action access for %s", action)
		}
	}
	if key.CanAccess(demo2, "view") {
		t.Fatal("Expected wildcard action to be scoped to demo1 only")
	}

	// invalid scope entries are ignored
	key.SetScopes([]string{"garbage", "demo1:view"})
	if !key.CanAccess(posts, "view") {
		t.Fatal("Expected valid scope to work alongside invalid ones")
	}

	if key.CanAccess(nil, "view") {
		t.Fatal("Expected no access to nil collection")
	}
}

func TestAPIKeyExpirationAndRevocation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetScopes([]string{"*:*"})

	now := time.Now()

	// non-expiring, non-revoked
	if key.IsExpired(now) {
		t.Fatal("Expected fresh key to not be expired")
	}
	if key.IsRevoked() {
		t.Fatal("Expected fresh key to not be revoked")
	}
	if !key.IsActive(now) {
		t.Fatal("Expected fresh key to be active")
	}

	// expiration clock boundary:
	// IsExpired is defined as !now.Before(expires), i.e. expires <= now
	expires := now.Add(time.Hour)
	key.SetExpires(expires)

	if key.IsExpired(expires.Add(-time.Nanosecond)) {
		t.Fatal("Expected key to be active 1ns before expiration")
	}
	if !key.IsExpired(expires) {
		t.Fatal("Expected key to be considered expired exactly at the expiration time")
	}
	if !key.IsExpired(expires.Add(time.Second)) {
		t.Fatal("Expected key to be expired after the expiration time")
	}
	if key.IsActive(expires) {
		t.Fatal("Expected inactive key at the expiration boundary")
	}

	// clear expiration
	key.SetExpires(time.Time{})
	if key.IsExpired(now) {
		t.Fatal("Expected cleared expiration to not be expired")
	}

	// revocation
	if key.IsRevoked() {
		t.Fatal("Expected not revoked initially")
	}
	key.SetRevokedAt(now)
	if !key.IsRevoked() {
		t.Fatal("Expected revoked after SetRevokedAt")
	}
	if key.IsActive(now) {
		t.Fatal("Expected revoked key to not be active")
	}
	key.SetRevokedAt(time.Time{})
	if key.IsRevoked() {
		t.Fatal("Expected un-revoke to clear the revocation time")
	}
}

func TestAPIKeyValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCachedCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	userRecord, err := app.FindFirstRecordByData(users, "email", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name      string
		key       func() *core.APIKey
		expectErr bool
	}{
		{
			name: "valid guest key",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k1")
				key.SetScopes([]string{"*:*"})
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: false,
		},
		{
			name: "valid owner-bound key",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k2")
				key.SetScopes([]string{"users:view"})
				key.SetOwnerCollectionRef(users.Id)
				key.SetOwnerRecordRef(userRecord.Id)
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: false,
		},
		{
			name: "missing name",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetScopes([]string{"*:*"})
				return key
			},
			expectErr: true,
		},
		{
			name: "empty scopes",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k3")
				key.SetScopes(nil)
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: true,
		},
		{
			name: "invalid scope entry",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k4")
				key.SetScopes([]string{"bogus"})
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: true,
		},
		{
			name: "system collection scope",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k5")
				key.SetScopes([]string{"_superusers:view"})
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: true,
		},
		{
			name: "missing secret data",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k6")
				key.SetScopes([]string{"*:*"})
				return key
			},
			expectErr: true,
		},
		{
			name: "nonexistent owner record",
			key: func() *core.APIKey {
				key := core.NewAPIKey(app)
				key.SetName("k7")
				key.SetScopes([]string{"*:*"})
				key.SetOwnerCollectionRef(users.Id)
				key.SetOwnerRecordRef("missing")
				if _, err := key.GenerateSecret(); err != nil {
					t.Fatal(err)
				}
				return key
			},
			expectErr: true,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			key := s.key()
			err := app.Save(key)
			hasErr := err != nil
			if hasErr != s.expectErr {
				t.Fatalf("Expected error %v, got %v (%v)", s.expectErr, hasErr, err)
			}
		})
	}
}

func TestAPIKeyDuplicateName(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	create := func() *core.APIKey {
		key := core.NewAPIKey(app)
		key.SetName("duplicate-name")
		key.SetScopes([]string{"*:*"})
		if _, err := key.GenerateSecret(); err != nil {
			t.Fatal(err)
		}
		return key
	}

	if err := app.Save(create()); err != nil {
		t.Fatalf("Expected first save to succeed, got %v", err)
	}

	if err := app.Save(create()); err == nil {
		t.Fatal("Expected second save with the same name to fail")
	}
}

func TestAPIKeyOwnerCascadeDelete(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCachedCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	userRecord, err := app.FindFirstRecordByData(users, "email", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	key := core.NewAPIKey(app)
	key.SetName("cascade-key")
	key.SetScopes([]string{"*:*"})
	key.SetOwnerCollectionRef(users.Id)
	key.SetOwnerRecordRef(userRecord.Id)
	if _, err := key.GenerateSecret(); err != nil {
		t.Fatal(err)
	}
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	// delete the owner record
	if err := app.Delete(userRecord); err != nil {
		t.Fatal(err)
	}

	keys, err := app.FindAllAPIKeysByRecord(userRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected the owner's api keys to be cascade-deleted, found %d", len(keys))
	}
}

func TestFindAPIKeyBySecret(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetName("lookup")
	key.SetScopes([]string{"*:*"})
	plaintext, err := key.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	// correct secret
	found, err := app.FindAPIKeyBySecret(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil || found.Id != key.Id {
		t.Fatal("Expected to find the key by its plaintext")
	}

	// wrong secret
	found, err = app.FindAPIKeyBySecret(plaintext + "x")
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Fatal("Expected no key for a wrong secret")
	}

	// malformed
	found, err = app.FindAPIKeyBySecret("nope")
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Fatal("Expected no key for a malformed secret")
	}
}

func TestAPIKeyAllActionsComplete(t *testing.T) {
	t.Parallel()

	expected := []string{"list", "view", "create", "update", "delete"}
	if !slices.Equal(core.APIKeyAllActions, expected) {
		t.Fatalf("Expected %v, got %v", expected, core.APIKeyAllActions)
	}
}
