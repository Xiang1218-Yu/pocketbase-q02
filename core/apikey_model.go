package core

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

const CollectionNameAPIKeys = "_apiKeys"

// APIKeySupportedActions contains all valid API key scope actions.
//
// The action names follow the CRUD naming of the record API rules
// (list/view/create/update/delete) plus "file" for the protected
// files download route.
var APIKeySupportedActions = []string{
	"list",
	"view",
	"create",
	"update",
	"delete",
	"file",
}

// APIKeyPrefix is the fixed prefix of every plaintext API key.
//
// It exists so that keys are easily recognizable by humans (and scanners)
// and so that the Authorization header can be cheaply distinguished
// from a regular JWT auth token.
const APIKeyPrefix = "pbak_"

const (
	apiKeySecretLength = 40
	apiKeyHashLength   = sha256.Size * 2 // hex encoded sha256 digest
)

// ErrAPIKeyInvalid is returned when an API key cannot be resolved
// (unknown key, revoked/deleted or invalid format).
var ErrAPIKeyInvalid = errors.New("invalid or revoked API key")

// ErrAPIKeyExpired is returned when a resolvable API key is past its
// explicit expiration time.
var ErrAPIKeyExpired = errors.New("expired API key")

var (
	_ Model        = (*APIKey)(nil)
	_ PreValidator = (*APIKey)(nil)
	_ RecordProxy  = (*APIKey)(nil)
)

// APIKey defines a Record proxy for working with the _apiKeys collection.
//
// The plaintext key is never stored - only its SHA-256 hex digest is
// persisted in the "keyHash" system field and it is hidden from API responses.
type APIKey struct {
	*Record
}

// NewAPIKey instantiates and returns a new blank *APIKey model.
func NewAPIKey(app App) *APIKey {
	m := &APIKey{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameAPIKeys)
	if err != nil {
		// this is just to make tests easier since _apiKeys is a system
		// collection and it is expected to be always accessible
		// (note: the loaded record is further checked on APIKey.PreValidate())
		c = NewBaseCollection("@___invalid___")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *APIKey) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameAPIKeys {
		return errors.New("missing or invalid APIKey ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *APIKey) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *APIKey) SetProxyRecord(record *Record) {
	m.Record = record
}

// Name returns the user defined "name" field value.
func (m *APIKey) Name() string {
	return m.GetString("name")
}

// SetName updates the "name" field value.
func (m *APIKey) SetName(name string) {
	m.Set("name", name)
}

// KeyHash returns the persisted irreversible key digest.
func (m *APIKey) KeyHash() string {
	return m.GetString("keyHash")
}

// SetKeyHash updates the persisted irreversible key digest.
func (m *APIKey) SetKeyHash(hash string) {
	m.Set("keyHash", hash)
}

// CollectionRef returns the id of the collection the key is scoped to
// (empty string means all collections).
func (m *APIKey) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the scoped collection id.
//
// Pass an empty string to allow all collections.
func (m *APIKey) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// RecordRef returns the id of the auth record the key acts as
// (empty string means guest access).
func (m *APIKey) RecordRef() string {
	return m.GetString("recordRef")
}

// SetRecordRef updates the linked auth record id.
//
// Pass an empty string for guest scoped keys.
func (m *APIKey) SetRecordRef(recordId string) {
	m.Set("recordRef", recordId)
}

// Scopes returns the normalized list of "collection/action" permission entries.
//
// The "*" wildcard is supported for either the collection or the action part,
// e.g. "*/*", "users/view", "*/delete".
func (m *APIKey) Scopes() []string {
	return m.GetStringSlice("scopes")
}

// SetScopes replaces the key scopes.
func (m *APIKey) SetScopes(scopes []string) {
	m.Set("scopes", scopes)
}

// ExpiresAt returns the key expiration time.
//
// It returns zero time if the key doesn't expire.
func (m *APIKey) ExpiresAt() types.DateTime {
	return m.GetDateTime("expiresAt")
}

// SetExpiresAt updates the key expiration time.
//
// Pass a zero time to create a key without expiration.
func (m *APIKey) SetExpiresAt(dt types.DateTime) {
	m.Set("expiresAt", dt)
}

// LastUsedAt returns the last successful authentication time.
func (m *APIKey) LastUsedAt() types.DateTime {
	return m.GetDateTime("lastUsedAt")
}

// SetLastUsedAt updates the last successful authentication time.
func (m *APIKey) LastUsedByIP() string {
	return m.GetString("lastUsedByIP")
}

// SetLastUsedByIP updates the IP of the last successful authentication.
func (m *APIKey) SetLastUsedByIP(ip string) {
	m.Set("lastUsedByIP", ip)
}

// Created returns the "created" record field value.
func (m *APIKey) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *APIKey) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

// HasExpired reports whether the key is expired at the provided time.
//
// Keys without expiration (zero ExpiresAt) never expire.
//
// The boundary is inclusive: a key with ExpiresAt == t is considered
// expired (the credential is valid for instant t' where t' < ExpiresAt).
func (m *APIKey) HasExpired(t time.Time) bool {
	exp := m.ExpiresAt()
	if exp.IsZero() {
		return false
	}

	return !t.Before(exp.Time())
}

// CanAccess reports whether the key scope allows the specified action
// on the specified collection (matched by collection id and name).
//
// "*" passed as collectionName means that the check is performed outside
// of a collection context (in that case only "* / action" or "*/*" scopes match).
func (m *APIKey) CanAccess(collectionId, collectionName, action string) bool {
	for _, scope := range m.Scopes() {
		scopeCollection, scopeAction, ok := strings.Cut(scope, "/")
		if !ok {
			continue
		}

		if scopeAction != "*" && scopeAction != action {
			continue
		}

		if scopeCollection == "*" {
			return true
		}

		if scopeCollection != "" &&
			(scopeCollection == collectionId || scopeCollection == collectionName) {
			return true
		}
	}

	return false
}

// SetPlaintextKey sets the "keyHash" field from the provided plaintext key.
//
// The plaintext value is not retained.
func (m *APIKey) SetPlaintextKey(plaintext string) {
	m.SetKeyHash(HashAPIKey(plaintext))
}

// GenerateKey creates a new plaintext API key and populates the model's keyHash.
//
// It returns the generated plaintext key that must be shown to the user
// only once (it cannot be recovered afterwards).
func (m *APIKey) GenerateKey() string {
	plaintext := GenerateAPIKey()
	m.SetPlaintextKey(plaintext)
	return plaintext
}

// GenerateAPIKey generates a new plaintext API key (without persisting it anywhere).
func GenerateAPIKey() string {
	return APIKeyPrefix + security.RandomString(apiKeySecretLength)
}

// HashAPIKey returns the irreversible SHA-256 hex digest of the provided key.
//
// The raw key is normalized (trimmed whitespace) before hashing.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plaintext)))
	return hex.EncodeToString(sum[:])
}

// IsAPIKeyToken checks if the provided token has the API key prefix format.
func IsAPIKeyToken(token string) bool {
	return strings.HasPrefix(token, APIKeyPrefix)
}

// EqualKeyHash performs a constant time comparison between a key hash and
// the hash of a plaintext key.
func EqualKeyHash(keyHash, plaintext string) bool {
	plainHash := HashAPIKey(plaintext)
	return subtle.ConstantTimeCompare([]byte(keyHash), []byte(plainHash)) == 1
}

func (app *BaseApp) registerAPIKeyHooks() {
	// revoke (cascade delete) keys linked to a deleted auth record
	app.OnRecordDeleteExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			originalApp := e.App

			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				if e.Record.Collection().IsAuth() {
					if err := txApp.DeleteAllAPIKeysByRecord(e.Record); err != nil {
						return err
					}
				}

				return nil
			})
			e.App = originalApp

			return txErr
		},
		Priority: 99,
	})

	// revoke the keys linked to an auth record on tokenKey change
	// (e.g. password change) to minimize the risk of stale/hijacked credentials
	app.OnRecordUpdateExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			err := e.Next()
			if err != nil || !e.Record.Collection().IsAuth() {
				return err
			}

			if !e.Record.Original().IsNew() && e.Record.Original().TokenKey() != e.Record.TokenKey() {
				if delErr := e.App.DeleteAllAPIKeysByRecord(e.Record); delErr != nil {
					e.App.Logger().Warn(
						"Failed to revoke API keys after auth record tokenKey change",
						"error", delErr,
						"recordId", e.Record.Id,
						"collectionId", e.Record.Collection().Id,
					)
				}
			}

			return nil
		},
		Priority: 99,
	})

	// invalidate/cascade related realtime clients on key delete (revocation)
	app.OnRecordAfterDeleteSuccess(CollectionNameAPIKeys).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			disconnectAPIKeyClients(e.App, e.Record.Id)
			return e.Next()
		},
		Priority: -99,
	})
}
