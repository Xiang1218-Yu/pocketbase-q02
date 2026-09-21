package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/types"
)

var (
	_ Model        = (*APIKey)(nil)
	_ PreValidator = (*APIKey)(nil)
	_ RecordProxy  = (*APIKey)(nil)
)

const CollectionNameAPIKeys = "_apiKeys"

const (
	// APIKeyPrefix is the fixed prefix of every plaintext API key.
	//
	// It allows cheap recognition of the credential type by the auth
	// middleware (and accidental scanning in code bases).
	APIKeyPrefix = "pb_ak_"

	// APIKeySecretLength is the length (excluding the prefix) of the
	// randomly generated key secret.
	APIKeySecretLength = 40

	// APIKeyPrefixLength is the length of the non-secret identifier
	// part stored in the "keyPrefix" field and used for indexed lookup.
	APIKeyPrefixLength = 12
)

// API key CRUD action identifiers used in the scopes entries.
const (
	APIKeyActionList   = "list"
	APIKeyActionView   = "view"
	APIKeyActionCreate = "create"
	APIKeyActionUpdate = "update"
	APIKeyActionDelete = "delete"
)

// APIKeyAllActions is the list with all API key action identifiers.
var APIKeyAllActions = []string{
	APIKeyActionList,
	APIKeyActionView,
	APIKeyActionCreate,
	APIKeyActionUpdate,
	APIKeyActionDelete,
}

// APIKeyWildcard is the wildcard value for scope collection/action parts.
const APIKeyWildcard = "*"

// APIKey is a Record proxy for working with the _apiKeys system collection.
type APIKey struct {
	*Record
}

// NewAPIKey instantiates and returns a new blank *APIKey model.
func NewAPIKey(app App) *APIKey {
	m := &APIKey{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameAPIKeys)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on APIKey.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the PreValidator interface and checks
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

// Name returns the human readable identifier of the key.
func (m *APIKey) Name() string {
	return m.GetString("name")
}

// SetName updates the human readable identifier of the key.
func (m *APIKey) SetName(name string) {
	m.Set("name", name)
}

// KeyPrefix returns the non-secret prefix used for indexed lookup.
func (m *APIKey) KeyPrefix() string {
	return m.GetString("keyPrefix")
}

func (m *APIKey) setKeyPrefix(prefix string) {
	m.Set("keyPrefix", prefix)
}

// KeyHash returns the salted SHA-256 digest of the plaintext key.
func (m *APIKey) KeyHash() string {
	return m.GetString("keyHash")
}

func (m *APIKey) setKeyHash(hash string) {
	m.Set("keyHash", hash)
}

// KeySalt returns the per-key random salt used for the digest.
func (m *APIKey) KeySalt() string {
	return m.GetString("keySalt")
}

func (m *APIKey) setKeySalt(salt string) {
	m.Set("keySalt", salt)
}

// Scopes returns the collection/action scope entries of the key.
func (m *APIKey) Scopes() []string {
	return m.GetStringSlice("scopes")
}

// SetScopes replaces the collection/action scope entries of the key.
func (m *APIKey) SetScopes(scopes []string) {
	if scopes == nil {
		scopes = []string{}
	}
	m.Set("scopes", scopes)
}

// OwnerRecordRef returns the id of the bound auth record (if any).
//
// An empty value means that the key authenticates as guest.
func (m *APIKey) OwnerRecordRef() string {
	return m.GetString("ownerRecordRef")
}

// SetOwnerRecordRef binds the key to the provided auth record id
// (use empty string to mark it as a guest key).
func (m *APIKey) SetOwnerRecordRef(recordId string) {
	m.Set("ownerRecordRef", recordId)
}

// OwnerCollectionRef returns the collection id of the bound auth record (if any).
func (m *APIKey) OwnerCollectionRef() string {
	return m.GetString("ownerCollectionRef")
}

// SetOwnerCollectionRef updates the collection id of the bound auth record.
func (m *APIKey) SetOwnerCollectionRef(collectionId string) {
	m.Set("ownerCollectionRef", collectionId)
}

// Expires returns the expiration time of the key.
//
// It returns zero time if the key doesn't expire.
func (m *APIKey) Expires() time.Time {
	return m.GetDateTime("expires").Time()
}

// SetExpires sets the key expiration time (use zero time to create a non-expiring key).
func (m *APIKey) SetExpires(t time.Time) {
	if t.IsZero() {
		m.Set("expires", types.DateTime{})
	} else {
		dt, _ := types.ParseDateTime(t.UTC())
		m.Set("expires", dt)
	}
}

// LastUsedAt returns the last successful authentication time with the key.
func (m *APIKey) LastUsedAt() time.Time {
	return m.GetDateTime("lastUsedAt").Time()
}

func (m *APIKey) setLastUsedAt(t time.Time) {
	if t.IsZero() {
		m.Set("lastUsedAt", types.DateTime{})
	} else {
		dt, _ := types.ParseDateTime(t.UTC())
		m.Set("lastUsedAt", dt)
	}
}

// RevokedAt returns the revocation time of the key.
//
// It returns zero time if the key is still active.
func (m *APIKey) RevokedAt() time.Time {
	return m.GetDateTime("revokedAt").Time()
}

// SetRevokedAt sets the revocation time (use zero time to un-revoke).
func (m *APIKey) SetRevokedAt(t time.Time) {
	if t.IsZero() {
		m.Set("revokedAt", types.DateTime{})
	} else {
		dt, _ := types.ParseDateTime(t.UTC())
		m.Set("revokedAt", dt)
	}
}

// IsRevoked reports whether the key has been revoked.
func (m *APIKey) IsRevoked() bool {
	return !m.RevokedAt().IsZero()
}

// IsExpired reports whether the key has expired at time now.
func (m *APIKey) IsExpired(now time.Time) bool {
	expires := m.Expires()
	return !expires.IsZero() && !now.Before(expires)
}

// IsActive reports whether the key is neither revoked nor expired at time now.
func (m *APIKey) IsActive(now time.Time) bool {
	return !m.IsRevoked() && !m.IsExpired(now)
}

// GenerateSecret generates and sets the keyPrefix, keySalt and keyHash
// fields from a freshly generated random plaintext key.
//
// It returns the plaintext key which is meant to be shown to the user only once.
func (m *APIKey) GenerateSecret() (string, error) {
	secret, err := GenerateAPIKeySecret()
	if err != nil {
		return "", err
	}

	if err := m.SetSecret(secret); err != nil {
		return "", err
	}

	return secret, nil
}

// SetSecret computes and stores the keyPrefix, keySalt and keyHash
// for the provided plaintext key.
func (m *APIKey) SetSecret(plaintext string) error {
	if !strings.HasPrefix(plaintext, APIKeyPrefix) {
		return errors.New("invalid api key format")
	}

	salt, err := randomHex(16)
	if err != nil {
		return err
	}

	m.setKeySalt(salt)
	m.setKeyPrefix(APIKeySecretPrefix(plaintext))
	m.setKeyHash(HashAPIKeySecret(salt, plaintext))

	return nil
}

// VerifySecret reports whether the provided plaintext key matches
// the stored salted digest in constant time.
func (m *APIKey) VerifySecret(plaintext string) bool {
	if plaintext == "" || m.KeyHash() == "" || m.KeySalt() == "" {
		return false
	}

	expected, _ := hex.DecodeString(m.KeyHash())
	actual, _ := hex.DecodeString(HashAPIKeySecret(m.KeySalt(), plaintext))

	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// CanAccess reports whether the key scope allows the provided action
// on the specified collection.
//
// Both the collection name and collection id are checked.
func (m *APIKey) CanAccess(collection *Collection, action string) bool {
	if collection == nil {
		return false
	}

	for _, scope := range m.Scopes() {
		scopeCollection, scopeAction, ok := ParseAPIKeyScope(scope)
		if !ok {
			continue
		}

		if scopeAction != APIKeyWildcard && scopeAction != action {
			continue
		}

		if scopeCollection == APIKeyWildcard ||
			scopeCollection == collection.Name ||
			scopeCollection == collection.Id {
			return true
		}
	}

	return false
}

// GenerateAPIKeySecret generates a new random plaintext API key.
func GenerateAPIKeySecret() (string, error) {
	// use the std crypto/rand directly instead of security.RandomString
	// because the latter uses a pseudorandom alphabet subset per call
	b := make([]byte, APIKeySecretLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return APIKeyPrefix + hex.EncodeToString(b)[:APIKeySecretLength], nil
}

// APIKeySecretPrefix extracts the non-secret lookup prefix from a
// plaintext API key.
func APIKeySecretPrefix(plaintext string) string {
	if !strings.HasPrefix(plaintext, APIKeyPrefix) {
		return ""
	}

	secret := plaintext[len(APIKeyPrefix):]
	if len(secret) < APIKeyPrefixLength {
		return ""
	}

	return secret[:APIKeyPrefixLength]
}

// HashAPIKeySecret returns the hex encoded SHA-256 digest of
// salt + ":" + plaintext.
func HashAPIKeySecret(salt, plaintext string) string {
	sum := sha256.Sum256([]byte(salt + ":" + plaintext))
	return hex.EncodeToString(sum[:])
}

// ParseAPIKeyScope parses a single "collection:action" scope entry.
//
// Returns ok=false if the scope format is invalid.
func ParseAPIKeyScope(scope string) (collection string, action string, ok bool) {
	collection, action, found := strings.Cut(strings.TrimSpace(scope), ":")
	if !found {
		return "", "", false
	}

	collection = strings.TrimSpace(collection)
	action = strings.TrimSpace(action)

	if collection == "" || action == "" {
		return "", "", false
	}

	if action != APIKeyWildcard && !slices.Contains(APIKeyAllActions, action) {
		return "", "", false
	}

	return collection, action, true
}

// randomHex returns a hex encoded random string with the specified byte length.
func randomHex(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (app *BaseApp) registerAPIKeyHooks() {
	app.OnRecordValidate(CollectionNameAPIKeys).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			m := &APIKey{e.Record}

			errs := validation.Errors{}

			name := m.Name()
			if err := validation.Validate(name,
				validation.Required,
				validation.Length(1, 255),
			); err != nil {
				errs["name"] = err
			}

			// keyHash/keySalt are system-managed and must always be present
			if m.KeyHash() == "" || m.KeySalt() == "" || m.KeyPrefix() == "" {
				errs["keyHash"] = errors.New("missing key secret data")
			}

			scopes := m.Scopes()
			if len(scopes) == 0 {
				errs["scopes"] = errors.New("at least one scope is required")
			} else {
				invalidScopes := []string{}
				for _, scope := range scopes {
					c, _, ok := ParseAPIKeyScope(scope)
					if !ok {
						invalidScopes = append(invalidScopes, scope)
						continue
					}

					// system collections (name starting with "_") can never be accessed through an API key
					if c != APIKeyWildcard && strings.HasPrefix(c, "_") {
						invalidScopes = append(invalidScopes, scope)
					}
				}
				if len(invalidScopes) > 0 {
					errs["scopes"] = errors.New("invalid scope entries: " + strings.Join(list.ToUniqueStringSlice(invalidScopes), ", "))
				}
			}

			// validate the owner reference (if any) - API keys can be bound
			// only to non-superuser auth records
			ownerRecordRef := m.OwnerRecordRef()
			ownerCollectionRef := m.OwnerCollectionRef()
			if ownerRecordRef != "" || ownerCollectionRef != "" {
				if ownerRecordRef == "" || ownerCollectionRef == "" {
					errs["ownerRecordRef"] = errors.New("both ownerRecordRef and ownerCollectionRef must be set")
				} else {
					ownerCollection, err := e.App.FindCachedCollectionByNameOrId(ownerCollectionRef)
					if err != nil || ownerCollection == nil || !ownerCollection.IsAuth() {
						errs["ownerCollectionRef"] = errors.New("the owner collection doesn't exist or is not an auth collection")
					} else if ownerCollection.Name == CollectionNameSuperusers {
						errs["ownerRecordRef"] = errors.New("API keys cannot be bound to superuser records")
					} else {
						ownerRecord, err := e.App.FindRecordById(ownerCollection, ownerRecordRef)
						if err != nil || ownerRecord == nil {
							errs["ownerRecordRef"] = errors.New("the owner record doesn't exist")
						}
					}
				}
			}

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// cascade-delete the API keys of a deleted owner auth record or auth collection
	// ----------------------------------------------------------------
	app.OnRecordDeleteExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if e.Record.Collection().Name == CollectionNameAPIKeys || !e.Record.Collection().IsAuth() {
				return e.Next()
			}

			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				keys, err := txApp.FindAllAPIKeysByRecord(e.Record)
				if err != nil {
					return err
				}

				for _, key := range keys {
					if err := txApp.Delete(key); err != nil {
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

	app.OnCollectionDeleteExecute().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if e.Collection.Name == CollectionNameAPIKeys || !e.Collection.IsAuth() {
				return e.Next()
			}

			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				keys, err := txApp.FindAllAPIKeysByCollection(e.Collection)
				if err != nil {
					return err
				}

				for _, key := range keys {
					if err := txApp.Delete(key); err != nil {
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
}
