package core

import (
	"database/sql"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
)

// FindAPIKeyById returns the API key model with the provided id.
func (app *BaseApp) FindAPIKeyById(id string) (*APIKey, error) {
	model := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(model)
	if err != nil {
		return nil, err
	}

	return model, nil
}

// FindAPIKeyByPrefix returns the API key model matching the provided
// non-secret lookup prefix.
//
// Note that the caller must additionally verify the key digest
// (see [APIKey.VerifySecret]).
func (app *BaseApp) FindAPIKeyByPrefix(keyPrefix string) (*APIKey, error) {
	model := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"keyPrefix": keyPrefix}).
		Limit(1).
		One(model)
	if err != nil {
		return nil, err
	}

	return model, nil
}

// FindAPIKeyBySecret looks up an API key by its non-secret prefix and
// verifies its salted digest.
//
// Returns nil without an error if the key doesn't exist or the secret doesn't match.
//
// The method checks neither the expiration nor the revocation state -
// use [APIKey.IsActive] for that.
func (app *BaseApp) FindAPIKeyBySecret(plaintext string) (*APIKey, error) {
	prefix := APIKeySecretPrefix(plaintext)
	if prefix == "" {
		return nil, nil
	}

	key, err := app.FindAPIKeyByPrefix(prefix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if !key.VerifySecret(plaintext) {
		return nil, nil
	}

	return key, nil
}

// FindAllAPIKeysByRecord returns all API keys bound to the provided auth record.
func (app *BaseApp) FindAllAPIKeysByRecord(authRecord *Record) ([]*APIKey, error) {
	keys := []*APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{
			"ownerCollectionRef": authRecord.Collection().Id,
			"ownerRecordRef":     authRecord.Id,
		}).
		OrderBy("created DESC").
		All(&keys)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// FindAllAPIKeysByCollection returns all API keys bound to records
// from the provided auth collection.
func (app *BaseApp) FindAllAPIKeysByCollection(collection *Collection) ([]*APIKey, error) {
	keys := []*APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"ownerCollectionRef": collection.Id}).
		OrderBy("created DESC").
		All(&keys)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// TouchAPIKeyLastUsedAt updates the "lastUsedAt" field of the API key
// but at most once per the specified throttle duration (to avoid
// write amplification on every authenticated request).
//
// The update is best-effort and doesn't trigger the regular model hooks
// nor update the "updated" autodate field.
func (app *BaseApp) TouchAPIKeyLastUsedAt(keyId string, throttle time.Duration) {
	key, err := app.FindAPIKeyById(keyId)
	if err != nil {
		return
	}

	now := time.Now().UTC()

	if last := key.LastUsedAt(); !last.IsZero() && now.Sub(last) < throttle {
		return
	}

	_, err = app.NonconcurrentDB().NewQuery(
		"UPDATE {{_apiKeys}} SET [[lastUsedAt]] = {:now} WHERE [[id]] = {:id} AND ([[lastUsedAt]] = '' OR [[lastUsedAt]] IS NULL OR [[lastUsedAt]] < {:threshold})",
	).Bind(dbx.Params{
		"id":        keyId,
		"now":       now.Format("2006-01-02 15:04:05.000Z"),
		"threshold": now.Add(-throttle).Format("2006-01-02 15:04:05.000Z"),
	}).Execute()
	if err != nil {
		app.Logger().Debug("Failed to update API key lastUsedAt", "keyId", keyId, "error", err)
	}
}
