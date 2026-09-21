package core

import (
	"errors"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/tools/types"
)

// FindAPIKeyById returns a single APIKey model by its id.
func (app *BaseApp) FindAPIKeyById(id string) (*APIKey, error) {
	result := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAPIKeyByHash returns the active APIKey matching the provided hash.
//
// It returns:
//   - [ErrAPIKeyExpired] if a matching key exists but is past its expiration;
//   - [ErrAPIKeyInvalid] if no active key exists for the hash.
func (app *BaseApp) FindAPIKeyByHash(keyHash string) (*APIKey, error) {
	if keyHash == "" {
		return nil, ErrAPIKeyInvalid
	}

	result := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"keyHash": keyHash}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, errors.Join(ErrAPIKeyInvalid, err)
	}

	if result.HasExpired(time.Now()) {
		return nil, ErrAPIKeyExpired
	}

	return result, nil
}

// FindAPIKeyByToken hashes the provided plaintext token and returns
// the matching active APIKey.
func (app *BaseApp) FindAPIKeyByToken(token string) (*APIKey, error) {
	if !IsAPIKeyToken(token) {
		return nil, ErrAPIKeyInvalid
	}

	return app.FindAPIKeyByHash(HashAPIKey(token))
}

// FindAllAPIKeysByRecord returns all API keys linked to the provided auth record.
func (app *BaseApp) FindAllAPIKeysByRecord(authRecord *Record) ([]*APIKey, error) {
	result := []*APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
		}).
		OrderBy("created DESC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteAllAPIKeysByRecord deletes all API keys associated with the provided record.
func (app *BaseApp) DeleteAllAPIKeysByRecord(authRecord *Record) error {
	models, err := app.FindAllAPIKeysByRecord(authRecord)
	if err != nil {
		return err
	}

	var errs []error
	for _, m := range models {
		if err := app.Delete(m); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// TouchAPIKey throttled updates the "lastUsedAt"/"lastUsedByIP" of the
// provided API key.
//
// It is a best-effort operation executed outside of the request transaction
// and errors are only logged by the callers; a failure must never affect
// the authenticated request itself.
//
// The lastUsedAt is updated only if the stored value is older than 30 seconds
// to avoid flooding the database with writes on high traffic keys.
func (app *BaseApp) TouchAPIKey(key *APIKey, ip string) error {
	now := types.NowDateTime()

	// cheap throttle based on the in-memory loaded value
	if !key.LastUsedAt().IsZero() && now.Time().Sub(key.LastUsedAt().Time()) < apiKeyLastUsedThrottle {
		return nil
	}

	_, err := app.NonconcurrentDB().NewQuery(
		"UPDATE {{_apiKeys}} SET [[lastUsedAt]]={:now}, [[lastUsedByIP]]={:ip}, [[updated]]={:now} WHERE [[id]]={:id} AND ([[lastUsedAt]]='' OR [[lastUsedAt]] IS NULL OR [[lastUsedAt]] < {:threshold})",
	).Bind(dbx.Params{
		"now":       now.String(),
		"ip":        ip,
		"id":        key.Id,
		"threshold": now.Add(-apiKeyLastUsedThrottle).String(),
	}).Execute()

	return err
}

// DeleteExpiredAPIKeys deletes all API keys with explicit "expiresAt" in the past.
func (app *BaseApp) DeleteExpiredAPIKeys() error {
	items := []*Record{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.NewExp("[[expiresAt]] != '' AND [[expiresAt]] < {:now}", dbx.Params{
			"now": types.NowDateTime().String(),
		})).
		All(&items)
	if err != nil {
		return err
	}

	for _, item := range items {
		if err := app.Delete(item); err != nil {
			return err
		}
	}

	return nil
}
