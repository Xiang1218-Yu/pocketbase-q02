package apis

import (
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/subscriptions"
)

// realtimeAPIKeyCacheTTL limits the db pressure of re-validating API keys
// during realtime broadcasts (the checks run per client per message).
//
// Revocation is NOT affected by the cache because disconnecting happens
// through disconnectAPIKeyClients on delete; the cache only tolerates a
// short delay for expiration and scope narrowing.
const (
	realtimeAPIKeyCacheTTL     = 10 * time.Second
	realtimeAPIKeyCacheMaxSize = 500
)

type cachedAPIKey struct {
	key      *core.APIKey
	cachedAt time.Time
}

var (
	realtimeAPIKeyCacheMu sync.RWMutex
	realtimeAPIKeyCache   = map[string]cachedAPIKey{}
)

// getCachedAPIKey returns the API key from the short-lived cache or loads it.
func getCachedAPIKey(app core.App, id string) (*core.APIKey, bool) {
	now := time.Now()

	realtimeAPIKeyCacheMu.RLock()
	cached, ok := realtimeAPIKeyCache[id]
	realtimeAPIKeyCacheMu.RUnlock()

	if ok && now.Sub(cached.cachedAt) < realtimeAPIKeyCacheTTL {
		return cached.key, true
	}

	key, err := app.FindAPIKeyById(id)
	if err != nil || key == nil {
		// negative cache for a very short period to avoid db flooding with deleted ids
		realtimeAPIKeyCacheMu.Lock()
		if len(realtimeAPIKeyCache) >= realtimeAPIKeyCacheMaxSize {
			realtimeAPIKeyCache = map[string]cachedAPIKey{}
		}
		realtimeAPIKeyCache[id] = cachedAPIKey{key: nil, cachedAt: now}
		realtimeAPIKeyCacheMu.Unlock()
		return nil, false
	}

	realtimeAPIKeyCacheMu.Lock()
	if len(realtimeAPIKeyCache) >= realtimeAPIKeyCacheMaxSize {
		realtimeAPIKeyCache = map[string]cachedAPIKey{}
	}
	realtimeAPIKeyCache[id] = cachedAPIKey{key: key, cachedAt: now}
	realtimeAPIKeyCacheMu.Unlock()

	return key, true
}

// realtimeClientAPIKeyCanView re-validates the API key bound to a realtime
// client for a record broadcast on the specified collection.
//
// It enforces:
//   - the key still exists (revoked keys are disconnected on delete anyway);
//   - the key is not expired (also taking into account the client's stored
//     expiration timestamp as a cheap cache-independent guard);
//   - the key collection binding allows the broadcast collection;
//   - the key scopes include the "view" action on it.
func realtimeClientAPIKeyCanView(app core.App, client subscriptions.Client, apiKeyId, collectionId, collectionName string) bool {
	// cheap expiration guard that doesn't require a db lookup
	if expUnix, _ := client.Get(core.RealtimeClientAPIKeyExpiresKey).(int64); expUnix > 0 && time.Now().Unix() >= expUnix {
		return false
	}

	key, ok := getCachedAPIKey(app, apiKeyId)
	if !ok || key == nil {
		return false
	}

	if key.HasExpired(time.Now()) {
		return false
	}

	return apiKeyCanAccess(key, collectionId, collectionName, "view")
}

// checkAPIKeySubscriptionScopes validates that the API key has "view" scope
// on every requested subscription topic at subscribe time.
//
// Supported topic formats (matching the regular realtime topic conventions):
//   - "collectionName" or "collectionName?" / "collectionId?" (whole collection)
//   - "collectionName/*" / "collectionId/*"
//   - "collectionName/recordId" / "collectionId/recordId"
//
// Everything after "?" is treated as serialized options and ignored.
func checkAPIKeySubscriptionScopes(app core.App, key *core.APIKey, rawSubs []string) error {
	for _, raw := range rawSubs {
		topic := raw
		if before, _, hasOpts := strings.Cut(topic, "?"); hasOpts {
			topic = before
		}
		topic = strings.TrimSpace(topic)
		if topic == "" {
			continue
		}

		parts := strings.Split(topic, "/")
		collectionPart := parts[0]

		var collectionId, collectionName string
		if col, err := app.FindCachedCollectionByNameOrId(collectionPart); err == nil && col != nil {
			collectionId = col.Id
			collectionName = col.Name
		} else {
			// unknown collection topic: let the standard flow handle it as no-match
			continue
		}

		if !apiKeyCanAccess(key, collectionId, collectionName, "view") {
			return newAPIKeyForbiddenError(
				"The API key is not allowed to subscribe to "+collectionName+".",
				map[string]any{"action": "view"},
			)
		}
	}

	return nil
}
