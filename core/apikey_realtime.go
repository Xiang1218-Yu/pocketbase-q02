package core

import (
	"context"

	"github.com/pocketbase/pocketbase/tools/subscriptions"
)

// Request event and realtime client store keys associated with API key auth.
const (
	// RequestEventKeyAPIKey holds the resolved *APIKey for the current request.
	RequestEventKeyAPIKey = "__pbAPIKey"

	// RequestEventKeyAPIKeyExpired marks that the request carried a
	// resolvable API key which has expired.
	RequestEventKeyAPIKeyExpired = "__pbAPIKeyExpired"

	// RealtimeClientAPIKeyIdKey holds the resolved API key id of a realtime client.
	RealtimeClientAPIKeyIdKey = "__pbAPIKeyId"

	// RealtimeClientAPIKeyExpiresKey holds the API key expiration unix timestamp
	// (int64; 0 means the key doesn't expire).
	RealtimeClientAPIKeyExpiresKey = "__pbAPIKeyExpires"

	// RealtimeClientAPICancelKey stores the SSE request context.CancelFunc
	// on API key clients, allowing revocation/expiry to terminate the
	// long-lived connection immediately even without pending messages.
	RealtimeClientAPICancelKey = "__pbAPIKeyCancel"
)

// disconnectAPIKeyClients unauthenticates and immediately disconnects all
// realtime clients that were established with the specified API key id.
//
// It is called on API key revocation (delete) so that an already open
// SSE connection cannot keep using the revoked credential.
func disconnectAPIKeyClients(app App, apiKeyId string) {
	if apiKeyId == "" {
		return
	}

	for _, client := range app.SubscriptionsBroker().Clients() {
		id, _ := client.Get(RealtimeClientAPIKeyIdKey).(string)
		if id == apiKeyId {
			// unblock the SSE read loop first...
			if cancel, ok := client.Get(RealtimeClientAPICancelKey).(context.CancelFunc); ok && cancel != nil {
				cancel()
			}

			// ...then clear the auth state and drop the connection for good
			client.Unset(RealtimeClientAPIKeyIdKey)
			client.Unset(RealtimeClientAPIKeyExpiresKey)
			client.Unset(RealtimeClientAPICancelKey)
			client.Unset("auth")
			client.Unsubscribe()
			client.Discard()
		}
	}
}

// FindRealtimeClientAPIKey is a convenience helper that returns the APIKey
// associated with a realtime client (or nil if the client isn't authenticated
// with an API key).
func (app *BaseApp) FindRealtimeClientAPIKey(client subscriptions.Client) *APIKey {
	id, _ := client.Get(RealtimeClientAPIKeyIdKey).(string)
	if id == "" {
		return nil
	}

	key, err := app.FindAPIKeyById(id)
	if err != nil {
		return nil
	}

	return key
}
