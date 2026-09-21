package apis

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/routine"
)

const (
	DefaultLoadAPIKeyMiddlewarePriority = DefaultLoadAuthTokenMiddlewarePriority + 1
	DefaultLoadAPIKeyMiddlewareId       = "pbLoadAPIKey"

	DefaultAPIKeyScopeMiddlewareId = "pbRequireAPIKeyScope"
)

// API key auth error code (used in the serialized ApiError response).
const apiKeyErrorCode = "api_key_auth_failed"

// apiKeyAuthError marks an ApiError as produced by the API key authentication
// or scope enforcement layer (serialized with {"code": "api_key_auth_failed"}).
type apiKeyAuthError struct{ *router.ApiError }

func (e *apiKeyAuthError) Unwrap() error { return e.ApiError }

// newAPIKeyApiError builds an ApiError whose "data" object is passed through
// verbatim (the default router resolution would treat raw maps as validation
// errors, see router.safeErrorsData).
func newAPIKeyApiError(status int, message string, details map[string]any) error {
	data := map[string]any{"code": apiKeyErrorCode}
	for k, v := range details {
		data[k] = v
	}

	return &apiKeyAuthError{&router.ApiError{
		Status:  status,
		Message: message,
		Data:    data,
	}}
}

func newAPIKeyUnauthorizedError(message string, details map[string]any) error {
	return newAPIKeyApiError(http.StatusUnauthorized, message, details)
}

func newAPIKeyForbiddenError(message string, details map[string]any) error {
	return newAPIKeyApiError(http.StatusForbidden, message, details)
}

// loadAPIKey resolves an API key from the Authorization header and
// populates the request auth context.
//
// It runs right after the regular JWT [loadAuthToken] middleware:
//   - if the token doesn't carry the API key prefix, the request continues untouched;
//   - on unknown, revoked or expired key the request continues unauthenticated
//     (same semantics as an invalid JWT, allowing downstream guards/custom middleware);
//   - on a valid key, the linked auth record (if any) is loaded into e.Auth,
//     @request.auth and the API rule resolution chain, while the resolved
//     *core.APIKey is stored under [core.RequestEventKeyAPIKey].
//
// The key last-used metadata is updated best-effort (throttled).
func loadAPIKey() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultLoadAPIKeyMiddlewareId,
		Priority: DefaultLoadAPIKeyMiddlewarePriority,
		Func: func(e *core.RequestEvent) error {
			token := getAuthTokenFromRequest(e)
			if token == "" || !core.IsAPIKeyToken(token) {
				return e.Next()
			}

			key, err := e.App.FindAPIKeyByToken(token)
			if err != nil {
				if errors.Is(err, core.ErrAPIKeyExpired) {
					// expired keys are never silently downgraded to guests
					e.Set(core.RequestEventKeyAPIKeyExpired, true)
				}
				e.App.Logger().Debug("loadAPIKey failure", "error", err)
				return e.Next()
			}

			// defense in depth: API keys can never be superusers
			var authRecord *core.Record
			if key.RecordRef() != "" {
				col, colErr := e.App.FindCachedCollectionByNameOrId(key.CollectionRef())
				if colErr != nil || col == nil || col.Name == core.CollectionNameSuperusers {
					e.App.Logger().Debug("loadAPIKey failure: invalid linked collection")
					return e.Next()
				}

				authRecord, err = e.App.FindRecordById(col, key.RecordRef())
				if err != nil || authRecord == nil {
					e.App.Logger().Debug("loadAPIKey failure: linked record is missing", "error", err)
					return e.Next()
				}

				e.Auth = authRecord
			}

			e.Set(core.RequestEventKeyAPIKey, key)

			// best-effort last usage update (must never block/fail the request)
			ip := e.RealIP()
			routine.FireAndForget(func() {
				if touchErr := e.App.TouchAPIKey(key, ip); touchErr != nil {
					e.App.Logger().Debug("loadAPIKey touch failure", "error", touchErr)
				}
			})

			return e.Next()
		},
	}
}

// rejectExpiredAPIKey rejects requests carrying an expired but resolvable
// API key with 401 - they must never be silently downgraded to guests
// (registered globally with a high priority).
func rejectExpiredAPIKey() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       "pbRejectExpiredAPIKey",
		Priority: DefaultLoadAPIKeyMiddlewarePriority + 1,
		Func: func(e *core.RequestEvent) error {
			if expired, _ := e.Get(core.RequestEventKeyAPIKeyExpired).(bool); expired {
				return newAPIKeyUnauthorizedError("The API key has expired.", nil)
			}

			return e.Next()
		},
	}
}

// requireNoAPIKeyAuth blocks interactive auth flows (login, refresh,
// password/verification/email-change, OTP) for requests authenticated
// with an API key - API keys are machine credentials, not interactive
// sessions, and must not be able to mint tokens or change credentials.
func requireNoAPIKeyAuth() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       "pbRequireNoAPIKeyAuth",
		Priority: DefaultLoadAPIKeyMiddlewarePriority + 1,
		Func: func(e *core.RequestEvent) error {
			if key, _ := e.Get(core.RequestEventKeyAPIKey).(*core.APIKey); key != nil {
				return newAPIKeyForbiddenError(
					"API keys cannot be used with interactive authentication endpoints.",
					nil,
				)
			}

			return e.Next()
		},
	}
}

// requireAPIKeyScope is a per-route guard ensuring that, when the request
// was authenticated with an API key, the key allows [action] on the
// collection resolved from the "{collection}" route path param.
//
// Requests authenticated with a regular record JWT (or guests) pass through
// unchanged - their permissions are enforced by the existing API rules.
func requireAPIKeyScope(action string) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultAPIKeyScopeMiddlewareId,
		Priority: DefaultLoadAPIKeyMiddlewarePriority + 1,
		Func: func(e *core.RequestEvent) error {
			key, _ := e.Get(core.RequestEventKeyAPIKey).(*core.APIKey)
			if key == nil {
				return e.Next()
			}

			if key.HasExpired(time.Now()) {
				return newAPIKeyUnauthorizedError("The API key has expired.", nil)
			}

			collectionId := ""
			collectionName := ""
			if pathCollection := e.Request.PathValue("collection"); pathCollection != "" {
				if col, err := e.App.FindCachedCollectionByNameOrId(pathCollection); err == nil && col != nil {
					collectionId = col.Id
					collectionName = col.Name
				} else {
					// let the handler return its regular "missing collection" 404
					return e.Next()
				}
			}

			if !apiKeyCanAccess(key, collectionId, collectionName, action) {
				return newAPIKeyForbiddenError(
					"The API key is not allowed to perform this action.",
					map[string]any{"action": action},
				)
			}

			return e.Next()
		},
	}
}

// apiKeyCanAccess enforces the key explicit scope list.
//
// The collection binding (collectionRef) doesn't grant implicit access -
// it is used only to load the linked auth record; every action must be
// explicitly allowed by a scope entry (with "*" wildcard support).
func apiKeyCanAccess(key *core.APIKey, collectionId, collectionName, action string) bool {
	if key == nil {
		return false
	}

	return key.CanAccess(collectionId, collectionName, action)
}

// apiKeyActionForMethod maps an HTTP method (uppercase) to a scope action.
//
// PUT returns "" because it is ambiguous (create OR update) and the caller
// must check both actions (see [ensureBatchAPIKeyScope]).
func apiKeyActionForMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return ""
	}
}

// ensureBatchAPIKeyScope enforces the API key scope for a single internal
// batch request, reusing the same semantics as the regular record routes.
func ensureBatchAPIKeyScope(baseEvent *core.RequestEvent, method, collectionParam string) error {
	key, _ := baseEvent.Get(core.RequestEventKeyAPIKey).(*core.APIKey)
	if key == nil {
		return nil
	}

	if key.HasExpired(time.Now()) {
		return newAPIKeyUnauthorizedError("The API key has expired.", nil)
	}

	collectionId := ""
	collectionName := ""
	if collectionParam != "" {
		if col, err := baseEvent.App.FindCachedCollectionByNameOrId(collectionParam); err == nil && col != nil {
			collectionId = col.Id
			collectionName = col.Name
		}
	}

	method = strings.ToUpper(method)
	if method == http.MethodPut {
		// upsert -> create OR update both allowed
		if !apiKeyCanAccess(key, collectionId, collectionName, "create") &&
			!apiKeyCanAccess(key, collectionId, collectionName, "update") {
			return newAPIKeyForbiddenError(
				"The API key is not allowed to perform this action.",
				map[string]any{"action": "create/update"},
			)
		}
		return nil
	}

	action := apiKeyActionForMethod(method)
	if action == "" {
		return nil
	}

	if !apiKeyCanAccess(key, collectionId, collectionName, action) {
		return newAPIKeyForbiddenError(
			"The API key is not allowed to perform this action.",
			map[string]any{"action": action},
		)
	}

	return nil
}
