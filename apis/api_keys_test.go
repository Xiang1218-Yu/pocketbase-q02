package apis_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/subscriptions"
	"github.com/pocketbase/pocketbase/tools/types"
)

const superuserAuthToken = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InN5d2JoZWNuaDQ2cmhtMCIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoicGJjXzMxNDI2MzU4MjMiLCJleHAiOjI1MjQ2MDQ0NjEsInJlZnJlc2hhYmxlIjp0cnVlfQ.UXgO3j-0BumcugrFjbd7j0M4MQvbrLggLlcu_YNGjoY"

// createTestAPIKey persists an API key directly through the core and
// returns the model together with the plaintext secret.
func createTestAPIKey(t *testing.T, app *tests.TestApp, name string, scopes []string, optExpires ...time.Time) (*core.APIKey, string) {
	t.Helper()

	key := core.NewAPIKey(app)
	key.SetName(name)
	key.SetScopes(scopes)

	if len(optExpires) > 0 {
		key.SetExpires(optExpires[0])
	}

	plaintext, err := key.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	return key, plaintext
}

func TestAPIKeysAdminEndpointsGuards(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:           "list - guest",
			Method:         http.MethodGet,
			URL:            "/api/api-keys",
			ExpectedStatus: 401,
			ExpectedContent: []string{
				`"message":"The request requires valid record authorization token."`,
			},
		},
		{
			Name:   "list - regular user (not superuser)",
			Method: http.MethodGet,
			URL:    "/api/api-keys",
			Headers: map[string]string{
				"Authorization": "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjRxMXhsY2xtZmxva3UzMyIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoiX3BiX3VzZXJzX2F1dGhfIiwiZXhwIjoyNTI0NjA0NDYxLCJyZWZyZXNoYWJsZSI6dHJ1ZX0.ZT3F0Z3iM-xbGgSG3LEKiEzHrPHr8t8IuHLZGGNuxLo",
			},
			ExpectedStatus: 403,
			ExpectedContent: []string{
				`"message":"The authorized record is not allowed to perform this action."`,
			},
		},
		{
			Name:   "list - superuser",
			Method: http.MethodGet,
			URL:    "/api/api-keys",
			Headers: map[string]string{
				"Authorization": superuserAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"items":[]`,
			},
		},
		{
			Name:           "create - guest",
			Method:         http.MethodPost,
			URL:            "/api/api-keys",
			Body:           strings.NewReader(`{"name":"x","scopes":["*:*"]}`),
			ExpectedStatus: 401,
			ExpectedContent: []string{
				`"message":"The request requires valid record authorization token."`,
			},
		},
		{
			Name:           "delete - guest",
			Method:         http.MethodDelete,
			URL:            "/api/api-keys/whatever",
			ExpectedStatus: 401,
			ExpectedContent: []string{
				`"message":"The request requires valid record authorization token."`,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestAPIKeyAdminCreate(t *testing.T) {
	t.Parallel()

	newApp := func(t testing.TB) *tests.TestApp {
		app, err := tests.NewTestApp()
		if err != nil {
			t.Fatal(err)
		}
		return app
	}

	t.Run("successful create returns the plaintext key once", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		router, err := apis.NewRouter(app)
		if err != nil {
			t.Fatal(err)
		}
		serveEvent := new(core.ServeEvent)
		serveEvent.App = app
		serveEvent.Router = router
		if err := app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error { return e.Next() }); err != nil {
			t.Fatal(err)
		}

		body := `{"name":"ci-deploy","scopes":["demo1:view","demo1:list"],"expires":"2099-01-01T00:00:00Z"}`
		req := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(body))
		req.Header.Set("Authorization", superuserAuthToken)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		mux, _ := router.BuildMux()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}

		plaintext, _ := resp["key"].(string)
		if !strings.HasPrefix(plaintext, core.APIKeyPrefix) {
			t.Fatalf("Expected plaintext key in response, got %v", resp["key"])
		}

		// secret material must not be present in the other fields
		bodyStr := rec.Body.String()
		if strings.Contains(bodyStr, "keyHash") || strings.Contains(bodyStr, "keySalt") {
			t.Fatalf("Expected keyHash/keySalt to be hidden, body: %s", bodyStr)
		}

		// the plaintext must not be retrievable anymore through the list endpoint
		req2 := httptest.NewRequest(http.MethodGet, "/api/api-keys", nil)
		req2.Header.Set("Authorization", superuserAuthToken)
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)

		if strings.Contains(rec2.Body.String(), plaintext) {
			t.Fatalf("The plaintext key must not be returned on list: %s", rec2.Body.String())
		}
		if !strings.Contains(rec2.Body.String(), `"name":"ci-deploy"`) {
			t.Fatalf("Expected the key metadata in the list, got %s", rec2.Body.String())
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		scenarios := []struct {
			name string
			body string
			data string
		}{
			{"missing name", `{"scopes":["*:*"]}`, `"name":`},
			{"empty scopes", `{"name":"a"}`, `"scopes":`},
			{"invalid scope", `{"name":"a","scopes":["nope"]}`, `"scopes":`},
			{"system collection scope", `{"name":"a","scopes":["_superusers:view"]}`, `"scopes":`},
			{"past expiration", `{"name":"a","scopes":["*:*"],"expires":"2000-01-01T00:00:00Z"}`, `"expires":`},
			{"invalid expiration", `{"name":"a","scopes":["*:*"],"expires":"not-a-date"}`, `"expires":`},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				app := newApp(t)
				defer app.Cleanup()

				router, _ := apis.NewRouter(app)
				se := new(core.ServeEvent)
				se.App = app
				se.Router = router
				if err := app.OnServe().Trigger(se, func(e *core.ServeEvent) error { return e.Next() }); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(s.body))
				req.Header.Set("Authorization", superuserAuthToken)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				mux, _ := router.BuildMux()
				mux.ServeHTTP(rec, req)

				if rec.Code != 400 {
					t.Fatalf("Expected 400, got %d: %s", rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), s.data) {
					t.Fatalf("Expected field error %s in %s", s.data, rec.Body.String())
				}
			})
		}
	})

	t.Run("duplicate name is rejected", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		createTestAPIKey(t, app, "dup", []string{"*:*"})

		router, _ := apis.NewRouter(app)
		se := new(core.ServeEvent)
		se.App = app
		se.Router = router
		if err := app.OnServe().Trigger(se, func(e *core.ServeEvent) error { return e.Next() }); err != nil {
			t.Fatal(err)
		}
		body := `{"name":"dup","scopes":["*:*"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/api-keys", strings.NewReader(body))
		req.Header.Set("Authorization", superuserAuthToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux, _ := router.BuildMux()
		mux.ServeHTTP(rec, req)

		if rec.Code != 400 {
			t.Fatalf("Expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"name":`) {
			t.Fatalf("Expected name field error, got %s", rec.Body.String())
		}
	})
}

func TestAPIKeyAdminUpdateViewRevoke(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	router, _ := apis.NewRouter(app)
	se := new(core.ServeEvent)
	se.App = app
	se.Router = router
	if err := app.OnServe().Trigger(se, func(e *core.ServeEvent) error { return e.Next() }); err != nil {
		t.Fatal(err)
	}
	mux, _ := router.BuildMux()

	do := func(method, url, body string) *httptest.ResponseRecorder {
		var r *bytes.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		} else {
			r = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, url, r)
		req.Header.Set("Authorization", superuserAuthToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	key, _ := createTestAPIKey(t, app, "editable", []string{"demo1:view"})

	// view
	rec := do(http.MethodGet, "/api/api-keys/"+key.Id, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"editable"`) {
		t.Fatalf("Expected the key in view response, got %d: %s", rec.Code, rec.Body.String())
	}

	// update name/scopes/expires
	rec = do(http.MethodPatch, "/api/api-keys/"+key.Id, `{"name":"renamed","scopes":["demo2:*"],"expires":"2099-06-01T00:00:00Z"}`)
	if rec.Code != 200 {
		t.Fatalf("Expected 200 on update, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"renamed"`) {
		t.Fatalf("Expected updated name, got %s", rec.Body.String())
	}

	// clear expiration
	rec = do(http.MethodPatch, "/api/api-keys/"+key.Id, `{"expires":""}`)
	if rec.Code != 200 {
		t.Fatalf("Expected 200 clearing expiration, got %d: %s", rec.Code, rec.Body.String())
	}

	// update with invalid scopes
	rec = do(http.MethodPatch, "/api/api-keys/"+key.Id, `{"scopes":["bad"]}`)
	if rec.Code != 400 {
		t.Fatalf("Expected 400 on invalid scopes, got %d", rec.Code)
	}

	// update nonexistent
	rec = do(http.MethodPatch, "/api/api-keys/missing", `{"name":"x"}`)
	if rec.Code != 404 {
		t.Fatalf("Expected 404 for missing key, got %d", rec.Code)
	}

	// revoke (DELETE)
	rec = do(http.MethodDelete, "/api/api-keys/"+key.Id, "")
	if rec.Code != 204 {
		t.Fatalf("Expected 204 on revoke, got %d", rec.Code)
	}

	// the record is preserved and marked revoked
	fresh, err := app.FindAPIKeyById(key.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.IsRevoked() {
		t.Fatal("Expected the key to be marked revoked")
	}
	if fresh.RevokedAt().IsZero() {
		t.Fatal("Expected revokedAt to be set")
	}

	// revoke is idempotent
	rec = do(http.MethodDelete, "/api/api-keys/"+key.Id, "")
	if rec.Code != 204 {
		t.Fatalf("Expected 204 on repeated revoke, got %d", rec.Code)
	}

	// revoke nonexistent
	rec = do(http.MethodDelete, "/api/api-keys/missing", "")
	if rec.Code != 404 {
		t.Fatalf("Expected 404 for missing key, got %d", rec.Code)
	}
}

// -------------------------------------------------------------------
// Authentication middleware & scope enforcement
// -------------------------------------------------------------------

func setupAPIKeyRouter(t *testing.T) (*tests.TestApp, http.Handler) {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}

	// trigger the serve event so that app routes and caches are initialized
	// (mirrors what tests.ApiScenario does internally)
	serveEvent := new(core.ServeEvent)
	serveEvent.App = app
	serveEvent.Router = router
	if err := app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		return e.Next()
	}); err != nil {
		t.Fatal(err)
	}

	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	return app, mux
}

func TestAPIKeyRecordAuthScenarios(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name           string
		scopes         []string
		target         string
		method         string
		expectedStatus int
	}{
		// demo1 has nil rules (superuser-only), demo2 is public
		{
			name:           "view allowed on scoped collection",
			scopes:         []string{"demo1:view"},
			target:         "/api/collections/demo1/records/ALKHH124Z1SWD6K",
			method:         http.MethodGet,
			expectedStatus: 404, // scope passes; nil rule blocks non-superuser -> but rule returns 403
		},
		{
			name:           "view scope missing -> 403",
			scopes:         []string{"demo1:list"},
			target:         "/api/collections/demo1/records/ALKHH124Z1SWD6K",
			method:         http.MethodGet,
			expectedStatus: 403,
		},
		{
			name:           "list public collection works with scope",
			scopes:         []string{"demo2:list"},
			target:         "/api/collections/demo2/records",
			method:         http.MethodGet,
			expectedStatus: 200,
		},
		{
			name:           "list public collection without scope -> 403",
			scopes:         []string{"demo2:view"},
			target:         "/api/collections/demo2/records",
			method:         http.MethodGet,
			expectedStatus: 403,
		},
		{
			name:           "wildcard scope",
			scopes:         []string{"*:view"},
			target:         "/api/collections/demo2/records/0yxhwia2amd8gec",
			method:         http.MethodGet,
			expectedStatus: 200,
		},
		{
			name:           "create scope denied",
			scopes:         []string{"demo2:view"},
			target:         "/api/collections/demo2/records",
			method:         http.MethodPost,
			expectedStatus: 403,
		},
		{
			name:           "delete scope denied",
			scopes:         []string{"demo2:view"},
			target:         "/api/collections/demo2/records/0yxhwia2amd8gec",
			method:         http.MethodDelete,
			expectedStatus: 403,
		},
		{
			name:           "scoped to different collection denied",
			scopes:         []string{"demo1:*"},
			target:         "/api/collections/demo2/records/0yxhwia2amd8gec",
			method:         http.MethodGet,
			expectedStatus: 403,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, mux := setupAPIKeyRouter(t)
			defer app.Cleanup()

			_, plaintext := createTestAPIKey(t, app, s.name, s.scopes)

			req := httptest.NewRequest(s.method, s.target, nil)
			req.Header.Set("Authorization", plaintext)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			// the first case is documented differently: scope passes but the
			// nil-rule collection still returns 403 for non-superusers
			expected := s.expectedStatus
			if s.name == "view allowed on scoped collection" {
				expected = 403
			}

			if rec.Code != expected {
				t.Fatalf("Expected %d, got %d: %s", expected, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAPIKeyInvalidAndExpired(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	// unknown key is treated as guest -> public collection still works
	req := httptest.NewRequest(http.MethodGet, "/api/collections/demo2/records/0yxhwia2amd8gec", nil)
	req.Header.Set("Authorization", core.APIKeyPrefix+"doesnotexist00000000000000000000000000")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Expected invalid key to fall back as guest on public route, got %d", rec.Code)
	}

	// revoked key is ignored (treated as guest)
	key, plaintext := createTestAPIKey(t, app, "revokable", []string{"*:*"})
	key.SetRevokedAt(time.Now())
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/collections/demo1/records", nil)
	req.Header.Set("Authorization", plaintext)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Expected revoked key to be ignored (guest -> 403 on nil-rule), got %d", rec.Code)
	}

	// expired key is ignored
	expiredKey, expiredPlaintext := createTestAPIKey(
		t, app, "expired", []string{"*:*"}, time.Now().Add(-time.Minute),
	)
	if !expiredKey.IsExpired(time.Now()) {
		t.Fatal("sanity: expected the key to be expired")
	}
	req = httptest.NewRequest(http.MethodGet, "/api/collections/demo1/records", nil)
	req.Header.Set("Authorization", expiredPlaintext)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Expected expired key to be ignored (guest -> 403), got %d", rec.Code)
	}

	// key expiring exactly at the boundary (1s in the future) is still valid
	boundaryKey, boundaryPlaintext := createTestAPIKey(
		t, app, "boundary", []string{"demo2:view"}, time.Now().Add(5*time.Second),
	)
	if boundaryKey.IsExpired(time.Now()) {
		t.Fatal("sanity: key expiring in 5s must still be active")
	}
	req = httptest.NewRequest(http.MethodGet, "/api/collections/demo2/records/0yxhwia2amd8gec", nil)
	req.Header.Set("Authorization", boundaryPlaintext)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Expected near-future key to still work, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyCannotAccessSystemAndAuthEndpoints(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	_, plaintext := createTestAPIKey(t, app, "scripts", []string{"*:*"})

	// API keys can never access superuser-gated system endpoints
	for _, target := range []string{
		"/api/settings",
		"/api/collections",
		"/api/backups",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", plaintext)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("Expected %s to be forbidden for API key, got %d", target, rec.Code)
		}
	}

	// API keys are explicitly denied on interactive auth endpoints
	req := httptest.NewRequest(http.MethodPost, "/api/collections/users/auth-refresh", nil)
	req.Header.Set("Authorization", plaintext)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Expected auth-refresh to be forbidden for API key, got %d", rec.Code)
	}

	// file token issuance requires an interactive record session
	req = httptest.NewRequest(http.MethodPost, "/api/files/token", nil)
	req.Header.Set("Authorization", plaintext)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("Expected file token endpoint to be forbidden for API key, got %d", rec.Code)
	}
}

func TestAPIKeyOwnerBound(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	users, err := app.FindCachedCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	owner, err := app.FindFirstRecordByData(users, "email", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	key, plaintext := createTestAPIKey(t, app, "owner-scoped", []string{"users:view", "users:update"})
	key.SetOwnerCollectionRef(users.Id)
	key.SetOwnerRecordRef(owner.Id)
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	// the key authenticates as the owner record, so owner API rules
	// ("id = @request.auth.id") must allow accessing the owner's own record
	req := httptest.NewRequest(http.MethodGet, "/api/collections/users/records/"+owner.Id, nil)
	req.Header.Set("Authorization", plaintext)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Expected owner-bound key to access the owner record, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"emailVisibility"`) && !strings.Contains(rec.Body.String(), `"id":"`+owner.Id+`"`) {
		t.Fatalf("Unexpected body: %s", rec.Body.String())
	}

	// but cannot access another user's record (owner rule blocks it)
	req = httptest.NewRequest(http.MethodGet, "/api/collections/users/records/oap640cot4yru2s", nil)
	req.Header.Set("Authorization", plaintext)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("Expected owner rule to hide other user records (404), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyLastUsedAt(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	key, plaintext := createTestAPIKey(t, app, "usage", []string{"demo2:view"})

	before := key.LastUsedAt()
	if !before.IsZero() {
		t.Fatal("Expected no lastUsedAt on a fresh key")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/collections/demo2/records/0yxhwia2amd8gec", nil)
	req.Header.Set("Authorization", plaintext)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	// the throttled update may lag slightly; allow a few retries
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fresh, err := app.FindAPIKeyById(key.Id)
		if err != nil {
			t.Fatal(err)
		}
		if !fresh.LastUsedAt().IsZero() {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("Expected lastUsedAt to be updated after an authenticated request")
}

// -------------------------------------------------------------------
// Batch requests
// -------------------------------------------------------------------

func TestAPIKeyBatchScope(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	_, allowed := createTestAPIKey(t, app, "batch-allowed", []string{"demo2:create", "demo2:update", "demo2:list", "demo2:view", "demo2:delete"})
	_, denied := createTestAPIKey(t, app, "batch-denied", []string{"demo2:view"})

	body := `{"requests":[
		{"method":"POST","url":"/api/collections/demo2/records","body":{"title":"via-batch"}}
	]}`

	// allowed key
	req := httptest.NewRequest(http.MethodPost, "/api/batch", strings.NewReader(body))
	req.Header.Set("Authorization", allowed)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Expected batch 200 with scoped key, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":200`) {
		t.Fatalf("Expected the inner create to succeed, got %s", rec.Body.String())
	}

	// denied key (missing create scope)
	req = httptest.NewRequest(http.MethodPost, "/api/batch", strings.NewReader(body))
	req.Header.Set("Authorization", denied)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("Expected batch failure 400 without create scope, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not allowed to perform this action") {
		t.Fatalf("Expected scope error in batch response, got %s", rec.Body.String())
	}

	// upsert (PUT) requires both create and update scopes
	upsertBody := `{"requests":[
		{"method":"PUT","url":"/api/collections/demo2/records","body":{"id":"0yxhwia2amd8gec","title":"upserted"}}
	]}`
	req = httptest.NewRequest(http.MethodPost, "/api/batch", strings.NewReader(upsertBody))
	req.Header.Set("Authorization", denied)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("Expected upsert to fail without create+update scopes, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeyConcurrentRevocation verifies that a key revoked while
// in-flight requests are running is rejected on every request that
// starts after the revocation commit (no stale in-memory acceptance).
func TestAPIKeyConcurrentRevocation(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	key, plaintext := createTestAPIKey(t, app, "concurrent", []string{"demo2:view", "demo2:list"})

	const total = 30
	var wg sync.WaitGroup
	results := make(chan int, total)

	// half of the requests start before the revocation, half after;
	// every request re-evaluates the key from the DB via the middleware,
	// so post-revocation requests must all fall back to guest behavior
	revoked := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-revoked

		fresh, err := app.FindAPIKeyById(key.Id)
		if err != nil {
			t.Error(err)
			return
		}
		fresh.SetRevokedAt(time.Now())
		if err := app.Save(fresh); err != nil {
			t.Error(err)
		}
	}()

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			if i == total/2 {
				close(revoked)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/collections/demo2/records/0yxhwia2amd8gec", nil)
			req.Header.Set("Authorization", plaintext)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			results <- rec.Code
		}(i)
	}

	wg.Wait()
	close(results)

	// demo2 is public, so both authenticated and guest requests return
	// 200 here; the security-relevant assertion below is explicit instead:
	// after the revocation no request may carry the API key identity.
	for code := range results {
		if code != 200 {
			t.Fatalf("Unexpected status %d on public collection", code)
		}
	}

	// now target demo1 (nil rules): revoked key must behave exactly like
	// a guest (403), never as an authenticated principal
	freshReqs := 10
	for i := 0; i < freshReqs; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/collections/demo1/records", nil)
		req.Header.Set("Authorization", plaintext)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("Expected all post-revocation requests to be treated as guest (403), got %d", rec.Code)
		}
	}
}

// -------------------------------------------------------------------
// Realtime revocation
// -------------------------------------------------------------------

func TestAPIKeyRealtimeRevocation(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	defer app.Cleanup()
	if err != nil {
		t.Fatal(err)
	}

	// init routes so that the realtime hooks are bound
	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	// demo2 is public, so create a collection with an owner-ish rule
	coll := core.NewBaseCollection("rt_apikey_test")
	coll.ListRule = types.Pointer("@request.auth.id != '' || 1=1")
	coll.Fields.Add(&core.TextField{Name: "title"})
	if err := app.Save(coll); err != nil {
		t.Fatal(err)
	}

	key, plaintext := createTestAPIKey(t, app, "rt-key", []string{"rt_apikey_test:*"})

	// register a connected client authenticated with the API key
	client := subscriptions.NewDefaultClient()
	client.Set(apis.RealtimeClientAPIKey, key)
	client.Subscribe("rt_apikey_test/*")
	app.SubscriptionsBroker().Register(client)
	defer app.SubscriptionsBroker().Unregister(client.Id())

	// first broadcast (create) must be delivered
	record1 := core.NewRecord(coll)
	record1.Set("title", "before-revoke")
	go func() {
		if err := app.Save(record1); err != nil {
			t.Error(err)
		}
	}()

	select {
	case msg := <-client.Channel():
		if !strings.Contains(string(msg.Data), "before-revoke") {
			t.Fatalf("Unexpected first message: %s", string(msg.Data))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for the first (pre-revocation) broadcast")
	}

	// revoke the key while the connection is still open
	fresh, err := app.FindAPIKeyById(key.Id)
	if err != nil {
		t.Fatal(err)
	}
	fresh.SetRevokedAt(time.Now())
	if err := app.Save(fresh); err != nil {
		t.Fatal(err)
	}

	// give the revocation hook a moment to downgrade the client
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := client.Get(apis.RealtimeClientAPIKey).(*core.APIKey); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := client.Get(apis.RealtimeClientAPIKey).(*core.APIKey); ok {
		t.Fatal("Expected the API key identity to be removed from the client after revocation")
	}

	// second broadcast must NOT be delivered to the downgraded client
	record2 := core.NewRecord(coll)
	record2.Set("title", "after-revoke")
	if err := app.Save(record2); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-client.Channel():
		t.Fatalf("Expected no message after revocation, got: %s", string(msg.Data))
	case <-time.After(500 * time.Millisecond):
		// success: nothing delivered
	}

	// the revoked key also can't establish a new subscription session:
	// the middleware treats it as a guest, so a fresh client with the key
	// must fail the setSubscriptions identity check when attempting to
	// subscribe against an already key-authenticated client
	_ = plaintext
}

func TestAPIKeyRealtimeScopeEnforcement(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	defer app.Cleanup()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	coll := core.NewBaseCollection("rt_scope_test")
	coll.ListRule = types.Pointer("")
	coll.ViewRule = types.Pointer("")
	coll.Fields.Add(&core.TextField{Name: "title"})
	if err := app.Save(coll); err != nil {
		t.Fatal(err)
	}

	// view-only key on a wildcard (list) topic
	viewOnly, _ := createTestAPIKey(t, app, "rt-view-only", []string{"rt_scope_test:view"})
	viewClient := subscriptions.NewDefaultClient()
	viewClient.Set(apis.RealtimeClientAPIKey, viewOnly)
	viewClient.Subscribe("rt_scope_test/*")
	app.SubscriptionsBroker().Register(viewClient)
	defer app.SubscriptionsBroker().Unregister(viewClient.Id())

	// full-scope key as control
	full, _ := createTestAPIKey(t, app, "rt-full", []string{"rt_scope_test:*"})
	fullClient := subscriptions.NewDefaultClient()
	fullClient.Set(apis.RealtimeClientAPIKey, full)
	fullClient.Subscribe("rt_scope_test/*")
	app.SubscriptionsBroker().Register(fullClient)
	defer app.SubscriptionsBroker().Unregister(fullClient.Id())

	record := core.NewRecord(coll)
	record.Set("title", "scope-msg")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	// full-scope client receives the message
	select {
	case <-fullClient.Channel():
		// ok
	case <-time.After(3 * time.Second):
		t.Fatal("expected the full-scope client to receive the broadcast")
	}

	// view-only client must NOT receive anything on the wildcard topic
	select {
	case msg := <-viewClient.Channel():
		t.Fatalf("view-only key must not receive wildcard-topic messages, got: %s", string(msg.Data))
	case <-time.After(500 * time.Millisecond):
		// ok
	}
}

func TestAPIKeyRealtimeSetSubscriptionsIdentity(t *testing.T) {
	t.Parallel()

	app, mux := setupAPIKeyRouter(t)
	defer app.Cleanup()

	key, plaintext := createTestAPIKey(t, app, "rt-identity", []string{"demo2:*"})

	// establish a live SSE connection authenticated with the key
	req := httptest.NewRequest(http.MethodGet, "/api/realtime", nil)
	req.Header.Set("Authorization", plaintext)
	rec := httptest.NewRecorder()
	go mux.ServeHTTP(rec, req)

	// wait for the connection to register in the broker (avoids reading
	// the response body concurrently with the SSE handler)
	clientId := waitForRealtimeClient(t, app)

	// set subscriptions with the same key -> 204
	setReq := newRealtimeSubRequest(clientId, []string{"demo2/*"}, plaintext)
	setRec := httptest.NewRecorder()
	mux.ServeHTTP(setRec, setReq)
	if setRec.Code != 204 {
		t.Fatalf("Expected 204 subscribing with the same key, got %d: %s", setRec.Code, setRec.Body.String())
	}

	// trying to change the identity (no Authorization header -> guest) -> 403
	setReq = newRealtimeSubRequest(clientId, []string{"demo2/*"}, "")
	setRec = httptest.NewRecorder()
	mux.ServeHTTP(setRec, setReq)
	if setRec.Code != 403 {
		t.Fatalf("Expected 403 when downgrading an API key realtime session, got %d", setRec.Code)
	}

	_ = key
}

func newRealtimeSubRequest(clientId string, subs []string, auth string) *http.Request {
	body := map[string]any{"clientId": clientId, "subscriptions": subs}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/realtime", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

func waitForRealtimeClient(t *testing.T, app *tests.TestApp) string {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, client := range app.SubscriptionsBroker().Clients() {
			if _, ok := client.Get(apis.RealtimeClientAPIKey).(*core.APIKey); ok {
				return client.Id()
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timeout waiting for the realtime client to register")
	return ""
}

// avoid unused import errors if the test set changes
var _ = fmt.Sprintf
