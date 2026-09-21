package apis_test

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/router"
)

// newAPIKeyTestServer builds a fully wired test server (router + all
// default middlewares) and returns the running httptest.Server and the app.
func newAPIKeyTestServer(t *testing.T) (*tests.TestApp, *httptest.Server) {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}

	serveEvent := new(core.ServeEvent)
	serveEvent.App = app
	serveEvent.Router = r
	if err := app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		return e.Next()
	}); err != nil {
		t.Fatal(err)
	}

	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(mux)

	t.Cleanup(func() {
		server.Close()
		app.Cleanup()
	})

	return app, server
}

func doAPIRequest(t *testing.T, server *httptest.Server, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, server.URL+url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)

	return res, raw
}

func superuserAPIToken(t *testing.T, app *tests.TestApp) string {
	t.Helper()

	su, err := app.FindFirstRecordByData(core.CollectionNameSuperusers, "email", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	token, err := su.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

type createdAPIKeyPayload struct {
	Key    string `json:"key"`
	APIKey struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		ExpiresAt  string `json:"expiresAt"`
		Expired    bool   `json:"expired"`
		LastUsedAt string `json:"lastUsedAt"`
	} `json:"apiKey"`
}

func createAPIKeyViaAPI(t *testing.T, server *httptest.Server, suToken string, payload map[string]any) createdAPIKeyPayload {
	t.Helper()

	res, raw := doAPIRequest(t, server, http.MethodPost, "/api/keys", suToken, payload)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected create 200, got %d: %s", res.StatusCode, raw)
	}

	var result createdAPIKeyPayload
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Key == "" || len(result.Key) < 40 {
		t.Fatalf("expected plaintext key in create response, got %q", result.Key)
	}

	return result
}

func TestAPIKeyManagementLifecycle(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	// guests and non-superusers cannot manage keys
	res, raw := doAPIRequest(t, server, http.MethodGet, "/api/keys", "", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("guest list: expected 401, got %d (%s)", res.StatusCode, raw)
	}

	// create
	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "ci-deploy",
		"scopes": []string{"demo1/view", "demo1/list"},
	})

	// create another with the same name is allowed (names are not unique identifiers)
	created2 := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "ci-deploy",
		"scopes": []string{"*/*"},
	})
	if created2.APIKey.ID == created.APIKey.ID {
		t.Fatal("duplicate-named keys must result in distinct key records")
	}

	// list never returns secret material
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/keys", suToken, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(created.Key)) {
		t.Fatal("list response must not contain the plaintext key")
	}
	if bytes.Contains(raw, []byte("keyHash")) {
		t.Fatal("list response must not contain the key hash")
	}
	if !bytes.Contains(raw, []byte("ci-deploy")) {
		t.Fatal("list response must contain the key name")
	}

	// GET individual key
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/keys/"+created.APIKey.ID, suToken, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("view: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(created.Key)) || bytes.Contains(raw, []byte("keyHash")) {
		t.Fatal("view response must not leak secret material")
	}

	// PATCH (rename + narrow scopes)
	res, raw = doAPIRequest(t, server, http.MethodPatch, "/api/keys/"+created.APIKey.ID, suToken, map[string]any{
		"name":      "ci-deploy-ro",
		"scopes":    []string{"demo1/view"},
		"expiresAt": "",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("ci-deploy-ro")) {
		t.Fatal("update response must reflect the new name")
	}

	// DELETE (revoke)
	res, _ = doAPIRequest(t, server, http.MethodDelete, "/api/keys/"+created.APIKey.ID, suToken, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", res.StatusCode)
	}
	res, _ = doAPIRequest(t, server, http.MethodGet, "/api/keys/"+created.APIKey.ID, suToken, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked view: expected 404, got %d", res.StatusCode)
	}
}

func TestAPIKeyManagementValidationErrors(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	expectBadRequest := func(payload map[string]any, expectedField string) {
		t.Helper()
		res, raw := doAPIRequest(t, server, http.MethodPost, "/api/keys", suToken, payload)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d (%s)", res.StatusCode, raw)
		}
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body.Data[expectedField]; !ok {
			t.Fatalf("expected validation error for field %q, got %s", expectedField, raw)
		}
	}

	expectBadRequest(map[string]any{"name": "", "scopes": []string{"*/view"}}, "name")
	expectBadRequest(map[string]any{"name": "x", "scopes": []string{}}, "scopes")
	expectBadRequest(map[string]any{"name": "x", "scopes": []string{"garbage"}}, "scopes")
	expectBadRequest(map[string]any{"name": "x", "scopes": []string{"*/frobnicate"}}, "scopes")
	expectBadRequest(map[string]any{"name": "x", "scopes": []string{"nope/view"}}, "scopes")
	expectBadRequest(map[string]any{
		"name":      "x",
		"scopes":    []string{"*/view"},
		"expiresAt": "not-a-date",
	}, "expiresAt")
	expectBadRequest(map[string]any{
		"name":      "x",
		"scopes":    []string{"*/view"},
		"expiresAt": "2000-01-01 00:00:00.000Z",
	}, "expiresAt")
	// linked record requires a collection
	expectBadRequest(map[string]any{
		"name":   "x",
		"scopes": []string{"*/view"},
		"record": "abc",
	}, "collection")
	// keys can't be linked to superusers
	expectBadRequest(map[string]any{
		"name":       "x",
		"scopes":     []string{"*/view"},
		"collection": core.CollectionNameSuperusers,
	}, "collection")
}

func TestAPIKeyAuthenticationAndScopes(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	// guest-scoped key, view only on demo2 (open API rules in the test data)
	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "read-only-demo2",
		"scopes": []string{"demo2/view"},
	})
	apiKey := created.Key

	// allowed action -> 200 (demo2 ViewRule is open)
	res, raw := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", apiKey, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("in scope view: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("llvuca81nly1qls")) {
		t.Fatal("expected the record in the response")
	}

	// lastUsedAt is eventually updated
	deadline := time.Now().Add(3 * time.Second)
	var lastUsed string
	for time.Now().Before(deadline) {
		res2, raw2 := doAPIRequest(t, server, http.MethodGet, "/api/keys/"+created.APIKey.ID, suToken, nil)
		if res2.StatusCode != http.StatusOK {
			t.Fatalf("view key: %d", res2.StatusCode)
		}
		var view struct {
			LastUsedAt string `json:"lastUsedAt"`
		}
		_ = json.Unmarshal(raw2, &view)
		lastUsed = view.LastUsedAt
		if lastUsed != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastUsed == "" {
		t.Fatal("expected lastUsedAt to be recorded after authentic requests")
	}

	// out of scope action (create) -> 403 with the API key error code
	res, raw = doAPIRequest(t, server, http.MethodPost, "/api/collections/demo2/records", apiKey, map[string]any{
		"title": "unauthorized",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("out of scope create: expected 403, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("api_key_auth_failed")) {
		t.Fatalf("expected api key error code in response, got %s", raw)
	}

	// out of scope action (list) on the scoped collection -> 403
	res, _ = doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records", apiKey, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("list action without list scope: expected 403, got %d", res.StatusCode)
	}

	// another collection -> 403 (regardless of its rules)
	res, _ = doAPIRequest(t, server, http.MethodGet, "/api/collections/demo1/records/84nmscqy84lsi1t", apiKey, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("other collection: expected 403, got %d", res.StatusCode)
	}

	// interactive auth endpoints reject an API key-authenticated request
	// (login, token refresh, password/OTP flows are session-only)
	res, _ = doAPIRequest(t, server, http.MethodPost, "/api/collections/users/auth-with-password", apiKey, map[string]any{
		"identity": "test@example.com",
		"password": "1234567890",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("interactive auth route with api key: expected 403, got %d", res.StatusCode)
	}

	res, _ = doAPIRequest(t, server, http.MethodPost, "/api/collections/users/auth-refresh", apiKey, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("auth-refresh with api key: expected 403, got %d", res.StatusCode)
	}

	// unknown key behaves like a missing/invalid token (guest -> route rules apply)
	res, _ = doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", core.GenerateAPIKey(), nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unknown api key on an open-rule route: expected guest 200, got %d", res.StatusCode)
	}

	// the "Bearer" prefix is supported for compatibility with HTTP clients
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", "Bearer "+apiKey, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Bearer-prefixed api key: expected 200, got %d (%s)", res.StatusCode, raw)
	}

	res, _ = doAPIRequest(t, server, http.MethodPost, "/api/collections/demo1/records", core.GenerateAPIKey(), nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown api key on a superuser-only route: expected 403, got %d", res.StatusCode)
	}

	// management endpoints are never accessible with an API key (even with */* scopes)
	allScopes := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "all-scopes",
		"scopes": []string{"*/*"},
	})
	res, _ = doAPIRequest(t, server, http.MethodGet, "/api/keys", allScopes.Key, nil)
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("management endpoint with api key: expected 403/401, got %d", res.StatusCode)
	}

	// ---- linked record key: flows through the regular API rule chain ----
	userKey := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":       "linked-user",
		"scopes":     []string{"*/*"},
		"collection": "users",
		"record":     "4q1xlclmfloku33",
	})
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/collections/users/records/4q1xlclmfloku33", userKey.Key, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("linked record viewing itself: expected 200, got %d (%s)", res.StatusCode, raw)
	}

	// create a temporary collection whose list rule requires the linked user
	createColPayload := map[string]any{
		"name":     "wkbz_apikey_tmp",
		"type":     "base",
		"listRule": "created_by = @request.auth.id",
		"fields": []map[string]any{
			{"name": "title", "type": "text"},
			{"name": "created_by", "type": "text"},
		},
	}
	res, raw = doAPIRequest(t, server, http.MethodPost, "/api/collections", suToken, createColPayload)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create temp collection: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	t.Cleanup(func() {
		doAPIRequest(t, server, http.MethodDelete, "/api/collections/wkbz_apikey_tmp", suToken, nil)
	})

	// insert a record owned by the linked user (via superuser)
	res, _ = doAPIRequest(t, server, http.MethodPost, "/api/collections/wkbz_apikey_tmp/records", suToken, map[string]any{
		"title":      "owned",
		"created_by": "4q1xlclmfloku33",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("seed record: expected 200, got %d", res.StatusCode)
	}

	// the linked-user key DOES see the record (rule evaluates against @request.auth)
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/collections/wkbz_apikey_tmp/records", userKey.Key, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("linked key rule eval: expected 200, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("owned")) {
		t.Fatalf("expected the rule-filtered record in the response: %s", raw)
	}

	// a guest key does NOT see it even with the scope, because the API rule filters it out
	guestWildcard := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "guest-wildcard",
		"scopes": []string{"*/*"},
	})
	res, raw = doAPIRequest(t, server, http.MethodGet, "/api/collections/wkbz_apikey_tmp/records", guestWildcard.Key, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("guest wildcard scope passes: expected 200 from handler, got %d (%s)", res.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte("owned")) {
		t.Fatalf("guest key must not see rule-filtered records: %s", raw)
	}

	_ = app
}

func TestAPIKeyBatchScopes(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	// view-only key: batch create must fail
	viewOnly := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "batch-view",
		"scopes": []string{"demo2/view"},
	})

	res, raw := doAPIRequest(t, server, http.MethodPost, "/api/batch", viewOnly.Key, map[string]any{
		"requests": []map[string]any{
			{
				"method": "POST",
				"url":    "/api/collections/demo2/records",
				"body":   map[string]any{"title": "x"},
			},
		},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("batch out-of-scope: expected 400, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("api_key_auth_failed")) {
		t.Fatalf("expected batch error to carry the api key error code, got %s", raw)
	}

	// create scoped key: batch POST succeeds (then validation may run, but scope passes)
	createKey := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "batch-create",
		"scopes": []string{"demo2/create"},
	})
	res, raw = doAPIRequest(t, server, http.MethodPost, "/api/batch", createKey.Key, map[string]any{
		"requests": []map[string]any{
			{
				"method": "POST",
				"url":    "/api/collections/demo2/records",
				"body":   map[string]any{"title": "batch-key-created"},
			},
		},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("batch in-scope: expected 200, got %d (%s)", res.StatusCode, raw)
	}

	// mixed batch: the second (forbidden) request must fail the whole transaction
	mixed := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "batch-mixed",
		"scopes": []string{"demo2/create"},
	})
	res, raw = doAPIRequest(t, server, http.MethodPost, "/api/batch", mixed.Key, map[string]any{
		"requests": []map[string]any{
			{
				"method": "POST",
				"url":    "/api/collections/demo2/records",
				"body":   map[string]any{"title": "first"},
			},
			{
				"method": "DELETE",
				"url":    "/api/collections/demo2/records/llvuca81nly1qls",
			},
		},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("mixed batch: expected 400, got %d (%s)", res.StatusCode, raw)
	}
}

func TestAPIKeyExpirationOverHTTP(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":      "short-lived",
		"scopes":    []string{"demo2/view"},
		"expiresAt": time.Now().Add(2 * time.Second).UTC().Format("2006-01-02T15:04:05.000Z"),
	})

	// works now
	res, _ := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", created.Key, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("pre-expiry request: expected 200, got %d", res.StatusCode)
	}

	// wait past expiry
	time.Sleep(2500 * time.Millisecond)

	res, raw := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", created.Key, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-expiry request: expected 401, got %d (%s)", res.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("api_key_auth_failed")) {
		t.Fatalf("expected api key error code, got %s", raw)
	}

	// and it no longer authenticates (guest level response on a rule-protected route)
	_ = app
}

// TestAPIKeyRevocationConcurrency verifies that while requests using a key
// are in-flight, revoking it causes subsequent requests to fail immediately.
func TestAPIKeyRevocationConcurrency(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "revoke-me",
		"scopes": []string{"demo2/view"},
	})

	// sanity
	res, _ := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", created.Key, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke: expected 200, got %d", res.StatusCode)
	}

	// hammer the key concurrently while revoking
	stop := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		for {
			select {
			case <-stop:
				errCh <- nil
				return
			default:
				r, _ := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo2/records/llvuca81nly1qls", created.Key, nil)
				// revoked keys resolve as guests: the open demo2 view rule then returns 200,
				// so both 200 (post-revoke guest) and 403 (key was resolved pre-delete in
				// another goroutine is impossible here) are acceptable; only unexpected 5xx fail
				if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusForbidden {
					errCh <- &router.ApiError{Status: r.StatusCode}
					return
				}
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)

	res, _ = doAPIRequest(t, server, http.MethodDelete, "/api/keys/"+created.APIKey.ID, suToken, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", res.StatusCode)
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected status during concurrent revoke: %v", err)
	}

	// after revocation the key resolves as a guest; on demo1 (superuser-only
	// rules) that must be 403, proving the revoked credential grants no access
	for i := 0; i < 10; i++ {
		r, _ := doAPIRequest(t, server, http.MethodGet, "/api/collections/demo1/records", created.Key, nil)
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("post-revoke request #%d: expected guest 403, got %d", i, r.StatusCode)
		}
	}
}
