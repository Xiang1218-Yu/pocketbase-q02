package apis_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

type sseConnection struct {
	mu       sync.Mutex
	clientID string
	events   chan string // raw "event:<name>" lines

	cancel context.CancelFunc
	done   chan struct{}
}

// connectSSE opens an SSE connection with the given token, waits for PB_CONNECT
// and returns a helper that continuously drains the SSE stream into events.
func connectSSE(t *testing.T, serverURL, token string) *sseConnection {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/api/realtime", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		raw := make([]byte, 256)
		n, _ := res.Body.Read(raw)
		cancel()
		res.Body.Close()
		t.Fatalf("SSE connect expected 200, got %d: %s", res.StatusCode, raw[:n])
	}

	conn := &sseConnection{
		events: make(chan string, 64),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(conn.done)
		defer res.Body.Close()

		scanner := bufio.NewScanner(res.Body)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "event:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				if name == "PB_CONNECT" {
					continue
				}
				select {
				case conn.events <- name:
				default:
				}
			}
			if strings.HasPrefix(line, "data:") && strings.Contains(line, "clientId") {
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				var msg struct {
					ClientID string `json:"clientId"`
				}
				if json.Unmarshal([]byte(payload), &msg) == nil && msg.ClientID != "" {
					conn.mu.Lock()
					if conn.clientID == "" {
						conn.clientID = msg.ClientID
					}
					conn.mu.Unlock()
				}
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn.mu.Lock()
		id := conn.clientID
		conn.mu.Unlock()
		if id != "" {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for PB_CONNECT")
		}
		time.Sleep(10 * time.Millisecond)
	}

	return conn
}

func (c *sseConnection) id() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientID
}

func (c *sseConnection) close() {
	c.cancel()
}

func postSSESubscription(t *testing.T, serverURL, token, clientID string, subs []string) (*http.Response, []byte) {
	t.Helper()

	raw, err := json.Marshal(map[string]any{"clientId": clientID, "subscriptions": subs})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/realtime", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)

	return res, buf[:n]
}

func TestAPIKeyRealtimeConnectSubscribeAndRevoke(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":   "sse-key",
		"scopes": []string{"demo2/view"},
	})

	// connect with the key
	conn := connectSSE(t, server.URL, created.Key)
	defer conn.close()

	if len(app.SubscriptionsBroker().Clients()) != 1 {
		t.Fatalf("expected 1 connected client, got %d", len(app.SubscriptionsBroker().Clients()))
	}

	client, err := app.SubscriptionsBroker().ClientById(conn.id())
	if err != nil {
		t.Fatal(err)
	}

	storedKeyID, _ := client.Get(core.RealtimeClientAPIKeyIdKey).(string)
	if storedKeyID != created.APIKey.ID {
		t.Fatalf("expected client to carry the api key id %q, got %q", created.APIKey.ID, storedKeyID)
	}

	// subscribe to an in-scope topic
	res, _ := postSSESubscription(t, server.URL, created.Key, conn.id(), []string{"demo2/llvuca81nly1qls"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("in-scope subscription: expected 204, got %d", res.StatusCode)
	}

	// subscribe to an out-of-scope topic -> 403
	res, raw := postSSESubscription(t, server.URL, created.Key, conn.id(), []string{"demo1/84nmscqy84lsi1t"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope subscription: expected 403, got %d (%s)", res.StatusCode, raw)
	}

	// a subscription request without the API key cannot hijack the connection
	res, _ = postSSESubscription(t, server.URL, "", conn.id(), []string{"demo2/llvuca81nly1qls"})
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("subscription without key: expected 403/401, got %d", res.StatusCode)
	}

	// broadcast an update for the subscribed record (save triggers realtime update events)
	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := app.FindRecordById(demo2, "llvuca81nly1qls")
	if err != nil {
		t.Fatal(err)
	}
	rec.Set("title", "updated-by-test-"+randomSuffix())
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}

	// the API key client must receive the broadcast event
	select {
	case name := <-conn.events:
		if !strings.Contains(name, "demo2") {
			t.Fatalf("expected demo2 event, got %q", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the realtime record event")
	}

	// revoke while connected: the client must be discarded and the SSE loop terminated
	res, _ = doAPIRequest(t, server, http.MethodDelete, "/api/keys/"+created.APIKey.ID, suToken, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", res.StatusCode)
	}

	select {
	case <-conn.done:
		// connection was closed - good
	case <-time.After(3 * time.Second):
		t.Fatal("expected the SSE connection to be closed after revocation")
	}

	brokerClient, err := app.SubscriptionsBroker().ClientById(conn.id())
	if err == nil && !brokerClient.IsDiscarded() {
		t.Fatal("expected the realtime client to be discarded after revocation")
	}
}

func TestAPIKeyRealtimeExpiredKeyRejected(t *testing.T) {
	t.Parallel()

	app, server := newAPIKeyTestServer(t)
	suToken := superuserAPIToken(t, app)

	created := createAPIKeyViaAPI(t, server, suToken, map[string]any{
		"name":      "sse-exp",
		"scopes":    []string{"demo2/view"},
		"expiresAt": time.Now().Add(1500 * time.Millisecond).UTC().Format("2006-01-02T15:04:05.000Z"),
	})

	// connected while still valid
	conn := connectSSE(t, server.URL, created.Key)
	defer conn.close()

	res, _ := postSSESubscription(t, server.URL, created.Key, conn.id(), []string{"demo2/llvuca81nly1qls"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("pre-expiry subscription: expected 204, got %d", res.StatusCode)
	}

	// wait until the key expires
	time.Sleep(1800 * time.Millisecond)

	// an already open connection is rejected on the NEXT subscription request
	res, raw := postSSESubscription(t, server.URL, created.Key, conn.id(), []string{"demo2/achvryl401bhse3"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-expiry subscription: expected 401, got %d (%s)", res.StatusCode, raw)
	}

	select {
	case <-conn.done:
		// client discarded -> connection closes
	case <-time.After(3 * time.Second):
		t.Fatal("expected the SSE connection to be closed after expired-key subscription")
	}

	// a brand new connection with an expired key is rejected immediately
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/realtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", created.Key)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("connect with expired key: expected 401, got %d", res2.StatusCode)
	}
}

func randomSuffix() string {
	return strings.ReplaceAll(time.Now().Format("15:04:05.000000000"), ":", "")
}
