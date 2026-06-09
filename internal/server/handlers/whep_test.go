package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glimesh/broadcast-box/internal/environment"
)

type whepWebhookPayload struct {
	Action      string            `json:"action"`
	BearerToken string            `json:"bearerToken"`
	QueryParams map[string]string `json:"queryParams"`
}

func TestWHEPHandlerCallsWebhook(t *testing.T) {
	payloads := make(chan whepWebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			_ = r.Body.Close()
		}()

		var payload whepWebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}

		payloads <- payload
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	t.Setenv(environment.WebhookURL, server.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/whep?viewer=1", strings.NewReader("v=0"))
	req.Header.Set("Authorization", "Bearer test_stream_key")
	req.Header.Set("User-Agent", "whep-handler-test")
	req.RemoteAddr = "203.0.113.10:1234"

	resp := httptest.NewRecorder()
	whepHandler(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}

	select {
	case payload := <-payloads:
		if payload.Action != "whep-connect" {
			t.Fatalf("expected action %q, got %q", "whep-connect", payload.Action)
		}

		if payload.BearerToken != "test_stream_key" {
			t.Fatalf("expected bearer token %q, got %q", "test_stream_key", payload.BearerToken)
		}

		if payload.QueryParams["viewer"] != "1" {
			t.Fatalf("expected query param %q, got %q", "1", payload.QueryParams["viewer"])
		}
	default:
		t.Fatal("expected webhook to be called")
	}
}
