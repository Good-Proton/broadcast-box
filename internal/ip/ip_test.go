package ip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimesh/broadcast-box/internal/environment"
)

func TestGetPublicIPFromJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"query":"203.0.113.10"}`))
	}))
	defer server.Close()

	t.Setenv(environment.PublicIpApiUrl, server.URL)

	if got := GetPublicIP(); got != "203.0.113.10" {
		t.Fatalf("GetPublicIP() = %q, want %q", got, "203.0.113.10")
	}
}

func TestGetPublicIPFromPlainTextResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.11\n"))
	}))
	defer server.Close()

	t.Setenv(environment.PublicIpApiUrl, server.URL)

	if got := GetPublicIP(); got != "203.0.113.11" {
		t.Fatalf("GetPublicIP() = %q, want %q", got, "203.0.113.11")
	}
}
