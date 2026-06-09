package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
)

func TestStatusHandlerRequiresAuthWhenTokenConfigured(t *testing.T) {
	t.Setenv(environment.StatusAuthToken, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	resp := httptest.NewRecorder()

	statusHandler(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func TestStatusHandlerAllowsMatchingAuthToken(t *testing.T) {
	t.Setenv(environment.StatusAuthToken, "secret")
	manager.SessionsManager = &manager.SessionManager{}
	manager.SessionsManager.Setup()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp := httptest.NewRecorder()

	statusHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestStatusHandlerAllowsDisableStatusFalse(t *testing.T) {
	t.Setenv(environment.DisableStatus, "false")
	manager.SessionsManager = &manager.SessionManager{}
	manager.SessionsManager.Setup()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	resp := httptest.NewRecorder()

	statusHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestHealthcheckHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/healthcheck", nil)
	resp := httptest.NewRecorder()

	healthcheckHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestMetricsHandlerRequiresAuthWhenTokenConfigured(t *testing.T) {
	t.Setenv(environment.StatusAuthToken, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	resp := httptest.NewRecorder()

	metricsHandler(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func TestMetricsHandlerAllowsMatchingAuthToken(t *testing.T) {
	t.Setenv(environment.StatusAuthToken, "secret")
	manager.SessionsManager = &manager.SessionManager{}
	manager.SessionsManager.Setup()

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp := httptest.NewRecorder()

	metricsHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}
