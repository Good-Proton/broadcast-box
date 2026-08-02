package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/server/authorization"
	"github.com/golang-jwt/jwt/v5"
)

func TestWHEPHandlerRejectsPlainToken(t *testing.T) {
	configureWHEPAuthorization(t)

	req := httptest.NewRequest(http.MethodPost, "/api/whep", strings.NewReader("v=0"))
	req.Header.Set("Authorization", "Bearer test_stream_key")

	resp := httptest.NewRecorder()
	whepHandler(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func configureWHEPAuthorization(t *testing.T) {
	t.Helper()

	_, publicKeyPEM := generateWHEPTestKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, "203.0.113.10")
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")
	if err := authorization.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}
}

func TestWHEPHandlerCallsOptionalWebhookAfterJWTAuth(t *testing.T) {
	privateKey, publicKeyPEM := generateWHEPTestKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, "203.0.113.10")
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")
	if err := authorization.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	payloads := make(chan map[string]any, 1)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() { _ = request.Body.Close() }()
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode webhook payload: %v", err)
			return
		}
		payloads <- payload
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer webhookServer.Close()
	t.Setenv(environment.WebhookURL, webhookServer.URL)

	token := signWHEPTestJWT(t, privateKey)
	request := httptest.NewRequest(http.MethodPost, "/api/whep?viewer=1", strings.NewReader("v=0"))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "whep-handler-test")
	request.RemoteAddr = "203.0.113.10:1234"

	response := httptest.NewRecorder()
	whepHandler(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}

	select {
	case payload := <-payloads:
		if payload["action"] != "whep-connect" {
			t.Fatalf("action = %v, want whep-connect", payload["action"])
		}
		if payload["bearerToken"] != "session_123" {
			t.Fatalf("bearerToken = %v, want resolved session key", payload["bearerToken"])
		}
		queryParams, ok := payload["queryParams"].(map[string]any)
		if !ok || queryParams["viewer"] != "1" {
			t.Fatalf("queryParams = %v, want viewer=1", payload["queryParams"])
		}
		if payload["advertiseAddress"] != "203.0.113.10" {
			t.Fatalf("advertiseAddress = %v, want startup-cached address", payload["advertiseAddress"])
		}
	default:
		t.Fatal("expected webhook to be called")
	}
}

func generateWHEPTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal test public key: %v", err)
	}

	return privateKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
}

func signWHEPTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, authorization.JwtPayload{
		SessionId:      "session_123",
		LhUserId:       "lh-user",
		AccessType:     "whep",
		WHEPAccessType: authorization.WHEPAccessTypeViewer,
		WorkerIp:       "203.0.113.10",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	value, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return value
}
