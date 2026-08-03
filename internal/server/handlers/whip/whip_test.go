package whip

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
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestWHIPHandlerDeleteRequiresSessionID(t *testing.T) {
	configureWHIPAuthorization(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/whip/", nil)
	req.Header.Set("Authorization", "Bearer stream_key")

	resp := httptest.NewRecorder()
	WHIPHandler(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestWHIPHandlerDeleteUnknownSession(t *testing.T) {
	configureWHIPAuthorization(t)

	manager.SessionsManager = &manager.SessionManager{}
	manager.SessionsManager.Setup()

	req := httptest.NewRequest(http.MethodDelete, "/api/whip/unknown-session", nil)
	req.Header.Set("Authorization", "Bearer stream_key")

	resp := httptest.NewRecorder()
	WHIPHandler(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestWHIPHandlerRejectsPlainToken(t *testing.T) {
	configureWHIPAuthorization(t)

	req := httptest.NewRequest(http.MethodPost, "/api/whip", strings.NewReader("v=0"))
	req.Header.Set("Authorization", "Bearer stream_key")

	resp := httptest.NewRecorder()
	WHIPHandler(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestWHIPHandlerCallsOptionalWebhookAfterJWTAuth(t *testing.T) {
	privateKey, publicKeyPEM := generateWHIPTestKey(t)
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

	token := signWHIPTestJWT(t, privateKey)
	request := httptest.NewRequest(http.MethodPost, "/api/whip?publisher=1", strings.NewReader("v=0"))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "whip-handler-test")
	request.RemoteAddr = "203.0.113.10:1234"

	response := httptest.NewRecorder()
	WHIPHandler(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)

	select {
	case payload := <-payloads:
		require.Equal(t, "whip-connect", payload["action"])
		require.Equal(t, "session_123", payload["bearerToken"])
	case <-time.After(time.Second):
		t.Fatal("expected webhook to be called")
	}
}

func TestWHIPHandlerSkipsWebhookWhenURLIsUnset(t *testing.T) {
	privateKey, publicKeyPEM := generateWHIPTestKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, "203.0.113.10")
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")
	if err := authorization.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	called := make(chan struct{}, 1)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		called <- struct{}{}
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookServer.Close()
	t.Setenv(environment.WebhookURL, "")

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/whip",
		strings.NewReader("not-an-sdp"),
	)
	request.Header.Set("Authorization", "Bearer "+signWHIPTestJWT(t, privateKey))

	response := httptest.NewRecorder()
	WHIPHandler(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
	select {
	case <-called:
		t.Fatal("webhook must not be called when WEBHOOK_URL is empty")
	default:
	}
}

func configureWHIPAuthorization(t *testing.T) {
	t.Helper()

	_, publicKeyPEM := generateWHIPTestKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, "203.0.113.10")
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")
	if err := authorization.Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}
}

func generateWHIPTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

func signWHIPTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, authorization.JwtPayload{
		SessionId:  "session_123",
		LhUserId:   "lh-user",
		AccessType: "whip",
		WorkerIp:   "203.0.113.10",
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
