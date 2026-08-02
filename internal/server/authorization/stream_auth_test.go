package authorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthenticateStreamRequestAcceptsWHIPJWT(t *testing.T) {
	privateKey := configureAuthorization(t, "203.0.113.10")
	token := signTestJWT(t, privateKey, "session_123", "lh-user", "whip", "", time.Hour, "203.0.113.10")
	req := requestWithToken(http.MethodPost, "/api/whip", token)

	authInfo, err := AuthenticateStreamRequest(req, WHIPConnect)
	if err != nil {
		t.Fatalf("AuthenticateStreamRequest() returned error: %v", err)
	}

	if authInfo.StreamKey != "session_123" {
		t.Fatalf("stream key = %q, want %q", authInfo.StreamKey, "session_123")
	}
	if authInfo.LhUserId != "lh-user" {
		t.Fatalf("lh user id = %q, want %q", authInfo.LhUserId, "lh-user")
	}
	if !authInfo.IsJwt {
		t.Fatal("expected JWT authentication mode")
	}
	if authInfo.AllowWHEPDataChannelMessageSending() {
		t.Fatal("expected WHIP auth to deny WHEP data channel messages")
	}
}

func TestAuthenticateStreamRequestAcceptsPlainTokenWhenJWTDisabled(t *testing.T) {
	t.Setenv(environment.JWTPublicKey, "")

	authInfo, err := AuthenticateStreamRequest(
		requestWithToken(http.MethodPost, "/api/whip", "legacy_stream_key"),
		WHIPConnect,
	)
	if err != nil {
		t.Fatalf("AuthenticateStreamRequest() returned error: %v", err)
	}

	if authInfo.StreamKey != "legacy_stream_key" {
		t.Fatalf("stream key = %q, want legacy_stream_key", authInfo.StreamKey)
	}
	if authInfo.IsJwt {
		t.Fatal("expected legacy authentication mode")
	}
	if !authInfo.AllowWHEPDataChannelMessageSending() {
		t.Fatal("expected legacy authentication to allow WHEP data channel messages")
	}
}

func TestAuthenticateStreamRequestAcceptsWHEPRoles(t *testing.T) {
	privateKey := configureAuthorization(t, "203.0.113.10")

	tests := []struct {
		name          string
		role          string
		allowsSending bool
	}{
		{name: "viewer", role: WHEPAccessTypeViewer, allowsSending: false},
		{name: "editor", role: WHEPAccessTypeEditor, allowsSending: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signTestJWT(t, privateKey, "session_123", "lh-user", "whep", test.role, time.Hour, "203.0.113.10")
			authInfo, err := AuthenticateStreamRequest(
				requestWithToken(http.MethodPost, "/api/whep", token),
				WHEPConnect,
			)
			if err != nil {
				t.Fatalf("AuthenticateStreamRequest() returned error: %v", err)
			}
			if authInfo.AllowWHEPDataChannelMessageSending() != test.allowsSending {
				t.Fatalf("data channel permission = %t, want %t", authInfo.AllowWHEPDataChannelMessageSending(), test.allowsSending)
			}
		})
	}
}

func TestAuthenticateStreamRequestRejectsInvalidJWTContract(t *testing.T) {
	privateKey := configureAuthorization(t, "203.0.113.10")
	otherKey, _ := generateTestECDSAKey(t)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "wrong signature",
			token: signTestJWT(t, otherKey, "session_123", "lh-user", "whip", "", time.Hour, "203.0.113.10"),
		},
		{
			name:  "expired",
			token: signTestJWT(t, privateKey, "session_123", "lh-user", "whip", "", -time.Hour, "203.0.113.10"),
		},
		{
			name:  "wrong worker address",
			token: signTestJWT(t, privateKey, "session_123", "lh-user", "whip", "", time.Hour, "203.0.113.11"),
		},
		{
			name:  "invalid WHEP role",
			token: signTestJWT(t, privateKey, "session_123", "lh-user", "whep", "admin", time.Hour, "203.0.113.10"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AuthenticateStreamRequest(
				requestWithToken(http.MethodPost, "/api/whip", test.token),
				WHIPConnect,
			); err == nil {
				t.Fatal("expected invalid JWT contract to fail")
			}
		})
	}
}

func TestAuthenticateStreamRequestRejectsWrongAction(t *testing.T) {
	privateKey := configureAuthorization(t, "203.0.113.10")
	token := signTestJWT(t, privateKey, "session_123", "lh-user", "whip", "", time.Hour, "203.0.113.10")

	if _, err := AuthenticateStreamRequest(
		requestWithToken(http.MethodPost, "/api/whep", token),
		WHEPConnect,
	); err == nil {
		t.Fatal("expected a WHIP token to fail WHEP authentication")
	}
}

func TestAuthenticateStreamRequestRejectsPlainToken(t *testing.T) {
	configureAuthorization(t, "203.0.113.10")

	if _, err := AuthenticateStreamRequest(
		requestWithToken(http.MethodPost, "/api/whip", "stream_key"),
		WHIPConnect,
	); err == nil {
		t.Fatal("expected a plain stream token to fail")
	}
}

func TestAuthenticateStreamRequestRejectsEmptyAuthorization(t *testing.T) {
	configureAuthorization(t, "203.0.113.10")
	req := httptest.NewRequest(http.MethodPost, "/api/whip", nil)

	if _, err := AuthenticateStreamRequest(req, WHIPConnect); err == nil {
		t.Fatal("expected empty authorization to fail")
	}
}

func TestInitializeFailsWithoutAdvertisedAddress(t *testing.T) {
	_, publicKeyPEM := generateTestECDSAKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, "")
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")

	if err := Initialize(); err == nil {
		t.Fatal("expected startup authorization to require an advertised address")
	}
}

func TestAdvertisedAddressUsesStartupCache(t *testing.T) {
	configureAuthorization(t, "203.0.113.10")
	t.Setenv(environment.NAT1To1IP, "203.0.113.11")

	if got := AdvertisedAddress(); got != "203.0.113.10" {
		t.Fatalf("AdvertisedAddress() = %q, want startup address", got)
	}
}

func configureAuthorization(t *testing.T, advertisedIP string) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, publicKeyPEM := generateTestECDSAKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))
	t.Setenv(environment.NAT1To1IP, advertisedIP)
	t.Setenv(environment.IncludePublicIPInNAT1To1IP, "")
	t.Setenv(environment.PublicIpApiUrl, "")
	if err := Initialize(); err != nil {
		t.Fatalf("Initialize() returned error: %v", err)
	}

	return privateKey
}

func requestWithToken(method, path, token string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func generateTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return privateKey, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})
}

func signTestJWT(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	sessionID string,
	lhUserID string,
	accessType string,
	whepAccessType string,
	expiresIn time.Duration,
	workerIP string,
) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, JwtPayload{
		SessionId:      sessionID,
		LhUserId:       lhUserID,
		AccessType:     accessType,
		WHEPAccessType: whepAccessType,
		WorkerIp:       workerIP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		},
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	return tokenString
}
