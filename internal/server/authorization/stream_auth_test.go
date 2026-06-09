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
	"github.com/glimesh/broadcast-box/internal/server/webhook"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthenticateStreamRequestPlainTokenWhenJWTDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/whip", nil)
	req.Header.Set("Authorization", "Bearer stream_key")

	authInfo, err := AuthenticateStreamRequest(req, webhook.WHIPConnect)
	if err != nil {
		t.Fatalf("AuthenticateStreamRequest() returned error: %v", err)
	}

	if authInfo.StreamKey != "stream_key" {
		t.Fatalf("stream key = %q, want %q", authInfo.StreamKey, "stream_key")
	}

	if authInfo.IsJwt {
		t.Fatal("expected plain token auth, got JWT auth")
	}
}

func TestAuthenticateStreamRequestRejectsEmptyAuthorization(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/whip", nil)

	if _, err := AuthenticateStreamRequest(req, webhook.WHIPConnect); err == nil {
		t.Fatal("expected empty authorization to fail")
	}
}

func TestAuthenticateStreamRequestWithJWTAccessTypes(t *testing.T) {
	privateKey, publicKeyPEM := generateTestECDSAKey(t)
	t.Setenv(environment.JWTPublicKey, strings.ReplaceAll(string(publicKeyPEM), "\n", "\\n"))

	whipToken := signTestJWT(t, privateKey, "session_123", "lh-user", "whip")
	whipReq := httptest.NewRequest(http.MethodPost, "/api/whip", nil)
	whipReq.Header.Set("Authorization", "Bearer "+whipToken)

	authInfo, err := AuthenticateStreamRequest(whipReq, webhook.WHIPConnect)
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
		t.Fatal("expected JWT auth")
	}

	whepReq := httptest.NewRequest(http.MethodPost, "/api/whep", nil)
	whepReq.Header.Set("Authorization", "Bearer "+whipToken)

	if _, err := AuthenticateStreamRequest(whepReq, webhook.WHEPConnect); err == nil {
		t.Fatal("expected WHIP token to fail WHEP auth")
	}

	whepToken := signTestJWT(t, privateKey, "session_123", "lh-user", "whep")
	whepReq.Header.Set("Authorization", "Bearer "+whepToken)

	if _, err := AuthenticateStreamRequest(whepReq, webhook.WHEPConnect); err != nil {
		t.Fatalf("expected WHEP token to pass WHEP auth: %v", err)
	}
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

func signTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey, sessionID, lhUserID, accessType string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, JwtPayload{
		SessionId:  sessionID,
		LhUserId:   lhUserID,
		AccessType: accessType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	return tokenString
}
