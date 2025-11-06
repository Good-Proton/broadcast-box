package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/config"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	logger.MustInitialize()
	code := m.Run()
	_ = logger.Sync()
	os.Exit(code)
}

func TestVerifyJwtToken(t *testing.T) {
	primaryKey, primaryPublicKey := generateES256KeyPair(t)
	secondaryKey, _ := generateES256KeyPair(t)

	t.Run("config not loaded", func(t *testing.T) {
		payload, err := VerifyJwtToken("token")
		require.Error(t, err)
		require.Nil(t, payload)
	})

	t.Run("returns error when public key missing", func(t *testing.T) {
		loadConfigWithPublicKey(t, "")

		payload, err := VerifyJwtToken("token")
		require.ErrorIs(t, err, jwt.ErrInvalidKey)
		require.Nil(t, payload)
	})

	t.Run("fails to parse malformed token", func(t *testing.T) {
		loadConfigWithPublicKey(t, primaryPublicKey)

		payload, err := VerifyJwtToken("not-a-token")
		require.Error(t, err)
		require.Nil(t, payload)
	})

	t.Run("rejects token with invalid signature", func(t *testing.T) {
		loadConfigWithPublicKey(t, primaryPublicKey)

		tokenString := signToken(t, secondaryKey, JwtPayload{
			SessionId:  "session-123",
			LhUserId:   "user-456",
			AccessType: "whip",
			WorkerIp:   "198.51.100.2",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})

		payload, err := VerifyJwtToken(tokenString)
		require.Error(t, err)
		require.Nil(t, payload)
	})

	t.Run("parses valid token", func(t *testing.T) {
		loadConfigWithPublicKey(t, primaryPublicKey)

		expectedClaims := JwtPayload{
			SessionId:  "session-abc",
			LhUserId:   "99",
			AccessType: "whep",
			WorkerIp:   "198.51.100.3",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				Subject:   "stream",
			},
		}

		tokenString := signToken(t, primaryKey, expectedClaims)

		payload, err := VerifyJwtToken(tokenString)
		require.NoError(t, err)
		require.NotNil(t, payload)
		require.Equal(t, expectedClaims.SessionId, payload.SessionId)
		require.Equal(t, expectedClaims.LhUserId, payload.LhUserId)
		require.Equal(t, expectedClaims.AccessType, payload.AccessType)
		require.Equal(t, expectedClaims.WorkerIp, payload.WorkerIp)
		require.Equal(t, expectedClaims.RegisteredClaims.Subject, payload.RegisteredClaims.Subject)
		require.NotNil(t, payload.RegisteredClaims.ExpiresAt)
		require.NotNil(t, payload.RegisteredClaims.IssuedAt)
		require.WithinDuration(t, expectedClaims.RegisteredClaims.ExpiresAt.Time, payload.RegisteredClaims.ExpiresAt.Time, time.Second)
		require.WithinDuration(t, expectedClaims.RegisteredClaims.IssuedAt.Time, payload.RegisteredClaims.IssuedAt.Time, time.Second)
	})
}

func loadConfigWithPublicKey(t *testing.T, publicKey string) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "198.51.100.10")
	}))
	t.Cleanup(server.Close)

	require.NoError(t, os.Setenv("PUBLIC_IP_API_URL", server.URL))
	require.NoError(t, os.Setenv("JWT_PUBLIC_KEY", publicKey))

	_, err := config.LoadConfig()
	require.NoError(t, err)
}

func generateES256KeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	require.NotEmpty(t, pemBytes)

	return key, string(pemBytes)
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, claims JwtPayload) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}
