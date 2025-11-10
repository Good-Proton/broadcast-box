package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestGetStreamInfo(t *testing.T) {
	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.ErrorIs(t, err, errAuthorizationNotSet)
		require.Nil(t, streamInfo)
	})

	t.Run("missing bearer prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "test-key")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.ErrorIs(t, err, errInvalidStreamKey)
		require.Nil(t, streamInfo)
	})

	t.Run("invalid characters in stream key", func(t *testing.T) {
		setupBasicConfig(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer invalid key!")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.ErrorIs(t, err, errInvalidStreamKey)
		require.Nil(t, streamInfo)
	})

	t.Run("valid stream key without webhook or jwt", func(t *testing.T) {
		setupBasicConfig(t)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-stream-key-123")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.NoError(t, err)
		require.NotNil(t, streamInfo)
		require.Equal(t, "valid-stream-key-123", streamInfo.StreamKey)
		require.Equal(t, "", streamInfo.LhUserId)
	})

	t.Run("webhook transforms stream key", func(t *testing.T) {
		webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"streamKey": "transformed-key",
			})
		}))
		t.Cleanup(webhookServer.Close)

		setupConfigWithWebhook(t, webhookServer.URL)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer original-key")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.NoError(t, err)
		require.NotNil(t, streamInfo)
		require.Equal(t, "transformed-key", streamInfo.StreamKey)
		require.Equal(t, "", streamInfo.LhUserId)
	})

	t.Run("webhook error propagates", func(t *testing.T) {
		webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(webhookServer.Close)

		setupConfigWithWebhook(t, webhookServer.URL)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer test-key")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.Error(t, err)
		require.Nil(t, streamInfo)
	})

	t.Run("jwt validation extracts session id for whip", func(t *testing.T) {
		privateKey, publicKeyPEM := generateES256KeyPair(t)
		setupConfigWithJWT(t, publicKeyPEM)

		tokenString := signToken(t, privateKey, JwtPayload{
			SessionId:  "session-xyz",
			LhUserId:   "user-123",
			AccessType: "whip",
			WorkerIp:   "198.51.100.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.NoError(t, err)
		require.NotNil(t, streamInfo)
		require.Equal(t, "session-xyz", streamInfo.StreamKey)
		require.Equal(t, "user-123", streamInfo.LhUserId)
	})

	t.Run("jwt validation extracts session id for whep", func(t *testing.T) {
		privateKey, publicKeyPEM := generateES256KeyPair(t)
		setupConfigWithJWT(t, publicKeyPEM)

		tokenString := signToken(t, privateKey, JwtPayload{
			SessionId:  "session-abc",
			LhUserId:   "user-456",
			AccessType: "whep",
			WorkerIp:   "198.51.100.2",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		streamInfo, err := GetStreamInfo("whep-connect", req)
		require.NoError(t, err)
		require.NotNil(t, streamInfo)
		require.Equal(t, "session-abc", streamInfo.StreamKey)
		require.Equal(t, "user-456", streamInfo.LhUserId)
	})

	t.Run("jwt with wrong access type for whip", func(t *testing.T) {
		privateKey, publicKeyPEM := generateES256KeyPair(t)
		setupConfigWithJWT(t, publicKeyPEM)

		tokenString := signToken(t, privateKey, JwtPayload{
			SessionId:  "session-wrong",
			LhUserId:   "user-789",
			AccessType: "whep",
			WorkerIp:   "198.51.100.3",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.ErrorIs(t, err, errInvalidStreamKey)
		require.Nil(t, streamInfo)
	})

	t.Run("jwt with wrong access type for whep", func(t *testing.T) {
		privateKey, publicKeyPEM := generateES256KeyPair(t)
		setupConfigWithJWT(t, publicKeyPEM)

		tokenString := signToken(t, privateKey, JwtPayload{
			SessionId:  "session-bad",
			LhUserId:   "user-999",
			AccessType: "whip",
			WorkerIp:   "198.51.100.4",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		streamInfo, err := GetStreamInfo("whep-connect", req)
		require.ErrorIs(t, err, errInvalidStreamKey)
		require.Nil(t, streamInfo)
	})

	t.Run("jwt validation fails with invalid token", func(t *testing.T) {
		_, publicKeyPEM := generateES256KeyPair(t)
		setupConfigWithJWT(t, publicKeyPEM)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer invalid-jwt-token")

		streamInfo, err := GetStreamInfo("whip-connect", req)
		require.Error(t, err)
		require.Nil(t, streamInfo)
	})
}

func setupBasicConfig(t *testing.T) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "198.51.100.50")
	}))
	t.Cleanup(server.Close)

	require.NoError(t, os.Setenv("PUBLIC_IP_API_URL", server.URL))
	require.NoError(t, os.Setenv("JWT_PUBLIC_KEY", ""))
	require.NoError(t, os.Setenv("WEBHOOK_URL", ""))

	_, err := config.LoadConfig()
	require.NoError(t, err)
}

func setupConfigWithWebhook(t *testing.T, webhookURL string) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "198.51.100.51")
	}))
	t.Cleanup(server.Close)

	require.NoError(t, os.Setenv("PUBLIC_IP_API_URL", server.URL))
	require.NoError(t, os.Setenv("JWT_PUBLIC_KEY", ""))
	require.NoError(t, os.Setenv("WEBHOOK_URL", webhookURL))

	_, err := config.LoadConfig()
	require.NoError(t, err)
}

func setupConfigWithJWT(t *testing.T, publicKey string) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "198.51.100.52")
	}))
	t.Cleanup(server.Close)

	require.NoError(t, os.Setenv("PUBLIC_IP_API_URL", server.URL))
	require.NoError(t, os.Setenv("JWT_PUBLIC_KEY", publicKey))
	require.NoError(t, os.Setenv("WEBHOOK_URL", ""))

	_, err := config.LoadConfig()
	require.NoError(t, err)
}
