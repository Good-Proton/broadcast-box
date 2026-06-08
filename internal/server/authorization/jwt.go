package authorization

import (
	"errors"
	"log/slog"
	"os"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/golang-jwt/jwt/v5"
)

type JwtPayload struct {
	SessionId  string `json:"sessionId"`
	LhUserId   string `json:"lhUserId"`
	AccessType string `json:"accessType"`
	WorkerIp   string `json:"workerIp"`

	jwt.RegisteredClaims
}

func IsJwtEnabled() bool {
	return getJwtPublicKey() != ""
}

func VerifyJwtToken(tokenString string) (*JwtPayload, error) {
	publicKeyPem := getJwtPublicKey()
	if publicKeyPem == "" {
		return nil, jwt.ErrInvalidKey
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPem))
	if err != nil {
		slog.Error("JWT public key parse failed", "err", err)
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &JwtPayload{}, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))
	if err != nil {
		slog.Error("JWT parse failed", "err", err)
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenUnverifiable
	}

	claims, ok := token.Claims.(*JwtPayload)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	if claims.SessionId == "" {
		return nil, errors.New("jwt sessionId is empty")
	}

	return claims, nil
}

func getJwtPublicKey() string {
	return environment.SanitizeValue(os.Getenv(environment.JWTPublicKey))
}
