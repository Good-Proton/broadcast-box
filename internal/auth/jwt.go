package auth

import (
	"github.com/glimesh/broadcast-box/internal/config"
	"github.com/glimesh/broadcast-box/internal/logger"
	"go.uber.org/zap"

	"github.com/golang-jwt/jwt/v5"
)

type JwtPayload struct {
	SessionId  string `json:"sessionId"`
	LhUserId   string `json:"lhUserId"`
	AccessType string `json:"accessType"`
	WorkerIp   string `json:"workerIp"`

	jwt.RegisteredClaims
}

func VerifyJwtToken(tokenString string) (*JwtPayload, error) {
	cfg, err := config.GetAppConfig()
	if err != nil {
		logger.Error("Cannot get config", zap.Error(err))
		return nil, err
	}

	if cfg.JwtPublicKey == "" {
		logger.Error("JWT public key is not set in the config")
		return nil, jwt.ErrInvalidKey
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(cfg.JwtPublicKey))
	if err != nil {
		logger.Error("Cannot parse JWT public key", zap.Error(err))
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &JwtPayload{}, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))

	if err != nil {
		logger.Error("Cannot parse JWT token", zap.Error(err))
		return nil, err
	}

	if !token.Valid {
		logger.Error("Invalid JWT token")
		return nil, jwt.ErrTokenUnverifiable
	}

	if claims, ok := token.Claims.(*JwtPayload); ok {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}
