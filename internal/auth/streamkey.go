package auth

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/glimesh/broadcast-box/internal/config"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/glimesh/broadcast-box/internal/webhook"
	"go.uber.org/zap"
)

var (
	errAuthorizationNotSet = errors.New("authorization was not set")
	errInvalidStreamKey    = errors.New("invalid stream key format")

	streamKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.~]+$`)
)

type StreamInfo struct {
	StreamKey string
	LhUserId  string
}

func GetStreamInfo(action string, r *http.Request) (*StreamInfo, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		logger.Error("Stream key format error. Empty", zap.String("header", authorizationHeader))
		return nil, errAuthorizationNotSet
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authorizationHeader, bearerPrefix) {
		logger.Error("Stream key format error. No prefix")
		return nil, errInvalidStreamKey
	}

	streamKey := strings.TrimPrefix(authorizationHeader, bearerPrefix)
	lhUserId := ""

	if webhookUrl := os.Getenv("WEBHOOK_URL"); webhookUrl != "" {
		var err error
		streamKey, err = webhook.CallWebhook(webhookUrl, action, streamKey, r)
		if err != nil {
			logger.Error("Webhook call failed", zap.Error(err))
			return nil, err
		}
	}

	if config.IsJwtEnabled() {
		jwtPayload, err := VerifyJwtToken(streamKey)
		if err != nil {
			logger.Error("JWT verification failed", zap.Error(err))
			return nil, err
		}

		if action == "whip-connect" && jwtPayload.AccessType != "whip" {
			logger.Error("JWT access type invalid for WHIP", zap.String("accessType", jwtPayload.AccessType))
			return nil, errInvalidStreamKey
		}

		if action == "whep-connect" && jwtPayload.AccessType != "whep" {
			logger.Error("JWT access type invalid for WHEP", zap.String("accessType", jwtPayload.AccessType))
			return nil, errInvalidStreamKey
		}

		streamKey = jwtPayload.SessionId
		lhUserId = jwtPayload.LhUserId
	}

	if !streamKeyRegex.MatchString(streamKey) {
		logger.Error("Stream key format error. Invalid characters", zap.String("header", authorizationHeader), zap.String("streamKey", streamKey))
		return nil, errInvalidStreamKey
	}

	return &StreamInfo{
		StreamKey: streamKey,
		LhUserId:  lhUserId,
	}, nil
}
