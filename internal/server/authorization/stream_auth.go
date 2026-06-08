package authorization

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/glimesh/broadcast-box/internal/server/helpers"
	"github.com/glimesh/broadcast-box/internal/server/webhook"
)

var (
	ErrAuthorizationNotSet = errors.New("authorization was not set")
	ErrInvalidStreamKey    = errors.New("invalid stream key format")

	streamKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.~]+$`)
)

type StreamAuthInfo struct {
	StreamKey  string
	LhUserId   string
	AccessType string
	IsJwt      bool
}

func AuthenticateStreamRequest(request *http.Request, action webhook.Action) (*StreamAuthInfo, error) {
	token := helpers.ResolveBearerToken(request.Header.Get("Authorization"))
	if token == "" {
		slog.Info("Authorization was invalid")
		return nil, ErrAuthorizationNotSet
	}

	authInfo := &StreamAuthInfo{
		StreamKey: token,
	}

	if IsJwtEnabled() {
		payload, err := VerifyJwtToken(token)
		if err != nil {
			return nil, err
		}

		expectedAccessType := accessTypeForAction(action)
		if expectedAccessType != "" && !strings.EqualFold(payload.AccessType, expectedAccessType) {
			slog.Info("JWT access type invalid", "actual", payload.AccessType, "expected", expectedAccessType)
			return nil, ErrInvalidStreamKey
		}

		authInfo.StreamKey = payload.SessionId
		authInfo.LhUserId = payload.LhUserId
		authInfo.AccessType = payload.AccessType
		authInfo.IsJwt = true
	}

	if !streamKeyRegex.MatchString(authInfo.StreamKey) {
		slog.Info("Stream key format error", "streamKey", authInfo.StreamKey)
		return nil, ErrInvalidStreamKey
	}

	return authInfo, nil
}

func accessTypeForAction(action webhook.Action) string {
	switch action {
	case webhook.WHIPConnect:
		return "whip"
	case webhook.WHEPConnect:
		return "whep"
	default:
		return ""
	}
}
