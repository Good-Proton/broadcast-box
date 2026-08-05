package manager

import (
	"sync"
	"time"

	"github.com/glimesh/broadcast-box/internal/chat"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/session"
	"github.com/pion/webrtc/v4"
)

var (
	SessionsManager *SessionManager

	APIWHIP *webrtc.API
	APIWHEP *webrtc.API
)

type SessionManager struct {
	sessionsLock sync.RWMutex
	sessions     map[string]*session.Session
	ChatManager  *chat.Manager

	noViewersTimeout       time.Duration
	noViewersCheckInterval time.Duration
	noViewersCleanupStop   chan struct{}
}
