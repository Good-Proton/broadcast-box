package manager

import (
	"log/slog"
	"os"
	"time"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/session"
)

const (
	defaultNoViewersCheckInterval = 1 * time.Minute
)

func (m *SessionManager) setupNoViewersCleanup() {
	if stop := m.noViewersCleanupStop; stop != nil {
		close(stop)
		m.noViewersCleanupStop = nil
	}

	m.noViewersTimeout = parseDurationEnv(environment.IdleStreamTimeout)
	if m.noViewersTimeout <= 0 {
		return
	}

	m.noViewersCheckInterval = defaultNoViewersCheckInterval
	if val := os.Getenv(environment.IdleStreamCheckInterval); val != "" {
		interval, err := time.ParseDuration(val)
		if err != nil || interval <= 0 {
			slog.Warn("SessionManager: invalid duration env var, using default",
				"key", environment.IdleStreamCheckInterval,
				"value", val,
				"default", m.noViewersCheckInterval,
				"err", err,
			)
		} else {
			m.noViewersCheckInterval = interval
		}
	}

	slog.Info(
		"SessionManager: enabled idle stream cleanup for streams without viewers",
		"timeout", m.noViewersTimeout,
		"checkInterval", m.noViewersCheckInterval,
	)

	m.noViewersCleanupStop = make(chan struct{})
	go m.noViewersCleanupLoop()
}

func parseDurationEnv(key string) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return 0
	}

	duration, err := time.ParseDuration(val)
	if err != nil || duration <= 0 {
		slog.Warn("SessionManager: invalid duration env var, feature disabled", "key", key, "value", val)
		return 0
	}

	return duration
}

func (m *SessionManager) noViewersCleanupLoop() {
	ticker := time.NewTicker(m.noViewersCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.stopStreamsWithoutViewers(time.Now())
		case <-m.noViewersCleanupStop:
			return
		}
	}
}

func (m *SessionManager) stopStreamsWithoutViewers(now time.Time) {
	if m.noViewersTimeout <= 0 {
		return
	}

	m.sessionsLock.RLock()
	sessions := make([]*session.Session, 0, len(m.sessions))
	for _, streamSession := range m.sessions {
		sessions = append(sessions, streamSession)
	}
	m.sessionsLock.RUnlock()

	for _, streamSession := range sessions {
		if !streamSession.ShouldStopForNoViewers(m.noViewersTimeout, now) {
			continue
		}

		noViewersSince, _ := streamSession.NoViewersSince()
		slog.Info(
			"SessionManager: stopping stream without viewers",
			"streamKey", streamSession.StreamKey,
			"lhUserId", streamSession.LhUserId,
			"noViewersSince", noViewersSince,
			"timeout", m.noViewersTimeout,
		)
		streamSession.Close()
	}
}
