package manager

import (
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/session"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whip"
)

func TestStopStreamsWithoutViewers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	host := &whip.WHIPSession{}

	t.Run("stops idle stream", func(t *testing.T) {
		t.Parallel()

		manager := &SessionManager{
			sessions:         make(map[string]*session.Session),
			noViewersTimeout: time.Hour,
		}

		streamSession := &session.Session{StreamKey: "idle-stream"}
		streamSession.SetOnClose(func() {
			manager.sessionsLock.Lock()
			delete(manager.sessions, "idle-stream")
			manager.sessionsLock.Unlock()
		})
		streamSession.Host.Store(host)
		streamSession.MarkNoViewersSince(now.Add(-2 * time.Hour))

		manager.sessions["idle-stream"] = streamSession
		manager.stopStreamsWithoutViewers(now)

		manager.sessionsLock.RLock()
		_, stillPresent := manager.sessions["idle-stream"]
		manager.sessionsLock.RUnlock()

		if stillPresent {
			t.Fatal("expected idle stream to be removed")
		}
	})

	t.Run("keeps stream before timeout", func(t *testing.T) {
		t.Parallel()

		manager := &SessionManager{
			sessions:         make(map[string]*session.Session),
			noViewersTimeout: time.Hour,
		}

		streamSession := &session.Session{StreamKey: "recent-idle-stream"}
		streamSession.Host.Store(host)
		streamSession.MarkNoViewersSince(now.Add(-30 * time.Minute))

		manager.sessions["recent-idle-stream"] = streamSession
		manager.stopStreamsWithoutViewers(now)

		manager.sessionsLock.RLock()
		_, stillPresent := manager.sessions["recent-idle-stream"]
		manager.sessionsLock.RUnlock()

		if !stillPresent {
			t.Fatal("expected stream to remain active before timeout expires")
		}
	})
}
