package session

import (
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whep"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whip"
)

func TestShouldStopForNoViewers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	host := &whip.WHIPSession{}

	t.Run("disabled timeout", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.Host.Store(host)
		streamSession.noViewers.mark(now.Add(-2 * time.Hour))

		if streamSession.ShouldStopForNoViewers(0, now) {
			t.Fatal("expected stream to remain active when timeout is disabled")
		}
	})

	t.Run("no host", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.noViewers.mark(now.Add(-2 * time.Hour))

		if streamSession.ShouldStopForNoViewers(time.Hour, now) {
			t.Fatal("expected stream without host to remain active")
		}
	})

	t.Run("has viewers", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{
			WHEPSessions: map[string]*whep.WHEPSession{
				"viewer-1": {SessionID: "viewer-1"},
			},
		}
		streamSession.Host.Store(host)
		streamSession.noViewers.mark(now.Add(-2 * time.Hour))

		if streamSession.ShouldStopForNoViewers(time.Hour, now) {
			t.Fatal("expected stream with viewers to remain active")
		}
	})

	t.Run("idle long enough", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.Host.Store(host)
		streamSession.noViewers.mark(now.Add(-2 * time.Hour))

		if !streamSession.ShouldStopForNoViewers(time.Hour, now) {
			t.Fatal("expected idle stream to be stopped")
		}
	})

	t.Run("idle but not long enough", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.Host.Store(host)
		streamSession.noViewers.mark(now.Add(-30 * time.Minute))

		if streamSession.ShouldStopForNoViewers(time.Hour, now) {
			t.Fatal("expected stream to remain active before timeout expires")
		}
	})
}

func TestUpdateNoViewersTracking(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	host := &whip.WHIPSession{}

	t.Run("marks when host has no viewers", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.Host.Store(host)

		streamSession.updateNoViewersTracking(now)

		since, ok := streamSession.NoViewersSince()
		if !ok || !since.Equal(now) {
			t.Fatalf("expected noViewersSince=%s, got %v ok=%v", now, since, ok)
		}
	})

	t.Run("clears when viewer connects", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{
			WHEPSessions: map[string]*whep.WHEPSession{
				"viewer-1": {SessionID: "viewer-1"},
			},
		}
		streamSession.Host.Store(host)
		streamSession.noViewers.mark(now)

		streamSession.updateNoViewersTracking(now.Add(time.Minute))

		if _, ok := streamSession.NoViewersSince(); ok {
			t.Fatal("expected noViewersSince to be cleared when viewer is present")
		}
	})

	t.Run("preserves first idle timestamp", func(t *testing.T) {
		t.Parallel()

		streamSession := &Session{}
		streamSession.Host.Store(host)
		streamSession.updateNoViewersTracking(now)
		streamSession.updateNoViewersTracking(now.Add(10 * time.Minute))

		since, ok := streamSession.NoViewersSince()
		if !ok || !since.Equal(now) {
			t.Fatalf("expected original noViewersSince=%s, got %v ok=%v", now, since, ok)
		}
	})
}
