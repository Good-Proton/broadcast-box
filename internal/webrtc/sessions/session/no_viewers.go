package session

import (
	"sync/atomic"
	"time"
)

// NoViewersSinceUnixNano stores when the stream entered a no-viewers state.
// Zero means the stream currently has viewers or no active host.
type noViewersTracker struct {
	sinceUnixNano atomic.Int64
}

func (t *noViewersTracker) clear() {
	t.sinceUnixNano.Store(0)
}

func (t *noViewersTracker) mark(now time.Time) {
	t.sinceUnixNano.Store(now.UnixNano())
}

func (t *noViewersTracker) since() (time.Time, bool) {
	nano := t.sinceUnixNano.Load()
	if nano == 0 {
		return time.Time{}, false
	}

	return time.Unix(0, nano), true
}

func (s *Session) activeViewerCount() int {
	s.WHEPSessionsLock.RLock()
	defer s.WHEPSessionsLock.RUnlock()

	count := 0
	for _, whepSession := range s.WHEPSessions {
		if whepSession != nil && !whepSession.IsSessionClosed.Load() {
			count++
		}
	}

	return count
}

func (s *Session) updateNoViewersTracking(now time.Time) {
	if s.activeViewerCount() > 0 {
		s.noViewers.clear()
		return
	}

	if s.Host.Load() == nil {
		s.noViewers.clear()
		return
	}

	if _, ok := s.noViewers.since(); !ok {
		s.noViewers.mark(now)
	}
}

func (s *Session) NoViewersSince() (time.Time, bool) {
	return s.noViewers.since()
}

func (s *Session) MarkNoViewersSince(now time.Time) {
	s.noViewers.mark(now)
}

func (s *Session) ShouldStopForNoViewers(timeout time.Duration, now time.Time) bool {
	if timeout <= 0 {
		return false
	}

	if s.Host.Load() == nil {
		return false
	}

	if s.activeViewerCount() > 0 {
		return false
	}

	since, ok := s.noViewers.since()
	if !ok {
		return false
	}

	return !now.Before(since.Add(timeout))
}
