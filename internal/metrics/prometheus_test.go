package metrics

import (
	"strings"
	"testing"

	"github.com/glimesh/broadcast-box/internal/server/authorization"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whep"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestUpdateMetricsDropsHighCardinalityIdentityLabels(t *testing.T) {
	sessionManager := &manager.SessionManager{}
	sessionManager.Setup()
	manager.SessionsManager = sessionManager
	t.Cleanup(func() {
		manager.SessionsManager = nil
		UpdateMetrics()
	})

	streamA, err := sessionManager.GetOrAddSession(authorization.PublicProfile{
		StreamKey: "stream-a",
		LhUserId:  "user-a",
		IsPublic:  true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	streamB, err := sessionManager.GetOrAddSession(authorization.PublicProfile{
		StreamKey: "stream-b",
		LhUserId:  "user-b",
		IsPublic:  true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	streamA.WHEPSessions["session-a"] = testWHEPSession("session-a", "high", 10, 100)
	streamB.WHEPSessions["session-b"] = testWHEPSession("session-b", "high", 20, 200)

	UpdateMetrics()
	families := gatherMetrics(t)

	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "broadcast_box_") {
			continue
		}

		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "stream_key", "lh_user_id", "session_id":
					t.Fatalf("metric %s still exposes high-cardinality label %q", family.GetName(), label.GetName())
				}
			}
		}
	}

	assertGaugeValue(t, families, "broadcast_box_active_whep_sessions_total", nil, 2)
	assertGaugeValue(t, families, "broadcast_box_whep_session_packets_written_total", map[string]string{
		"current_layer": "high",
	}, 30)
	assertGaugeValue(t, families, "broadcast_box_whep_session_rtt_milliseconds", map[string]string{
		"current_layer": "high",
	}, 150)
}

func testWHEPSession(id string, currentLayer string, packetsWritten uint64, rtt uint64) *whep.WHEPSession {
	session := &whep.WHEPSession{
		SessionID:           id,
		VideoPacketsWritten: packetsWritten,
	}
	session.AudioLayerCurrent.Store("")
	session.VideoLayerCurrent.Store(currentLayer)
	session.IsSessionClosed.Store(false)
	session.VideoRTT.Store(rtt)
	return session
}

func gatherMetrics(t *testing.T) []*dto.MetricFamily {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	return families
}

func assertGaugeValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string, expected float64) {
	t.Helper()

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		for _, metric := range family.GetMetric() {
			if labelsMatch(metric, labels) {
				if metric.GetGauge().GetValue() != expected {
					t.Fatalf("metric %s = %v, want %v", name, metric.GetGauge().GetValue(), expected)
				}
				return
			}
		}
	}

	t.Fatalf("metric %s with labels %v was not found", name, labels)
}

func labelsMatch(metric *dto.Metric, labels map[string]string) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}

	for _, label := range metric.GetLabel() {
		if labels[label.GetName()] != label.GetValue() {
			return false
		}
	}

	return true
}
