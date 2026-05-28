//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

type streamStatus struct {
	StreamKey              string              `json:"streamKey"`
	AudioPacketsReceived   uint64              `json:"audioPacketsReceived"`
	VideoStreams           []videoStreamStatus `json:"videoStreams"`
	WHEPSessions           []whepSessionStatus `json:"whepSessions"`
	WHIPICEConnectionState string              `json:"whipICEConnectionState"`
}

type videoStreamStatus struct {
	PacketsReceived   uint64 `json:"packetsReceived"`
	FramesReceived    uint64 `json:"framesReceived"`
	KeyframesReceived uint64 `json:"keyframesReceived"`
}

type whepSessionStatus struct {
	ID                  string `json:"id"`
	PacketsWritten      uint64 `json:"packetsWritten"`
	FramesWritten       uint64 `json:"framesWritten"`
	KeyframesWritten    uint64 `json:"keyframesWritten"`
	PacketsQueueDropped uint64 `json:"packetsQueueDropped"`
	ICEConnectionState  string `json:"iceConnectionState"`
}

func fetchStatuses(baseURL string) ([]streamStatus, error) {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(baseURL + "/api/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/status returned %d: %s", resp.StatusCode, string(body))
	}

	var statuses []streamStatus
	if err := json.Unmarshal(body, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

func findStatus(statuses []streamStatus, streamKey string) *streamStatus {
	for i := range statuses {
		if statuses[i].StreamKey == streamKey {
			return &statuses[i]
		}
	}
	return nil
}

func eventually(t *testing.T, timeout time.Duration, interval time.Duration, check func() (bool, string)) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	lastMessage := ""
	for time.Now().Before(deadline) {
		ok, message := check()
		if ok {
			return
		}
		lastMessage = message
		time.Sleep(interval)
	}

	t.Fatalf("condition was not met within %s: %s", timeout, lastMessage)
}
