//go:build integration

package integration_test

import (
	"fmt"
	"testing"
	"time"
)

const (
	testStreamKey = "integration-test-stream"
)

func TestBroadcastBoxWHIPWHEPMediaPath(t *testing.T) {
	app := startBroadcastBox(t)

	publisher := startPublisher(t, app.baseURL+"/api/whip", testStreamKey)
	t.Cleanup(publisher.close)

	viewers := []*viewer{
		startViewer(t, app.baseURL+"/api/whep", testStreamKey, "viewer-1"),
		startViewer(t, app.baseURL+"/api/whep", testStreamKey, "viewer-2"),
	}
	for _, viewer := range viewers {
		t.Cleanup(viewer.close)
	}

	eventually(t, 20*time.Second, 100*time.Millisecond, func() (bool, string) {
		for _, viewer := range viewers {
			if viewer.videoPackets.Load() < 20 || viewer.videoFrames.Load() < 5 {
				return false, fmt.Sprintf("%s video packets=%d frames=%d", viewer.name, viewer.videoPackets.Load(), viewer.videoFrames.Load())
			}
		}
		return true, ""
	})

	eventually(t, 20*time.Second, 100*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}

		status := findStatus(statuses, testStreamKey)
		if status == nil {
			return false, fmt.Sprintf("stream %q not present in status", testStreamKey)
		}
		if status.WHIPICEConnectionState != "connected" {
			return false, fmt.Sprintf("WHIP ICE state=%q", status.WHIPICEConnectionState)
		}
		if status.AudioPacketsReceived == 0 {
			return false, "audioPacketsReceived=0"
		}
		if len(status.VideoStreams) != 1 {
			return false, fmt.Sprintf("videoStreams=%d", len(status.VideoStreams))
		}
		if status.VideoStreams[0].PacketsReceived < 20 || status.VideoStreams[0].FramesReceived < 5 {
			return false, fmt.Sprintf("publisher video packets=%d frames=%d", status.VideoStreams[0].PacketsReceived, status.VideoStreams[0].FramesReceived)
		}
		if status.VideoStreams[0].KeyframesReceived == 0 {
			return false, "publisher keyframesReceived=0"
		}
		if len(status.WHEPSessions) != len(viewers) {
			return false, fmt.Sprintf("whepSessions=%d", len(status.WHEPSessions))
		}
		for _, session := range status.WHEPSessions {
			if session.ICEConnectionState != "connected" {
				return false, fmt.Sprintf("WHEP %s ICE state=%q", session.ID, session.ICEConnectionState)
			}
			if session.PacketsWritten < 20 || session.FramesWritten < 5 {
				return false, fmt.Sprintf("WHEP %s packets=%d frames=%d", session.ID, session.PacketsWritten, session.FramesWritten)
			}
			if session.KeyframesWritten == 0 {
				return false, fmt.Sprintf("WHEP %s keyframesWritten=0", session.ID)
			}
			if session.PacketsQueueDropped != 0 {
				return false, fmt.Sprintf("WHEP %s packetsQueueDropped=%d", session.ID, session.PacketsQueueDropped)
			}
		}

		return true, ""
	})

	for _, viewer := range viewers {
		viewer.close()
	}

	eventually(t, 20*time.Second, 200*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}

		status := findStatus(statuses, testStreamKey)
		if status == nil {
			return true, ""
		}
		if len(status.WHEPSessions) != 0 {
			return false, fmt.Sprintf("whepSessions still active=%d", len(status.WHEPSessions))
		}
		return true, ""
	})

	deleteWHIP(t, app.baseURL+"/api/whip", testStreamKey)
	publisher.close()

	eventually(t, 5*time.Second, 100*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}
		if status := findStatus(statuses, testStreamKey); status != nil {
			return false, fmt.Sprintf("stream %q still present", testStreamKey)
		}
		return true, ""
	})
}
