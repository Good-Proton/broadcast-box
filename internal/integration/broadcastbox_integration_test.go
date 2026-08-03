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

	publisher := startPublisher(t, app.baseURL+"/api/whip", app.token(t, testStreamKey, "whip", ""))
	t.Cleanup(publisher.close)

	viewers := []*viewer{
		startViewer(t, app.baseURL+"/api/whep", app.token(t, testStreamKey, "whep", "viewer"), "viewer-1"),
		startViewer(t, app.baseURL+"/api/whep", app.token(t, testStreamKey, "whep", "viewer"), "viewer-2"),
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
		if len(status.AudioTracks) != 1 {
			return false, fmt.Sprintf("audioTracks=%d", len(status.AudioTracks))
		}
		if status.AudioTracks[0].PacketsReceived == 0 {
			return false, "publisher audio packets=0"
		}
		if len(status.VideoTracks) != 1 {
			return false, fmt.Sprintf("videoTracks=%d", len(status.VideoTracks))
		}
		if status.VideoTracks[0].PacketsReceived < 20 || status.VideoTracks[0].FramesReceived < 5 {
			return false, fmt.Sprintf("publisher video packets=%d frames=%d", status.VideoTracks[0].PacketsReceived, status.VideoTracks[0].FramesReceived)
		}
		if status.VideoTracks[0].KeyframesReceived == 0 {
			return false, "publisher keyframesReceived=0"
		}
		if len(status.Sessions) != len(viewers) {
			return false, fmt.Sprintf("sessions=%d", len(status.Sessions))
		}
		for _, session := range status.Sessions {
			if session.ICEConnectionState != "connected" {
				return false, fmt.Sprintf("WHEP %s ICE state=%q", session.ID, session.ICEConnectionState)
			}
			if session.VideoPacketsWritten < 20 || session.VideoFramesWritten < 5 {
				return false, fmt.Sprintf("WHEP %s videoPackets=%d videoFrames=%d", session.ID, session.VideoPacketsWritten, session.VideoFramesWritten)
			}
			if session.VideoKeyframesWritten == 0 {
				return false, fmt.Sprintf("WHEP %s videoKeyframesWritten=0", session.ID)
			}
			if session.VideoPacketsDropped != 0 {
				return false, fmt.Sprintf("WHEP %s videoPacketsDropped=%d", session.ID, session.VideoPacketsDropped)
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
		if len(status.Sessions) != 0 {
			return false, fmt.Sprintf("sessions still active=%d", len(status.Sessions))
		}
		return true, ""
	})

	deleteWHIP(t, app.baseURL+"/api/whip", app.token(t, testStreamKey, "whip", ""))
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

func TestBroadcastBoxStopsStreamerWhileViewerActive(t *testing.T) {
	app := startBroadcastBox(t)

	streamKey := testStreamKey + "-streamer-stop"
	publisher := startPublisher(t, app.baseURL+"/api/whip", app.token(t, streamKey, "whip", ""))
	t.Cleanup(publisher.close)

	viewer := startViewer(t, app.baseURL+"/api/whep", app.token(t, streamKey, "whep", "viewer"), "viewer-streamer-stop")
	t.Cleanup(viewer.close)

	eventually(t, 20*time.Second, 100*time.Millisecond, func() (bool, string) {
		if viewer.videoPackets.Load() < 20 || viewer.videoFrames.Load() < 5 {
			return false, fmt.Sprintf("%s video packets=%d frames=%d", viewer.name, viewer.videoPackets.Load(), viewer.videoFrames.Load())
		}

		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}
		status := findStatus(statuses, streamKey)
		if status == nil {
			return false, "stream not present in status"
		}
		if status.WHIPICEConnectionState != "connected" {
			return false, fmt.Sprintf("WHIP ICE state=%q", status.WHIPICEConnectionState)
		}

		return true, ""
	})

	publisher.close()

	eventually(t, 20*time.Second, 200*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}

		status := findStatus(statuses, streamKey)
		if status == nil {
			return false, "stream unexpectedly removed while viewer is still connected"
		}
		if status.WHIPICEConnectionState == "connected" {
			return false, "WHIP ICE state still connected"
		}
		return true, ""
	})

	eventuallyCounterStable(t, 10*time.Second, 200*time.Millisecond, 5, func() uint64 {
		return viewer.videoPackets.Load()
	})

	viewer.close()

	eventually(t, 20*time.Second, 200*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}
		if status := findStatus(statuses, streamKey); status != nil {
			return false, "stream still present after streamer and viewer are closed"
		}
		return true, ""
	})
}

func TestBroadcastBoxStopsAllViewersWhileStreamerActive(t *testing.T) {
	app := startBroadcastBox(t)

	streamKey := testStreamKey + "-viewers-stop"
	publisher := startPublisher(t, app.baseURL+"/api/whip", app.token(t, streamKey, "whip", ""))
	t.Cleanup(publisher.close)

	viewers := []*viewer{
		startViewer(t, app.baseURL+"/api/whep", app.token(t, streamKey, "whep", "viewer"), "viewer-a"),
		startViewer(t, app.baseURL+"/api/whep", app.token(t, streamKey, "whep", "viewer"), "viewer-b"),
	}
	for _, viewer := range viewers {
		t.Cleanup(viewer.close)
	}

	eventually(t, 20*time.Second, 100*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}

		status := findStatus(statuses, streamKey)
		if status == nil {
			return false, "stream not present in status"
		}
		if len(status.Sessions) != len(viewers) {
			return false, fmt.Sprintf("sessions=%d", len(status.Sessions))
		}
		for _, viewer := range viewers {
			if viewer.videoPackets.Load() < 20 || viewer.videoFrames.Load() < 5 {
				return false, fmt.Sprintf("%s video packets=%d frames=%d", viewer.name, viewer.videoPackets.Load(), viewer.videoFrames.Load())
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

		status := findStatus(statuses, streamKey)
		if status == nil {
			return false, "stream unexpectedly removed while streamer is still active"
		}
		if status.WHIPICEConnectionState != "connected" {
			return false, fmt.Sprintf("WHIP ICE state=%q", status.WHIPICEConnectionState)
		}
		if len(status.Sessions) != 0 {
			return false, fmt.Sprintf("sessions still active=%d", len(status.Sessions))
		}
		return true, ""
	})

	deleteWHIP(t, app.baseURL+"/api/whip", app.token(t, streamKey, "whip", ""))
	publisher.close()

	eventually(t, 5*time.Second, 100*time.Millisecond, func() (bool, string) {
		statuses, err := fetchStatuses(app.baseURL)
		if err != nil {
			return false, err.Error()
		}
		if status := findStatus(statuses, streamKey); status != nil {
			return false, "stream still present after WHIP delete"
		}
		return true, ""
	})
}

func eventuallyCounterStable(t *testing.T, timeout time.Duration, interval time.Duration, consecutiveEqualReads int, read func() uint64) {
	t.Helper()

	last := read()
	equalReads := 0

	eventually(t, timeout, interval, func() (bool, string) {
		current := read()
		if current == last {
			equalReads++
		} else {
			last = current
			equalReads = 0
		}

		if equalReads >= consecutiveEqualReads {
			return true, ""
		}

		return false, fmt.Sprintf("counter still changing: current=%d stableReads=%d/%d", current, equalReads, consecutiveEqualReads)
	})
}
