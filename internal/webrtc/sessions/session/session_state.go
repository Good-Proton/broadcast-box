package session

import (
	"time"

	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whep"
)

// Status for an individual streaming session
type whipSessionStatus struct {
	StreamKey   string    `json:"streamKey"`
	LhUserId    string    `json:"lhUserId,omitempty"`
	MOTD        string    `json:"motd"`
	ViewerCount int       `json:"viewers"`
	IsOnline    bool      `json:"isOnline"`
	StreamStart time.Time `json:"streamStart"`
}

// Information for a whip session
type StreamSessionState struct {
	StreamKey   string    `json:"streamKey"`
	IsPublic    bool      `json:"isPublic"`
	MOTD        string    `json:"motd"`
	StreamStart time.Time `json:"streamStart"`

	AudioTracks []AudioTrackState `json:"audioTracks"`
	VideoTracks []VideoTrackState `json:"videoTracks"`

	Sessions []whep.SessionState `json:"sessions"`
}

type AudioTrackState struct {
	Rid             string `json:"rid"`
	PacketsReceived uint64 `json:"packetsReceived"`
	PacketsDropped  uint64 `json:"packetsDropped"`
}

type VideoTrackState struct {
	Rid             string    `json:"rid"`
	Bitrate         uint64    `json:"bitrate"`
	PacketsReceived uint64    `json:"packetsReceived"`
	PacketsDropped  uint64    `json:"packetsDropped"`
	LastKeyframe    time.Time `json:"lastKeyframe"`
}
