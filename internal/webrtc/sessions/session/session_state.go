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
	StreamKey                     string    `json:"streamKey"`
	LhUserId                      string    `json:"lhUserId,omitempty"`
	IsPublic                      bool      `json:"isPublic"`
	MOTD                          string    `json:"motd"`
	StreamStart                   time.Time `json:"streamStart"`
	WHIPConnectionEstablishedTime int64     `json:"whipConnectionEstablishedTime,omitempty"`
	DataChannelCount              int       `json:"dataChannelCount"`
	DataChannelMessagesReceived   uint64    `json:"dataChannelMessagesReceived"`
	DataChannelBytesSent          uint64    `json:"dataChannelBytesSent"`
	DataChannelBytesReceived      uint64    `json:"dataChannelBytesReceived"`

	AudioTracks []AudioTrackState `json:"audioTracks"`
	VideoTracks []VideoTrackState `json:"videoTracks"`

	Sessions []whep.SessionState `json:"sessions"`
}

type AudioTrackState struct {
	Rid             string `json:"rid"`
	PacketsReceived uint64 `json:"packetsReceived"`
	PacketsDropped  uint64 `json:"packetsDropped"`
	BytesReceived   uint64 `json:"bytesReceived"`
}

type VideoTrackState struct {
	Rid               string    `json:"rid"`
	Bitrate           uint64    `json:"bitrate"`
	PacketsReceived   uint64    `json:"packetsReceived"`
	PacketsDropped    uint64    `json:"packetsDropped"`
	BytesReceived     uint64    `json:"bytesReceived"`
	FramesReceived    uint64    `json:"framesReceived"`
	KeyframesReceived uint64    `json:"keyframesReceived"`
	LastKeyframe      time.Time `json:"lastKeyframe"`
}
