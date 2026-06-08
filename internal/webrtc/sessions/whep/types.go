package whep

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimesh/broadcast-box/internal/chat"
	"github.com/glimesh/broadcast-box/internal/webrtc/codecs"
	"github.com/pion/webrtc/v4"
)

type (
	WHEPSession struct {
		SessionID                  string
		StreamKey                  string
		IsWaitingForKeyframe       atomic.Bool
		IsSessionClosed            atomic.Bool
		ConnectionEstablishedEpoch atomic.Int64

		SessionClose sync.Once
		onClose      func(string)
		pliSender    func()

		PeerConnectionLock sync.RWMutex
		PeerConnection     *webrtc.PeerConnection

		// Protects VideoTrack, VideoTimestamp, VideoPacketsWritten, VideoSequenceNumber,
		// and auto video layer selection state.
		VideoLock                      sync.RWMutex
		VideoTrack                     *codecs.TrackMultiCodec
		VideoTimestamp                 uint32
		VideoBitrate                   atomic.Uint64
		VideoBytesWritten              int
		videoBitrateWindowStart        time.Time
		videoBitrateWindowBytes        int
		VideoPacketsWritten            uint64
		VideoPacketsDropped            atomic.Uint64
		VideoFramesWritten             atomic.Uint64
		VideoKeyframesWritten          atomic.Uint64
		VideoPacketsSkippedForKeyframe atomic.Uint64
		VideoSequenceNumber            uint16
		VideoLayerCurrent              atomic.Value
		VideoLayerSwitches             atomic.Uint64
		videoLayerPriority             int
		videoLayerExplicit             bool
		VideoRTT                       atomic.Uint64
		VideoJitter                    atomic.Uint64
		VideoDelay                     atomic.Uint64
		VideoTotalLost                 atomic.Uint64
		VideoLastSenderReport          atomic.Uint64

		// Protects AudioTrack, AudioTimestamp, AudioPacketsWritten, AudioSequenceNumber
		AudioLock           sync.RWMutex
		AudioTrack          *codecs.TrackMultiCodec
		AudioTimestamp      uint32
		AudioPacketsWritten uint64
		AudioBytesWritten   atomic.Uint64
		AudioSequenceNumber uint16
		AudioLayerCurrent   atomic.Value

		ChatManager *chat.Manager
	}
)
