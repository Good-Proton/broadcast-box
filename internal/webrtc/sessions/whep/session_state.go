package whep

type SessionState struct {
	ID                        string `json:"id"`
	ConnectionEstablishedTime int64  `json:"connectionEstablishedTime,omitempty"`
	ICEConnectionState        string `json:"iceConnectionState,omitempty"`

	AudioLayerCurrent   string `json:"audioLayerCurrent"`
	AudioTimestamp      uint32 `json:"audioTimestamp"`
	AudioPacketsWritten uint64 `json:"audioPacketsWritten"`
	AudioBytesWritten   uint64 `json:"audioBytesWritten"`
	AudioSequenceNumber uint64 `json:"audioSequenceNumber"`

	VideoLayerCurrent              string `json:"videoLayerCurrent"`
	VideoTimestamp                 uint32 `json:"videoTimestamp"`
	VideoBitrate                   uint64 `json:"videoBitrate"`
	VideoPacketsDropped            uint64 `json:"videoPacketsDropped"`
	VideoPacketsWritten            uint64 `json:"videoPacketsWritten"`
	VideoBytesWritten              uint64 `json:"videoBytesWritten"`
	VideoFramesWritten             uint64 `json:"videoFramesWritten"`
	VideoKeyframesWritten          uint64 `json:"videoKeyframesWritten"`
	VideoPacketsSkippedForKeyframe uint64 `json:"videoPacketsSkippedForKeyframe"`
	VideoLayerSwitches             uint64 `json:"videoLayerSwitches"`
	VideoSequenceNumber            uint64 `json:"videoSequenceNumber"`
	VideoRTT                       uint64 `json:"videoRtt"`
	VideoJitter                    uint64 `json:"videoJitter"`
	VideoDelay                     uint64 `json:"videoDelay"`
	VideoTotalLost                 uint64 `json:"videoTotalLost"`
	VideoLastSenderReport          uint64 `json:"videoLastSenderReport"`
}
