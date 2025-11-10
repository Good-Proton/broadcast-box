package metrics

import (
	"github.com/glimesh/broadcast-box/internal/webrtc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	streamFirstSeenEpoch = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_first_seen_epoch",
			Help: "Unix timestamp when the stream was first seen",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamAudioPacketsReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_audio_packets_received_total",
			Help: "Total number of audio packets received for the stream",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamVideoPacketsReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_packets_received_total",
			Help: "Total number of video packets received for the stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoLastKeyFrameSeen = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_last_keyframe_seen_timestamp",
			Help: "Unix timestamp of the last keyframe seen for the video stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	whepSessionPacketsWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_written_total",
			Help: "Total number of packets written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionSequenceNumber = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_sequence_number",
			Help: "Current RTP sequence number for the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_timestamp",
			Help: "Current RTP timestamp for the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	activeStreamsCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "broadcast_box_active_streams_total",
			Help: "Total number of active streams",
		},
	)

	activeWhepSessionsCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_active_whep_sessions_total",
			Help: "Total number of active WHEP sessions per stream",
		},
		[]string{"stream_key", "lh_user_id"},
	)
)

func UpdateMetrics() {
	statuses := webrtc.GetStreamStatuses()

	streamFirstSeenEpoch.Reset()
	streamAudioPacketsReceived.Reset()
	streamVideoPacketsReceived.Reset()
	streamVideoLastKeyFrameSeen.Reset()

	whepSessionPacketsWritten.Reset()
	whepSessionSequenceNumber.Reset()
	whepSessionTimestamp.Reset()
	activeWhepSessionsCount.Reset()

	activeStreamsCount.Set(float64(len(statuses)))

	for _, status := range statuses {
		streamFirstSeenEpoch.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.FirstSeenEpoch))
		streamAudioPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.AudioPacketsReceived))

		for _, video := range status.VideoStreams {
			streamVideoPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.RID).Set(float64(video.PacketsReceived))

			if !video.LastKeyFrameSeen.IsZero() {
				streamVideoLastKeyFrameSeen.WithLabelValues(status.StreamKey, status.LhUserId, video.RID).Set(float64(video.LastKeyFrameSeen.Unix()))
			}
		}

		activeWhepSessionsCount.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(len(status.WHEPSessions)))

		for _, session := range status.WHEPSessions {
			whepSessionPacketsWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.PacketsWritten))
			whepSessionSequenceNumber.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.SequenceNumber))
			whepSessionTimestamp.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.Timestamp))
		}
	}
}
