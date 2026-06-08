package metrics

import (
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	activeStreamsCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "broadcast_box_active_streams_total",
		Help: "Total number of active streams",
	})

	activeWhepSessionsCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_active_whep_sessions_total",
			Help: "Total number of active WHEP sessions per stream",
		},
		[]string{"stream_key", "lh_user_id"},
	)

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
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoPacketsReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_packets_received_total",
			Help: "Total number of video packets received for the stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_bytes_received_total",
			Help: "Total number of video bytes received for the stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoFramesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_frames_received_total",
			Help: "Total number of video frames received for the stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoKeyframesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_keyframes_received_total",
			Help: "Total number of video keyframes received for the stream",
		},
		[]string{"stream_key", "lh_user_id", "rid"},
	)

	streamVideoAverageBitrate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_average_bitrate_bps",
			Help: "Average video bitrate in bytes per second",
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

	streamDataChannelCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_count",
			Help: "Number of active raw data channels for the stream",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelMessagesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_messages_received_total",
			Help: "Total raw data channel messages received",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelBytesSent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_sent_total",
			Help: "Total raw data channel bytes sent",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_received_total",
			Help: "Total raw data channel bytes received",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	whipConnectionEstablishedTime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whip_connection_established_time",
			Help: "Unix timestamp when WHIP connection was established",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	whepSessionPacketsWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_written_total",
			Help: "Total number of video packets written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionBytesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_bytes_written_total",
			Help: "Total number of video bytes written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionFramesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_frames_written_total",
			Help: "Total number of video frames written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionKeyframesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_keyframes_written_total",
			Help: "Total number of video keyframes written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionPacketsDropped = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_dropped_total",
			Help: "Total number of video packets dropped for the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionPacketsSkippedForKeyframe = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_skipped_for_keyframe_total",
			Help: "Total number of video packets skipped while waiting for keyframe",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionLayerSwitches = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_layer_switches_total",
			Help: "Total number of simulcast layer switches",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionConnectionEstablishedTime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_connection_established_time",
			Help: "Unix timestamp when WHEP session connection was established",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionRTT = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_rtt_milliseconds",
			Help: "Round-trip time in milliseconds from RTCP receiver reports",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionJitter = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_jitter",
			Help: "Jitter value from RTCP receiver reports",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionDelay = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_delay",
			Help: "Delay from RTCP receiver reports",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionTotalLost = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_total_lost",
			Help: "Total packets lost from RTCP receiver reports",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionLastSenderReport = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_last_sender_report",
			Help: "Last sender report timestamp from RTCP receiver reports",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)
)

func UpdateMetrics() {
	if manager.SessionsManager == nil {
		resetMetrics()
		activeStreamsCount.Set(0)
		return
	}

	statuses := manager.SessionsManager.GetSessionStates(true)
	resetMetrics()
	activeStreamsCount.Set(float64(len(statuses)))

	for _, status := range statuses {
		streamFirstSeenEpoch.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.StreamStart.Unix()))
		streamDataChannelCount.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelCount))
		streamDataChannelMessagesReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelMessagesReceived))
		streamDataChannelBytesSent.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelBytesSent))
		streamDataChannelBytesReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelBytesReceived))
		whipConnectionEstablishedTime.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.WHIPConnectionEstablishedTime))

		for _, audio := range status.AudioTracks {
			streamAudioPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId, audio.Rid).Set(float64(audio.PacketsReceived))
		}

		for _, video := range status.VideoTracks {
			streamVideoPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.PacketsReceived))
			streamVideoBytesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.BytesReceived))
			streamVideoFramesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.FramesReceived))
			streamVideoKeyframesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.KeyframesReceived))
			streamVideoAverageBitrate.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.Bitrate))
			if !video.LastKeyframe.IsZero() {
				streamVideoLastKeyFrameSeen.WithLabelValues(status.StreamKey, status.LhUserId, video.Rid).Set(float64(video.LastKeyframe.Unix()))
			}
		}

		activeWhepSessionsCount.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(len(status.Sessions)))

		for _, session := range status.Sessions {
			currentLayer := session.VideoLayerCurrent
			whepSessionPacketsWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoPacketsWritten))
			whepSessionBytesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoBytesWritten))
			whepSessionFramesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoFramesWritten))
			whepSessionKeyframesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoKeyframesWritten))
			whepSessionPacketsDropped.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoPacketsDropped))
			whepSessionPacketsSkippedForKeyframe.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoPacketsSkippedForKeyframe))
			whepSessionLayerSwitches.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoLayerSwitches))
			whepSessionConnectionEstablishedTime.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.ConnectionEstablishedTime))
			whepSessionRTT.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoRTT))
			whepSessionJitter.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoJitter))
			whepSessionDelay.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoDelay))
			whepSessionTotalLost.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoTotalLost))
			whepSessionLastSenderReport.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, currentLayer).Set(float64(session.VideoLastSenderReport))
		}
	}
}

func resetMetrics() {
	activeWhepSessionsCount.Reset()
	streamFirstSeenEpoch.Reset()
	streamAudioPacketsReceived.Reset()
	streamVideoPacketsReceived.Reset()
	streamVideoBytesReceived.Reset()
	streamVideoFramesReceived.Reset()
	streamVideoKeyframesReceived.Reset()
	streamVideoAverageBitrate.Reset()
	streamVideoLastKeyFrameSeen.Reset()
	streamDataChannelCount.Reset()
	streamDataChannelMessagesReceived.Reset()
	streamDataChannelBytesSent.Reset()
	streamDataChannelBytesReceived.Reset()
	whipConnectionEstablishedTime.Reset()
	whepSessionPacketsWritten.Reset()
	whepSessionBytesWritten.Reset()
	whepSessionFramesWritten.Reset()
	whepSessionKeyframesWritten.Reset()
	whepSessionPacketsDropped.Reset()
	whepSessionPacketsSkippedForKeyframe.Reset()
	whepSessionLayerSwitches.Reset()
	whepSessionConnectionEstablishedTime.Reset()
	whepSessionRTT.Reset()
	whepSessionJitter.Reset()
	whepSessionDelay.Reset()
	whepSessionTotalLost.Reset()
	whepSessionLastSenderReport.Reset()
}
