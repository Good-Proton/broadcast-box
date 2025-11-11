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
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoLastKeyFrameSeen = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_last_keyframe_seen_timestamp",
			Help: "Unix timestamp of the last keyframe seen for the video stream",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_bytes_received_total",
			Help: "Total number of bytes received for the video stream",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoFramesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_frames_received_total",
			Help: "Total number of frames received for the video stream",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoKeyframesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_keyframes_received_total",
			Help: "Total number of keyframes received for the video stream",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoPacketsLost = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_packets_lost_total",
			Help: "Total number of video packets lost due to sequence number gaps",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoJitter = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_jitter",
			Help: "Jitter value from RTCP reports",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoRTT = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_rtt_milliseconds",
			Help: "Round-trip time in milliseconds from RTCP reports",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoPacketLossRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_packet_loss_rate_percent",
			Help: "Packet loss rate as percentage",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoAverageBitrate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_average_bitrate_bps",
			Help: "Average video bitrate in bits per second",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoFrameRate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_frame_rate_fps",
			Help: "Frame rate in frames per second",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoDelay = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_delay",
			Help: "Delay from RTCP Receiver Report",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoTotalLost = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_total_lost",
			Help: "Total packets lost from RTCP Receiver Report",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamVideoLastSenderReport = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_last_sender_report",
			Help: "Last sender report timestamp from RTCP",
		},
		[]string{"stream_key", "lh_user_id", "rid", "codec"},
	)

	streamDataChannelCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_count",
			Help: "Number of active data channels for the stream",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelMessagesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_messages_received_total",
			Help: "Total number of data channel messages received",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelBytesSent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_sent_total",
			Help: "Total number of bytes sent via data channels",
		},
		[]string{"stream_key", "lh_user_id"},
	)

	streamDataChannelBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_received_total",
			Help: "Total number of bytes received via data channels",
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

	whepSessionBytesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_bytes_written_total",
			Help: "Total number of bytes written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionFramesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_frames_written_total",
			Help: "Total number of frames written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionKeyframesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_keyframes_written_total",
			Help: "Total number of keyframes written to the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionPacketsDropped = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_dropped_total",
			Help: "Total number of packets dropped for the WHEP session",
		},
		[]string{"stream_key", "lh_user_id", "session_id", "current_layer"},
	)

	whepSessionPacketsSkippedForKeyframe = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_skipped_for_keyframe_total",
			Help: "Total number of packets skipped while waiting for keyframe",
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

	whepSessionStartEpoch = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_start_epoch",
			Help: "Unix timestamp when the WHEP session started",
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
	streamVideoBytesReceived.Reset()
	streamVideoFramesReceived.Reset()
	streamVideoKeyframesReceived.Reset()
	streamVideoPacketsLost.Reset()
	streamVideoJitter.Reset()
	streamVideoRTT.Reset()
	streamVideoPacketLossRate.Reset()
	streamVideoAverageBitrate.Reset()
	streamVideoFrameRate.Reset()
	streamVideoDelay.Reset()
	streamVideoTotalLost.Reset()
	streamVideoLastSenderReport.Reset()
	streamDataChannelCount.Reset()
	streamDataChannelMessagesReceived.Reset()
	streamDataChannelBytesSent.Reset()
	streamDataChannelBytesReceived.Reset()
	whipConnectionEstablishedTime.Reset()

	whepSessionPacketsWritten.Reset()
	whepSessionSequenceNumber.Reset()
	whepSessionTimestamp.Reset()
	whepSessionBytesWritten.Reset()
	whepSessionFramesWritten.Reset()
	whepSessionKeyframesWritten.Reset()
	whepSessionPacketsDropped.Reset()
	whepSessionPacketsSkippedForKeyframe.Reset()
	whepSessionLayerSwitches.Reset()
	whepSessionStartEpoch.Reset()
	whepSessionConnectionEstablishedTime.Reset()
	activeWhepSessionsCount.Reset()

	activeStreamsCount.Set(float64(len(statuses)))

	for _, status := range statuses {
		streamFirstSeenEpoch.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.FirstSeenEpoch))
		streamAudioPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.AudioPacketsReceived))
		streamDataChannelCount.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelCount))
		streamDataChannelMessagesReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelMessagesReceived))
		streamDataChannelBytesSent.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelBytesSent))
		streamDataChannelBytesReceived.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.DataChannelBytesReceived))
		whipConnectionEstablishedTime.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(status.WHIPConnectionEstablishedTime))

		for _, video := range status.VideoStreams {
			streamVideoPacketsReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.PacketsReceived))
			streamVideoBytesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.BytesReceived))
			streamVideoFramesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.FramesReceived))
			streamVideoKeyframesReceived.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.KeyframesReceived))
			streamVideoPacketsLost.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.PacketsLost))
			streamVideoJitter.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.Jitter))
			streamVideoRTT.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.RTT))
			streamVideoPacketLossRate.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(video.PacketLossRate)
			streamVideoAverageBitrate.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(video.AverageBitrate)
			streamVideoFrameRate.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(video.FrameRate)
			streamVideoDelay.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.Delay))
			streamVideoTotalLost.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.TotalLost))
			streamVideoLastSenderReport.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.LastSenderReport))

			if !video.LastKeyFrameSeen.IsZero() {
				streamVideoLastKeyFrameSeen.WithLabelValues(status.StreamKey, status.LhUserId, video.RID, video.Codec).Set(float64(video.LastKeyFrameSeen.Unix()))
			}
		}

		activeWhepSessionsCount.WithLabelValues(status.StreamKey, status.LhUserId).Set(float64(len(status.WHEPSessions)))

		for _, session := range status.WHEPSessions {
			whepSessionPacketsWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.PacketsWritten))
			whepSessionSequenceNumber.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.SequenceNumber))
			whepSessionTimestamp.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.Timestamp))
			whepSessionBytesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.BytesWritten))
			whepSessionFramesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.FramesWritten))
			whepSessionKeyframesWritten.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.KeyframesWritten))
			whepSessionPacketsDropped.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.PacketsDropped))
			whepSessionPacketsSkippedForKeyframe.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.PacketsSkippedForKeyframe))
			whepSessionLayerSwitches.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.LayerSwitches))
			whepSessionStartEpoch.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.SessionStartEpoch))
			whepSessionConnectionEstablishedTime.WithLabelValues(status.StreamKey, status.LhUserId, session.ID, session.CurrentLayer).Set(float64(session.ConnectionEstablishedTime))
		}
	}
}
