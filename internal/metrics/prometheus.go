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
			Help: "Total number of active WHEP sessions",
		},
		[]string{},
	)

	streamFirstSeenEpoch = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_first_seen_epoch",
			Help: "Unix timestamp when the oldest active stream was first seen",
		},
		[]string{},
	)

	streamAudioPacketsReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_audio_packets_received_total",
			Help: "Total number of audio packets received for active streams",
		},
		[]string{"rid"},
	)

	streamVideoPacketsReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_packets_received_total",
			Help: "Total number of video packets received for active streams",
		},
		[]string{"rid"},
	)

	streamVideoBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_bytes_received_total",
			Help: "Total number of video bytes received for active streams",
		},
		[]string{"rid"},
	)

	streamVideoFramesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_frames_received_total",
			Help: "Total number of video frames received for active streams",
		},
		[]string{"rid"},
	)

	streamVideoKeyframesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_keyframes_received_total",
			Help: "Total number of video keyframes received for active streams",
		},
		[]string{"rid"},
	)

	streamVideoAverageBitrate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_average_bitrate_bps",
			Help: "Sum of per-stream average video bitrates in bytes per second for active streams",
		},
		[]string{"rid"},
	)

	streamVideoLastKeyFrameSeen = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_video_last_keyframe_seen_timestamp",
			Help: "Unix timestamp of the last keyframe seen for active streams",
		},
		[]string{"rid"},
	)

	streamDataChannelCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_count",
			Help: "Number of active raw data channels for active streams",
		},
		[]string{},
	)

	streamDataChannelMessagesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_messages_received_total",
			Help: "Total raw data channel messages received",
		},
		[]string{},
	)

	streamDataChannelBytesSent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_sent_total",
			Help: "Total raw data channel bytes sent",
		},
		[]string{},
	)

	streamDataChannelBytesReceived = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_stream_data_channel_bytes_received_total",
			Help: "Total raw data channel bytes received",
		},
		[]string{},
	)

	whipConnectionEstablishedTime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whip_connection_established_time",
			Help: "Latest Unix timestamp when a WHIP connection was established",
		},
		[]string{},
	)

	whepSessionPacketsWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_written_total",
			Help: "Total number of video packets written to active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionBytesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_bytes_written_total",
			Help: "Total number of video bytes written to active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionFramesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_frames_written_total",
			Help: "Total number of video frames written to active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionKeyframesWritten = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_keyframes_written_total",
			Help: "Total number of video keyframes written to active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionPacketsDropped = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_dropped_total",
			Help: "Total number of video packets dropped for active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionPacketsSkippedForKeyframe = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_packets_skipped_for_keyframe_total",
			Help: "Total number of video packets skipped while active WHEP sessions wait for keyframes",
		},
		[]string{"current_layer"},
	)

	whepSessionLayerSwitches = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_layer_switches_total",
			Help: "Total number of simulcast layer switches across active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionConnectionEstablishedTime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_connection_established_time",
			Help: "Latest Unix timestamp when a WHEP session connection was established",
		},
		[]string{"current_layer"},
	)

	whepSessionRTT = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_rtt_milliseconds",
			Help: "Average round-trip time in milliseconds from RTCP receiver reports for active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionJitter = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_jitter",
			Help: "Average jitter value from RTCP receiver reports for active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionDelay = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_delay",
			Help: "Average delay from RTCP receiver reports for active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionTotalLost = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_total_lost",
			Help: "Total packets lost from RTCP receiver reports for active WHEP sessions",
		},
		[]string{"current_layer"},
	)

	whepSessionLastSenderReport = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "broadcast_box_whep_session_last_sender_report",
			Help: "Latest sender report timestamp from RTCP receiver reports for active WHEP sessions",
		},
		[]string{"current_layer"},
	)
)

type whepLayerTotals struct {
	sessions                  int
	videoPacketsWritten       uint64
	videoBytesWritten         uint64
	videoFramesWritten        uint64
	videoKeyframesWritten     uint64
	videoPacketsDropped       uint64
	videoPacketsSkipped       uint64
	videoLayerSwitches        uint64
	connectionEstablishedTime int64
	videoRTTTotal             uint64
	videoJitterTotal          uint64
	videoDelayTotal           uint64
	videoTotalLost            uint64
	videoLastSenderReport     uint64
}

func UpdateMetrics() {
	if manager.SessionsManager == nil {
		resetMetrics()
		activeStreamsCount.Set(0)
		return
	}

	statuses := manager.SessionsManager.GetSessionStates(true)
	resetMetrics()
	activeStreamsCount.Set(float64(len(statuses)))

	var activeWhepSessionsTotal int
	var streamFirstSeen int64
	var dataChannelCount int
	var dataChannelMessagesReceived uint64
	var dataChannelBytesSent uint64
	var dataChannelBytesReceived uint64
	var whipConnectionEstablished int64

	videoLastKeyframeByRID := map[string]int64{}
	whepTotalsByLayer := map[string]*whepLayerTotals{}

	for _, status := range statuses {
		if !status.StreamStart.IsZero() {
			streamStart := status.StreamStart.Unix()
			if streamFirstSeen == 0 || streamStart < streamFirstSeen {
				streamFirstSeen = streamStart
			}
		}

		dataChannelCount += status.DataChannelCount
		dataChannelMessagesReceived += status.DataChannelMessagesReceived
		dataChannelBytesSent += status.DataChannelBytesSent
		dataChannelBytesReceived += status.DataChannelBytesReceived
		if status.WHIPConnectionEstablishedTime > whipConnectionEstablished {
			whipConnectionEstablished = status.WHIPConnectionEstablishedTime
		}

		for _, audio := range status.AudioTracks {
			streamAudioPacketsReceived.WithLabelValues(audio.Rid).Add(float64(audio.PacketsReceived))
		}

		for _, video := range status.VideoTracks {
			streamVideoPacketsReceived.WithLabelValues(video.Rid).Add(float64(video.PacketsReceived))
			streamVideoBytesReceived.WithLabelValues(video.Rid).Add(float64(video.BytesReceived))
			streamVideoFramesReceived.WithLabelValues(video.Rid).Add(float64(video.FramesReceived))
			streamVideoKeyframesReceived.WithLabelValues(video.Rid).Add(float64(video.KeyframesReceived))
			streamVideoAverageBitrate.WithLabelValues(video.Rid).Add(float64(video.Bitrate))
			if !video.LastKeyframe.IsZero() {
				lastKeyframe := video.LastKeyframe.Unix()
				if lastKeyframe > videoLastKeyframeByRID[video.Rid] {
					videoLastKeyframeByRID[video.Rid] = lastKeyframe
				}
			}
		}

		activeWhepSessionsTotal += len(status.Sessions)

		for _, session := range status.Sessions {
			currentLayer := session.VideoLayerCurrent
			totals := whepTotalsByLayer[currentLayer]
			if totals == nil {
				totals = &whepLayerTotals{}
				whepTotalsByLayer[currentLayer] = totals
			}

			totals.sessions++
			totals.videoPacketsWritten += session.VideoPacketsWritten
			totals.videoBytesWritten += session.VideoBytesWritten
			totals.videoFramesWritten += session.VideoFramesWritten
			totals.videoKeyframesWritten += session.VideoKeyframesWritten
			totals.videoPacketsDropped += session.VideoPacketsDropped
			totals.videoPacketsSkipped += session.VideoPacketsSkippedForKeyframe
			totals.videoLayerSwitches += session.VideoLayerSwitches
			totals.videoRTTTotal += session.VideoRTT
			totals.videoJitterTotal += session.VideoJitter
			totals.videoDelayTotal += session.VideoDelay
			totals.videoTotalLost += session.VideoTotalLost
			if session.ConnectionEstablishedTime > totals.connectionEstablishedTime {
				totals.connectionEstablishedTime = session.ConnectionEstablishedTime
			}
			if session.VideoLastSenderReport > totals.videoLastSenderReport {
				totals.videoLastSenderReport = session.VideoLastSenderReport
			}
		}
	}

	activeWhepSessionsCount.WithLabelValues().Set(float64(activeWhepSessionsTotal))
	streamFirstSeenEpoch.WithLabelValues().Set(float64(streamFirstSeen))
	streamDataChannelCount.WithLabelValues().Set(float64(dataChannelCount))
	streamDataChannelMessagesReceived.WithLabelValues().Set(float64(dataChannelMessagesReceived))
	streamDataChannelBytesSent.WithLabelValues().Set(float64(dataChannelBytesSent))
	streamDataChannelBytesReceived.WithLabelValues().Set(float64(dataChannelBytesReceived))
	whipConnectionEstablishedTime.WithLabelValues().Set(float64(whipConnectionEstablished))

	for rid, lastKeyframe := range videoLastKeyframeByRID {
		streamVideoLastKeyFrameSeen.WithLabelValues(rid).Set(float64(lastKeyframe))
	}

	for currentLayer, totals := range whepTotalsByLayer {
		whepSessionPacketsWritten.WithLabelValues(currentLayer).Set(float64(totals.videoPacketsWritten))
		whepSessionBytesWritten.WithLabelValues(currentLayer).Set(float64(totals.videoBytesWritten))
		whepSessionFramesWritten.WithLabelValues(currentLayer).Set(float64(totals.videoFramesWritten))
		whepSessionKeyframesWritten.WithLabelValues(currentLayer).Set(float64(totals.videoKeyframesWritten))
		whepSessionPacketsDropped.WithLabelValues(currentLayer).Set(float64(totals.videoPacketsDropped))
		whepSessionPacketsSkippedForKeyframe.WithLabelValues(currentLayer).Set(float64(totals.videoPacketsSkipped))
		whepSessionLayerSwitches.WithLabelValues(currentLayer).Set(float64(totals.videoLayerSwitches))
		whepSessionConnectionEstablishedTime.WithLabelValues(currentLayer).Set(float64(totals.connectionEstablishedTime))
		whepSessionTotalLost.WithLabelValues(currentLayer).Set(float64(totals.videoTotalLost))
		whepSessionLastSenderReport.WithLabelValues(currentLayer).Set(float64(totals.videoLastSenderReport))

		if totals.sessions > 0 {
			whepSessionRTT.WithLabelValues(currentLayer).Set(float64(totals.videoRTTTotal) / float64(totals.sessions))
			whepSessionJitter.WithLabelValues(currentLayer).Set(float64(totals.videoJitterTotal) / float64(totals.sessions))
			whepSessionDelay.WithLabelValues(currentLayer).Set(float64(totals.videoDelayTotal) / float64(totals.sessions))
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
