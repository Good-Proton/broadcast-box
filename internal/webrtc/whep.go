package webrtc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/google/uuid"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"
)

type (
	videoPacket struct {
		packet       rtp.Packet
		layer        string
		timeDiff     int64
		sequenceDiff int
		codec        videoTrackCodec
		isKeyframe   bool
	}

	whepSession struct {
		videoTrack                *trackMultiCodec
		rtpSender                 *webrtc.RTPSender
		peerConnection            *webrtc.PeerConnection
		currentLayer              atomic.Value
		waitingForKeyframe        atomic.Bool
		sequenceNumber            atomic.Uint32
		timestamp                 atomic.Uint32
		packetsWritten            atomic.Uint64
		bytesWritten              atomic.Uint64
		framesWritten             atomic.Uint64
		keyframesWritten          atomic.Uint64
		packetsDropped            atomic.Uint64
		packetsQueueDropped       atomic.Uint64
		packetsSkippedForKeyframe atomic.Uint64
		layerSwitches             atomic.Uint64
		sessionStartEpoch         uint64
		connectionEstablishedTime atomic.Uint64
		firstPacketTime           atomic.Value
		lastPacketTime            atomic.Value
		iceConnectionState        atomic.Value

		rtt              atomic.Uint64
		jitter           atomic.Uint64
		lastRTCPTime     atomic.Value
		delay            atomic.Uint64
		totalLost        atomic.Uint64
		lastSenderReport atomic.Uint64

		videoPackets chan videoPacket
		done         chan struct{}
		closeOnce    sync.Once
	}

	simulcastLayerResponse struct {
		EncodingId string `json:"encodingId"`
	}
)

const whepVideoPacketQueueSize = 256

func WHEPLayers(whepSessionId string) ([]byte, error) {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	layers := []simulcastLayerResponse{}
	for streamKey := range streamMap {
		streamMap[streamKey].whepSessionsLock.Lock()
		defer streamMap[streamKey].whepSessionsLock.Unlock()

		if _, ok := streamMap[streamKey].whepSessions[whepSessionId]; ok {
			for i := range streamMap[streamKey].videoTracks {
				layers = append(layers, simulcastLayerResponse{EncodingId: streamMap[streamKey].videoTracks[i].rid})
			}

			break
		}
	}

	resp := map[string]map[string][]simulcastLayerResponse{
		"1": map[string][]simulcastLayerResponse{
			"layers": layers,
		},
	}

	return json.Marshal(resp)
}

func WHEPChangeLayer(whepSessionId, layer string) error {
	var streamForKeyframe *stream

	streamMapLock.Lock()

	for streamKey := range streamMap {
		streamMap[streamKey].whepSessionsLock.Lock()

		if _, ok := streamMap[streamKey].whepSessions[whepSessionId]; ok {
			oldLayer := streamMap[streamKey].whepSessions[whepSessionId].currentLayer.Load()
			if oldLayer != nil && oldLayer.(string) != layer {
				streamMap[streamKey].whepSessions[whepSessionId].layerSwitches.Add(1)
			}
			streamMap[streamKey].whepSessions[whepSessionId].currentLayer.Store(layer)
			streamMap[streamKey].whepSessions[whepSessionId].waitingForKeyframe.Store(true)
			streamForKeyframe = streamMap[streamKey]
		}

		streamMap[streamKey].whepSessionsLock.Unlock()
	}

	streamMapLock.Unlock()

	if streamForKeyframe != nil {
		requestPublisherKeyframe(streamForKeyframe, layer, "layer change", whepSessionId)
	}

	return nil
}

func WHEP(offer string, streamInfo *auth.StreamInfo) (string, string, error) {
	logger.Info("Received WHEP offer",
		zap.String("streamKey", streamInfo.StreamKey),
		zap.String("lhUserId", streamInfo.LhUserId),
	)

	maybePrintOfferAnswer(offer, true)

	streamMapLock.Lock()
	defer streamMapLock.Unlock()
	stream, err := getStream(streamInfo, "")
	if err != nil {
		logger.Error("Failed to get stream for WHEP",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
			zap.String("lhUserId", streamInfo.LhUserId),
		)
		return "", "", err
	}

	whepSessionId := uuid.New().String()

	videoTrack := &trackMultiCodec{id: "video", streamID: "pion"}

	peerConnection, err := newPeerConnection(apiWhep)
	if err != nil {
		logger.Error("Failed to create peer connection",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
			zap.String("lhUserId", streamInfo.LhUserId),
			zap.String("whepSessionId", whepSessionId),
		)
		return "", "", err
	}

	peerConnection.OnICEConnectionStateChange(func(i webrtc.ICEConnectionState) {
		stream.whepSessionsLock.Lock()
		if session, ok := stream.whepSessions[whepSessionId]; ok {
			session.iceConnectionState.Store(i.String())
			if i == webrtc.ICEConnectionStateConnected && session.connectionEstablishedTime.Load() == 0 {
				session.connectionEstablishedTime.Store(uint64(time.Now().Unix()))
			}
		}
		stream.whepSessionsLock.Unlock()

		if i == webrtc.ICEConnectionStateFailed || i == webrtc.ICEConnectionStateClosed {
			if err := peerConnection.Close(); err != nil {
				logger.Error("Failed to close peer connection",
					zap.Error(err),
					zap.String("streamKey", streamInfo.StreamKey),
					zap.String("iceState", i.String()),
				)
			}

			logger.Info("Disconnecting peer connection",
				zap.String("side", "whep"),
				zap.String("reason", "ICE connection state changed"),
				zap.String("streamKey", streamInfo.StreamKey),
				zap.String("iceState", i.String()),
			)
			peerConnectionDisconnected(false, streamInfo.StreamKey, whepSessionId)
		}
	})

	stream.dataChannelsLock.Lock()
	stream.subscriberConnections[whepSessionId] = peerConnection

	for label := range stream.publisherDataChannels {
		if err := ensureDataChannelPair(label, stream, nil, &whepSessionId); err != nil {
			logger.Error("Failed to ensure data channel pair",
				zap.Error(err),
				zap.String("streamKey", streamInfo.StreamKey),
				zap.String("label", label),
				zap.String("whepSessionId", whepSessionId),
			)
			return "", "", err
		}
	}
	stream.dataChannelsLock.Unlock()

	peerConnection.OnDataChannel(func(channel *webrtc.DataChannel) {
		stream.dataChannelsLock.Lock()
		label := channel.Label()
		if err := ensureDataChannelPair(label, stream, channel, &whepSessionId); err != nil {
			logger.Error("Failed to ensure data channel pair",
				zap.Error(err),
				zap.String("streamKey", streamInfo.StreamKey),
				zap.String("label", label),
			)
		}
		stream.dataChannelsLock.Unlock()
	})

	if _, err = peerConnection.AddTrack(stream.audioTrack); err != nil {
		logger.Error("Failed to add audio track",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	}

	rtpSender, err := peerConnection.AddTrack(videoTrack)
	if err != nil {
		logger.Error("Failed to add video track",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	}

	session := &whepSession{
		videoTrack:        videoTrack,
		rtpSender:         rtpSender,
		peerConnection:    peerConnection,
		sessionStartEpoch: uint64(time.Now().Unix()),
		videoPackets:      make(chan videoPacket, whepVideoPacketQueueSize),
		done:              make(chan struct{}),
	}
	session.timestamp.Store(50000)

	if err := peerConnection.SetRemoteDescription(webrtc.SessionDescription{
		SDP:  offer,
		Type: webrtc.SDPTypeOffer,
	}); err != nil {
		logger.Error("Failed to set remote description",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	}

	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	answer, err := peerConnection.CreateAnswer(nil)

	if err != nil {
		logger.Error("Failed to create answer",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	} else if err = peerConnection.SetLocalDescription(answer); err != nil {
		logger.Error("Failed to set local description",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	}

	<-gatherComplete

	stream.whepSessionsLock.Lock()
	defer stream.whepSessionsLock.Unlock()

	session.currentLayer.Store("")
	session.waitingForKeyframe.Store(false)
	session.iceConnectionState.Store("new")
	session.firstPacketTime.Store(time.Time{})
	session.lastPacketTime.Store(time.Time{})
	stream.whepSessions[whepSessionId] = session
	go readWHEPRTCP(rtpSender, stream, session, whepSessionId)
	go session.writeVideoPackets(stream.whipActiveContext)

	return maybePrintOfferAnswer(appendAnswer(peerConnection.LocalDescription().SDP), false), whepSessionId, nil
}

func readWHEPRTCP(rtpSender *webrtc.RTPSender, stream *stream, session *whepSession, whepSessionId string) {
	for {
		rtcpPackets, _, err := rtpSender.ReadRTCP()
		if err != nil {
			select {
			case <-session.done:
				return
			default:
			}
			if errors.Is(err, io.ErrClosedPipe) {
				logger.Debug("Stopped reading WHEP RTCP",
					zap.String("streamKey", stream.streamKey),
					zap.String("whepSessionId", whepSessionId),
				)
				return
			}

			logger.Error("Failed to read RTCP packets",
				zap.Error(err),
				zap.String("streamKey", stream.streamKey),
				zap.String("whepSessionId", whepSessionId),
			)
			return
		}

		now := time.Now()
		sessionSSRC := uint32(session.videoTrack.ssrc)
		id := session.videoTrack.RID()
		currentLayer, _ := session.currentLayer.Load().(string)

		for _, pkt := range rtcpPackets {
			switch rtcpPkt := pkt.(type) {
			case *rtcp.PictureLossIndication:
				requestPublisherKeyframe(stream, currentLayer, "whep pli", whepSessionId)
			case *rtcp.FullIntraRequest:
				requestPublisherKeyframe(stream, currentLayer, "whep fir", whepSessionId)
			case *rtcp.TransportLayerNack:
				requestPublisherKeyframe(stream, currentLayer, "whep nack", whepSessionId)
			case *rtcp.ReceiverReport:
				logger.Debug("Received whep ReceiverReport",
					zap.Int("reportsCount", len(rtcpPkt.Reports)),
					zap.Uint32("sessionSSRC", sessionSSRC),
					zap.String("rid", id),
					zap.String("sessionId", whepSessionId),
				)
				for _, report := range rtcpPkt.Reports {
					if report.SSRC == sessionSSRC {
						currentLastReport := uint32(session.lastSenderReport.Load())

						if currentLastReport <= report.LastSenderReport {
							session.jitter.Store(uint64(report.Jitter))
							session.delay.Store(uint64(report.Delay))
							session.totalLost.Store(uint64(report.TotalLost))
							session.lastSenderReport.Store(uint64(report.LastSenderReport))
							session.lastRTCPTime.Store(now)

							break
						} else {
							logger.Debug("Outdated ReceiverReport received",
								zap.Uint32("currentLastReport", currentLastReport),
								zap.Uint32("receivedLastReport", report.LastSenderReport),
								zap.Uint32("ssrc", report.SSRC),
								zap.String("rid", id),
								zap.String("sessionId", whepSessionId),
							)
						}
					}
				}
			}
		}
	}
}

func (w *whepSession) close() {
	w.closeOnce.Do(func() {
		close(w.done)
		if w.rtpSender != nil {
			if err := w.rtpSender.Stop(); err != nil {
				logger.Debug("Failed to stop WHEP RTP sender", zap.Error(err))
			}
		}
	})
}

func (w *whepSession) enqueueVideoPacket(packet videoPacket) {
	select {
	case <-w.done:
		return
	default:
	}

	select {
	case w.videoPackets <- packet:
	case <-w.done:
	default:
		w.packetsQueueDropped.Add(1)
	}
}

func (w *whepSession) writeVideoPackets(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case packet := <-w.videoPackets:
			w.sendVideoPacket(&packet.packet, packet.layer, packet.timeDiff, packet.sequenceDiff, packet.codec, packet.isKeyframe)
		}
	}
}

func (w *whepSession) sendVideoPacket(rtpPkt *rtp.Packet, layer string, timeDiff int64, sequenceDiff int, codec videoTrackCodec, isKeyframe bool) {
	currentLayer := w.currentLayer.Load()
	if currentLayer == "" {
		w.currentLayer.Store(layer)
	} else if layer != currentLayer {
		return
	} else if w.waitingForKeyframe.Load() {
		if !isKeyframe {
			w.packetsSkippedForKeyframe.Add(1)
			return
		}

		w.waitingForKeyframe.Store(false)
	}

	if currentLayer != "" && layer != currentLayer.(string) {
		w.layerSwitches.Add(1)
	}

	now := time.Now()
	if firstPacket, ok := w.firstPacketTime.Load().(time.Time); !ok || firstPacket.IsZero() {
		w.firstPacketTime.Store(now)
	}
	w.lastPacketTime.Store(now)

	w.packetsWritten.Add(1)
	sequenceNumber := uint16(int(w.sequenceNumber.Load()) + sequenceDiff)
	timestamp := uint32(int64(w.timestamp.Load()) + timeDiff)
	w.sequenceNumber.Store(uint32(sequenceNumber))
	w.timestamp.Store(timestamp)

	rtpPkt.SequenceNumber = sequenceNumber
	rtpPkt.Timestamp = timestamp

	packetSize := uint64(rtpPkt.MarshalSize())
	w.bytesWritten.Add(packetSize)

	if rtpPkt.Marker {
		w.framesWritten.Add(1)
	}

	if isKeyframe {
		w.keyframesWritten.Add(1)
	}

	if err := w.videoTrack.WriteRTP(rtpPkt, codec); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		w.packetsDropped.Add(1)
		logger.Error(
			"Failed to write RTP packet",
			zap.Error(err),
		)
	}
}
