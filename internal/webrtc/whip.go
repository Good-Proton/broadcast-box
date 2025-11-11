package webrtc

import (
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/google/uuid"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"
)

func audioWriter(remoteTrack *webrtc.TrackRemote, stream *stream) {
	rtpBuf := make([]byte, 1500)
	for {
		rtpRead, _, err := remoteTrack.Read(rtpBuf)
		switch {
		case errors.Is(err, io.EOF):
			return
		case err != nil:
			logger.Error("Failed to read audio RTP packet", zap.Error(err))
			return
		}

		stream.audioPacketsReceived.Add(1)
		if _, writeErr := stream.audioTrack.Write(rtpBuf[:rtpRead]); writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
			logger.Error("Failed to write audio RTP packet", zap.Error(writeErr))
			return
		}
	}
}

func videoWriter(remoteTrack *webrtc.TrackRemote, stream *stream, peerConnection *webrtc.PeerConnection, s *stream, sessionId string, receiver *webrtc.RTPReceiver) {
	id := remoteTrack.RID()
	if id == "" {
		id = videoTrackLabelDefault
	}

	codecMimeType := remoteTrack.Codec().MimeType
	ssrc := uint32(remoteTrack.SSRC())

	videoTrack, err := addTrack(s, id, sessionId, codecMimeType, ssrc, receiver)
	if err != nil {
		logger.Error("Failed to add video track",
			zap.Error(err),
			zap.String("rid", id),
			zap.String("sessionId", sessionId),
		)
		return
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stream.whipActiveContext.Done():
				return
			case <-ticker.C:
				if receiver == nil {
					continue
				}

				now := time.Now()
				rtcpPackets, _, err := receiver.ReadRTCP()
				if err != nil {
					break
				}

				for _, pkt := range rtcpPackets {
					switch rtcpPkt := pkt.(type) {
					case *rtcp.ReceiverReport:
						for _, report := range rtcpPkt.Reports {
							if report.SSRC == ssrc {
								videoTrack.jitter.Store(uint64(report.Jitter))
								videoTrack.delay.Store(uint64(report.Delay))
								videoTrack.totalLost.Store(uint64(report.TotalLost))
								videoTrack.lastSenderReport.Store(uint64(report.LastSenderReport))
								videoTrack.lastRTCPTime.Store(now)
							}
						}
					}
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-stream.whipActiveContext.Done():
				return
			case <-stream.pliChan:
				if sendErr := peerConnection.WriteRTCP([]rtcp.Packet{
					&rtcp.PictureLossIndication{
						MediaSSRC: uint32(remoteTrack.SSRC()),
					},
				}); sendErr != nil {
					return
				}
			}
		}
	}()

	rtpBuf := make([]byte, 1500)
	rtpPkt := &rtp.Packet{}
	codec := getVideoTrackCodec(remoteTrack.Codec().MimeType)

	var depacketizer rtp.Depacketizer
	switch codec {
	case videoTrackCodecH264:
		depacketizer = &codecs.H264Packet{}
	case videoTrackCodecVP8:
		depacketizer = &codecs.VP8Packet{}
	case videoTrackCodecVP9:
		depacketizer = &codecs.VP9Packet{}
	}

	lastTimestamp := uint32(0)
	lastTimestampSet := false

	lastSequenceNumber := uint16(0)
	lastSequenceNumberSet := false

	for {
		rtpRead, _, err := remoteTrack.Read(rtpBuf)
		switch {
		case errors.Is(err, io.EOF):
			return
		case err != nil:
			logger.Error("Failed to read RTP packet",
				zap.Error(err),
				zap.String("rid", id),
				zap.String("sessionId", sessionId),
			)
			return
		}

		if err = rtpPkt.Unmarshal(rtpBuf[:rtpRead]); err != nil {
			logger.Error("Failed to unmarshal RTP packet",
				zap.Error(err),
				zap.String("rid", id),
				zap.String("sessionId", sessionId),
			)
			return
		}

		now := time.Now()

		// Track first packet time
		if firstPacket, ok := videoTrack.firstPacketTime.Load().(time.Time); !ok || firstPacket.IsZero() {
			videoTrack.firstPacketTime.Store(now)
		}
		videoTrack.lastPacketTime.Store(now)

		videoTrack.packetsReceived.Add(1)
		videoTrack.bytesReceived.Add(uint64(rtpRead))

		// Track packet loss
		lastSeq := videoTrack.lastSequenceNumber.Load()
		if lastSeq != 0 {
			expectedSeq := uint32(uint16(lastSeq) + 1)
			if uint32(rtpPkt.SequenceNumber) != expectedSeq {
				var lost uint32
				if rtpPkt.SequenceNumber > uint16(lastSeq) {
					lost = uint32(rtpPkt.SequenceNumber) - uint32(uint16(lastSeq)) - 1
				} else {
					lost = (uint32(0xFFFF) - uint32(uint16(lastSeq))) + uint32(rtpPkt.SequenceNumber)
				}
				videoTrack.packetsLost.Add(uint64(lost))
			}
		}
		videoTrack.lastSequenceNumber.Store(uint32(rtpPkt.SequenceNumber))

		if rtpPkt.Marker {
			videoTrack.framesReceived.Add(1)
		}

		// Keyframe detection has only been implemented for H264
		isKeyframe := isKeyframe(rtpPkt, codec, depacketizer)
		if isKeyframe && codec == videoTrackCodecH264 {
			videoTrack.keyframesReceived.Add(1)
			videoTrack.lastKeyFrameSeen.Store(now)
		}

		rtpPkt.Extension = false
		rtpPkt.Extensions = nil

		timeDiff := int64(rtpPkt.Timestamp) - int64(lastTimestamp)
		switch {
		case !lastTimestampSet:
			timeDiff = 0
			lastTimestampSet = true
		case timeDiff < -(math.MaxUint32 / 10):
			timeDiff += (math.MaxUint32 + 1)
		}

		sequenceDiff := int(rtpPkt.SequenceNumber) - int(lastSequenceNumber)
		switch {
		case !lastSequenceNumberSet:
			lastSequenceNumberSet = true
			sequenceDiff = 0
		case sequenceDiff < -(math.MaxUint16 / 10):
			sequenceDiff += (math.MaxUint16 + 1)
		}

		lastTimestamp = rtpPkt.Timestamp
		lastSequenceNumber = rtpPkt.SequenceNumber

		s.whepSessionsLock.RLock()
		for i := range s.whepSessions {
			s.whepSessions[i].sendVideoPacket(rtpPkt, id, timeDiff, sequenceDiff, codec, isKeyframe)
		}
		s.whepSessionsLock.RUnlock()

	}
}

func WHIP(offer string, streamInfo *auth.StreamInfo) (string, error) {
	maybePrintOfferAnswer(offer, true)

	whipSessionId := uuid.New().String()

	peerConnection, err := newPeerConnection(apiWhip)
	if err != nil {
		return "", err
	}

	streamMapLock.Lock()
	defer streamMapLock.Unlock()
	stream, err := getStream(streamInfo, whipSessionId)
	if err != nil {
		return "", err
	}

	peerConnection.OnTrack(func(remoteTrack *webrtc.TrackRemote, rtpReceiver *webrtc.RTPReceiver) {
		if strings.HasPrefix(remoteTrack.Codec().MimeType, "audio") {
			audioWriter(remoteTrack, stream)
		} else {
			videoWriter(remoteTrack, stream, peerConnection, stream, whipSessionId, rtpReceiver)
		}
	})

	peerConnection.OnICEConnectionStateChange(func(i webrtc.ICEConnectionState) {
		stream.whipICEConnectionState.Store(i.String())

		if i == webrtc.ICEConnectionStateConnected && stream.whipConnectionEstablishedTime.Load() == 0 {
			stream.whipConnectionEstablishedTime.Store(uint64(time.Now().Unix()))
		}

		if i == webrtc.ICEConnectionStateFailed || i == webrtc.ICEConnectionStateClosed {
			if err := peerConnection.Close(); err != nil {
				logger.Error("Failed to close peer connection",
					zap.Error(err),
					zap.String("streamKey", streamInfo.StreamKey),
					zap.String("iceState", i.String()),
				)
			}
			peerConnectionDisconnected(true, streamInfo.StreamKey, whipSessionId)
		}
	})

	stream.dataChannelsLock.Lock()
	stream.publisherConnection = peerConnection

	for whepSessionId := range stream.subscriberConnections {
		for label := range stream.subscriberDataChannels[whepSessionId] {
			if err := ensureDataChannelPair(label, stream, nil, &whepSessionId); err != nil {
				return "", err
			}
		}
	}
	stream.dataChannelsLock.Unlock()

	peerConnection.OnDataChannel(func(channel *webrtc.DataChannel) {
		stream.dataChannelsLock.Lock()
		label := channel.Label()
		if err := ensureDataChannelPair(label, stream, channel, nil); err != nil {
			logger.Error("Failed to ensure data channel pair",
				zap.Error(err),
				zap.String("label", label),
			)
		}
		stream.dataChannelsLock.Unlock()
	})

	if err := peerConnection.SetRemoteDescription(webrtc.SessionDescription{
		SDP:  string(offer),
		Type: webrtc.SDPTypeOffer,
	}); err != nil {
		return "", err
	}

	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	answer, err := peerConnection.CreateAnswer(nil)

	if err != nil {
		return "", err
	} else if err = peerConnection.SetLocalDescription(answer); err != nil {
		return "", err
	}

	<-gatherComplete
	return maybePrintOfferAnswer(appendAnswer(peerConnection.LocalDescription().SDP), false), nil
}
