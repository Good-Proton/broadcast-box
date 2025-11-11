package webrtc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/ice/v3"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"
)

const (
	videoTrackLabelDefault = "default"

	videoTrackCodecH264 videoTrackCodec = iota + 1
	videoTrackCodecVP8
	videoTrackCodecVP9
	videoTrackCodecAV1
	videoTrackCodecH265
)

type (
	stream struct {
		// Does this stream have a publisher?
		// If stream was created by a WHEP request hasWHIPClient == false
		hasWHIPClient atomic.Bool
		sessionId     string
		lhUserId      string

		firstSeenEpoch uint64

		videoTracks []*videoTrack

		audioTrack           *webrtc.TrackLocalStaticRTP
		audioPacketsReceived atomic.Uint64

		pliChan chan any

		whipActiveContext       context.Context
		whipActiveContextCancel func()

		whepSessionsLock sync.RWMutex
		whepSessions     map[string]*whepSession

		subscriberDataChannels      map[string]map[string]*webrtc.DataChannel
		publisherDataChannels       map[string]*webrtc.DataChannel
		dataChannelsLock            sync.RWMutex
		dataChannelMessagesReceived atomic.Uint64
		dataChannelBytesSent        atomic.Uint64
		dataChannelBytesReceived    atomic.Uint64

		subscriberConnections         map[string]*webrtc.PeerConnection
		publisherConnection           *webrtc.PeerConnection
		whipConnectionEstablishedTime atomic.Uint64
		whipICEConnectionState        atomic.Value
	}

	videoTrack struct {
		sessionId          string
		rid                string
		codec              string
		ssrc               uint32
		packetsReceived    atomic.Uint64
		bytesReceived      atomic.Uint64
		framesReceived     atomic.Uint64
		keyframesReceived  atomic.Uint64
		packetsLost        atomic.Uint64
		lastSequenceNumber atomic.Uint32
		lastKeyFrameSeen   atomic.Value
		firstPacketTime    atomic.Value
		lastPacketTime     atomic.Value
		startTime          uint64
		width              atomic.Uint32
		height             atomic.Uint32

		rtt              atomic.Uint64
		jitter           atomic.Uint64
		lastRTCPTime     atomic.Value
		delay            atomic.Uint64
		totalLost        atomic.Uint64
		lastSenderReport atomic.Uint64

		receiver *webrtc.RTPReceiver
	}

	videoTrackCodec int
)

var (
	streamMap        map[string]*stream
	streamMapLock    sync.Mutex
	apiWhip, apiWhep *webrtc.API

	// nolint
	videoRTCPFeedback = []webrtc.RTCPFeedback{{"goog-remb", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}
)

func getVideoTrackCodec(in string) videoTrackCodec {
	downcased := strings.ToLower(in)
	switch {
	case strings.Contains(downcased, strings.ToLower(webrtc.MimeTypeH264)):
		return videoTrackCodecH264
	case strings.Contains(downcased, strings.ToLower(webrtc.MimeTypeVP8)):
		return videoTrackCodecVP8
	case strings.Contains(downcased, strings.ToLower(webrtc.MimeTypeVP9)):
		return videoTrackCodecVP9
	case strings.Contains(downcased, strings.ToLower(webrtc.MimeTypeAV1)):
		return videoTrackCodecAV1
	case strings.Contains(downcased, strings.ToLower(webrtc.MimeTypeH265)):
		return videoTrackCodecH265
	}

	return 0
}

func getStream(streamInfo *auth.StreamInfo, whipSessionId string) (*stream, error) {
	foundStream, ok := streamMap[streamInfo.StreamKey]
	if !ok {
		audioTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "pion")
		if err != nil {
			return nil, err
		}

		whipActiveContext, whipActiveContextCancel := context.WithCancel(context.Background())

		foundStream = &stream{
			audioTrack:              audioTrack,
			pliChan:                 make(chan any, 50),
			whepSessions:            map[string]*whepSession{},
			whipActiveContext:       whipActiveContext,
			whipActiveContextCancel: whipActiveContextCancel,
			firstSeenEpoch:          uint64(time.Now().Unix()),
			subscriberDataChannels:  make(map[string]map[string]*webrtc.DataChannel),
			publisherDataChannels:   make(map[string]*webrtc.DataChannel),
			subscriberConnections:   make(map[string]*webrtc.PeerConnection),
			lhUserId:                streamInfo.LhUserId,
		}
		foundStream.whipICEConnectionState.Store("new")
		streamMap[streamInfo.StreamKey] = foundStream
	}

	if whipSessionId != "" {
		foundStream.hasWHIPClient.Store(true)
		foundStream.sessionId = whipSessionId
		foundStream.lhUserId = streamInfo.LhUserId
	}

	return foundStream, nil
}

func peerConnectionDisconnected(forWHIP bool, streamKey string, sessionId string) {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	stream, ok := streamMap[streamKey]
	if !ok {
		return
	}

	stream.whepSessionsLock.Lock()
	defer stream.whepSessionsLock.Unlock()

	if !forWHIP {
		stream.dataChannelsLock.Lock()
		delete(stream.subscriberConnections, sessionId)
		stream.dataChannelsLock.Unlock()

		delete(stream.whepSessions, sessionId)
	} else {
		stream.dataChannelsLock.Lock()
		stream.publisherConnection = nil
		stream.dataChannelsLock.Unlock()

		stream.videoTracks = slices.DeleteFunc(stream.videoTracks, func(v *videoTrack) bool {
			return v.sessionId == sessionId
		})

		// A PeerConnection for a old WHIP session has gone to disconnected
		// closed. Cleanup the state associated with that session, but
		// don't modify the current session
		if stream.sessionId != sessionId {
			return
		}
		stream.hasWHIPClient.Store(false)
	}

	// Only delete stream if all WHEP Sessions are gone and have no WHIP Client
	if len(stream.whepSessions) != 0 || stream.hasWHIPClient.Load() {
		return
	}

	stream.whipActiveContextCancel()
	delete(streamMap, streamKey)
}

func addTrack(stream *stream, rid, sessionId, codec string, ssrc uint32, receiver *webrtc.RTPReceiver) (*videoTrack, error) {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	for i := range stream.videoTracks {
		if rid == stream.videoTracks[i].rid && sessionId == stream.videoTracks[i].sessionId {
			return stream.videoTracks[i], nil
		}
	}

	t := &videoTrack{
		rid:       rid,
		sessionId: sessionId,
		codec:     codec,
		ssrc:      ssrc,
		startTime: uint64(time.Now().Unix()),
		receiver:  receiver,
	}
	t.lastKeyFrameSeen.Store(time.Time{})
	t.firstPacketTime.Store(time.Time{})
	t.lastPacketTime.Store(time.Time{})
	t.lastRTCPTime.Store(time.Time{})
	stream.videoTracks = append(stream.videoTracks, t)
	return t, nil
}

func getPublicIP() string {
	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		logger.Fatal("Failed to get public IP", zap.Error(err))
	}
	defer func() {
		if closeErr := req.Body.Close(); closeErr != nil {
			logger.Fatal("Failed to close request body", zap.Error(closeErr))
		}
	}()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Fatal("Failed to read request body", zap.Error(err))
	}

	ip := struct {
		Query string
	}{}
	if err = json.Unmarshal(body, &ip); err != nil {
		logger.Fatal("Failed to unmarshal IP response", zap.Error(err))
	}

	if ip.Query == "" {
		logger.Fatal("Query entry was not populated")
	}

	return ip.Query
}

func createSettingEngine(isWHIP bool, udpMuxCache map[int]*ice.MultiUDPMuxDefault, tcpMuxCache map[string]ice.TCPMux) (settingEngine webrtc.SettingEngine) {
	var (
		NAT1To1IPs   []string
		networkTypes []webrtc.NetworkType
		udpMuxPort   int
		udpMuxOpts   []ice.UDPMuxFromPortOption
		err          error
	)

	if os.Getenv("NETWORK_TYPES") != "" {
		for _, networkTypeStr := range strings.Split(os.Getenv("NETWORK_TYPES"), "|") {
			networkType, err := webrtc.NewNetworkType(networkTypeStr)
			if err != nil {
				logger.Fatal("Failed to create network type",
					zap.Error(err),
					zap.String("networkTypeStr", networkTypeStr),
				)
			}
			networkTypes = append(networkTypes, networkType)
		}
	} else {
		networkTypes = append(networkTypes, webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6)
	}

	if os.Getenv("INCLUDE_PUBLIC_IP_IN_NAT_1_TO_1_IP") != "" {
		NAT1To1IPs = append(NAT1To1IPs, getPublicIP())
	}

	if os.Getenv("NAT_1_TO_1_IP") != "" {
		NAT1To1IPs = append(NAT1To1IPs, strings.Split(os.Getenv("NAT_1_TO_1_IP"), "|")...)
	}

	natICECandidateType := webrtc.ICECandidateTypeHost
	if os.Getenv("NAT_ICE_CANDIDATE_TYPE") == "srflx" {
		natICECandidateType = webrtc.ICECandidateTypeSrflx
	}

	if len(NAT1To1IPs) != 0 {
		settingEngine.SetNAT1To1IPs(NAT1To1IPs, natICECandidateType)
	}

	if os.Getenv("INTERFACE_FILTER") != "" {
		interfaceFilter := func(i string) bool {
			return i == os.Getenv("INTERFACE_FILTER")
		}

		settingEngine.SetInterfaceFilter(interfaceFilter)
		udpMuxOpts = append(udpMuxOpts, ice.UDPMuxFromPortWithInterfaceFilter(interfaceFilter))
	}

	portWhipEnv := os.Getenv("PORT_RANGE_UDP_WHIP")
	portWhepEnv := os.Getenv("PORT_RANGE_UDP_WHEP")
	muxPortEnv := os.Getenv("UDP_MUX_PORT")

	if isWHIP && portWhipEnv != "" {
		if udpMuxPort, err = strconv.Atoi(portWhipEnv); err != nil {
			logger.Fatal("Failed to parse UDP_MUX_PORT_WHIP", zap.Error(err), zap.String("value", portWhipEnv))
		}
	} else if !isWHIP && portWhepEnv != "" {
		if udpMuxPort, err = strconv.Atoi(portWhepEnv); err != nil {
			logger.Fatal("Failed to parse UDP_MUX_PORT_WHEP", zap.Error(err), zap.String("value", portWhepEnv))
		}
	} else if muxPortEnv != "" {
		if udpMuxPort, err = strconv.Atoi(muxPortEnv); err != nil {
			logger.Fatal("Failed to parse UDP_MUX_PORT", zap.Error(err), zap.String("value", muxPortEnv))
		}
	}

	if udpMuxPort != 0 {
		udpMux, ok := udpMuxCache[udpMuxPort]
		if !ok {
			if udpMux, err = ice.NewMultiUDPMuxFromPort(udpMuxPort, udpMuxOpts...); err != nil {
				logger.Fatal("Failed to create UDP mux", zap.Error(err), zap.Int("udpMuxPort", udpMuxPort))
			}

			for _, addr := range udpMux.GetListenAddresses() {
				logger.Info(
					"Listening to UDP mux",
					zap.String("network", addr.Network()),
					zap.String("address", addr.String()),
				)
			}

			udpMuxCache[udpMuxPort] = udpMux
		}

		settingEngine.SetICEUDPMux(udpMux)
	}

	tcpAddressEnv := os.Getenv("TCP_MUX_ADDRESS")

	if tcpAddressEnv != "" {
		tcpMux, ok := tcpMuxCache[tcpAddressEnv]
		if !ok {
			tcpAddr, err := net.ResolveTCPAddr("tcp", tcpAddressEnv)
			if err != nil {
				logger.Fatal("Failed to resolve TCP address", zap.Error(err), zap.String("value", tcpAddressEnv))
			}

			tcpListener, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				logger.Fatal("Failed to listen on TCP address", zap.Error(err), zap.String("address", tcpAddr.String()))
			}

			tcpMux = webrtc.NewICETCPMux(nil, tcpListener, 8)
			tcpMuxCache[tcpAddressEnv] = tcpMux
		}
		settingEngine.SetICETCPMux(tcpMux)

		if os.Getenv("TCP_MUX_FORCE") != "" {
			networkTypes = []webrtc.NetworkType{webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6}
		} else {
			networkTypes = append(networkTypes, webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6)
		}
	}

	settingEngine.SetDTLSEllipticCurves(elliptic.X25519, elliptic.P384, elliptic.P256)
	settingEngine.SetNetworkTypes(networkTypes)
	settingEngine.DisableSRTCPReplayProtection(true)
	settingEngine.DisableSRTPReplayProtection(true)
	settingEngine.SetIncludeLoopbackCandidate(os.Getenv("INCLUDE_LOOPBACK_CANDIDATE") != "")

	return
}

func PopulateMediaEngine(m *webrtc.MediaEngine) error {
	for _, codec := range []webrtc.RTPCodecParameters{
		{
			// nolint
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeOpus, 48000, 2, "minptime=10;useinbandfec=1", nil},
			PayloadType:        111,
		},
	} {
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}

	for _, codecDetails := range []struct {
		payloadType uint8
		mimeType    string
		sdpFmtpLine string
	}{
		{102, webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"},
		{104, webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f"},
		{106, webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"},
		{108, webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f"},
		{39, webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f"},
		{45, webrtc.MimeTypeAV1, ""},
		{98, webrtc.MimeTypeVP9, "profile-id=0"},
		{100, webrtc.MimeTypeVP9, "profile-id=2"},
		{113, webrtc.MimeTypeH265, "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST"},
	} {
		if err := m.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:     codecDetails.mimeType,
				ClockRate:    90000,
				Channels:     0,
				SDPFmtpLine:  codecDetails.sdpFmtpLine,
				RTCPFeedback: videoRTCPFeedback,
			},
			PayloadType: webrtc.PayloadType(codecDetails.payloadType),
		}, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}

		if err := m.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:     "video/rtx",
				ClockRate:    90000,
				Channels:     0,
				SDPFmtpLine:  fmt.Sprintf("apt=%d", codecDetails.payloadType),
				RTCPFeedback: nil,
			},
			PayloadType: webrtc.PayloadType(codecDetails.payloadType + 1),
		}, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	return nil
}

func newPeerConnection(api *webrtc.API) (*webrtc.PeerConnection, error) {
	cfg := webrtc.Configuration{}

	if stunServers := os.Getenv("STUN_SERVERS"); stunServers != "" {
		for _, stunServer := range strings.Split(stunServers, "|") {
			cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{
				URLs: []string{"stun:" + stunServer},
			})
		}
	}

	return api.NewPeerConnection(cfg)
}

func appendAnswer(in string) string {
	if extraCandidate := os.Getenv("APPEND_CANDIDATE"); extraCandidate != "" {
		index := strings.Index(in, "a=end-of-candidates")
		in = in[:index] + extraCandidate + in[index:]
	}

	return in
}

func maybePrintOfferAnswer(sdp string, isOffer bool) string {
	if os.Getenv("DEBUG_PRINT_OFFER") == "true" && isOffer {
		fmt.Println(sdp)
	}

	if os.Getenv("DEBUG_PRINT_ANSWER") == "true" && !isOffer {
		fmt.Println(sdp)
	}

	return sdp
}

func Configure() {
	streamMap = map[string]*stream{}

	mediaEngine := &webrtc.MediaEngine{}
	if err := PopulateMediaEngine(mediaEngine); err != nil {
		logger.Error("Populating media engine failed", zap.Error(err))
		panic(err)
	}

	interceptorRegistry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(mediaEngine, interceptorRegistry); err != nil {
		logger.Fatal("Registering default interceptors failed", zap.Error(err))
	}

	udpMuxCache := map[int]*ice.MultiUDPMuxDefault{}
	tcpMuxCache := map[string]ice.TCPMux{}

	apiWhip = webrtc.NewAPI(
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(interceptorRegistry),
		webrtc.WithSettingEngine(createSettingEngine(true, udpMuxCache, tcpMuxCache)),
	)

	apiWhep = webrtc.NewAPI(
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(interceptorRegistry),
		webrtc.WithSettingEngine(createSettingEngine(false, udpMuxCache, tcpMuxCache)),
	)
}

type StreamStatusVideo struct {
	RID               string    `json:"rid"`
	Codec             string    `json:"codec"`
	SSRC              uint32    `json:"ssrc"`
	PacketsReceived   uint64    `json:"packetsReceived"`
	PacketsLost       uint64    `json:"packetsLost"`
	BytesReceived     uint64    `json:"bytesReceived"`
	FramesReceived    uint64    `json:"framesReceived"`
	KeyframesReceived uint64    `json:"keyframesReceived"`
	LastKeyFrameSeen  time.Time `json:"lastKeyFrameSeen"`
	FirstPacketTime   time.Time `json:"firstPacketTime"`
	LastPacketTime    time.Time `json:"lastPacketTime"`
	StartTime         uint64    `json:"startTime"`
	Width             uint32    `json:"width"`
	Height            uint32    `json:"height"`

	Jitter           uint64    `json:"jitter"`
	RTT              uint64    `json:"rtt"`
	LastRTCPTime     time.Time `json:"lastRTCPTime"`
	Delay            uint64    `json:"delay"`
	TotalLost        uint64    `json:"totalLost"`
	LastSenderReport uint64    `json:"lastSenderReport"`
	PacketLossRate   float64   `json:"packetLossRate"`
	AverageBitrate   float64   `json:"averageBitrate"`
	FrameRate        float64   `json:"frameRate"`
}

type StreamStatus struct {
	StreamKey                     string              `json:"streamKey"`
	LhUserId                      string              `json:"lhUserId"`
	FirstSeenEpoch                uint64              `json:"firstSeenEpoch"`
	AudioPacketsReceived          uint64              `json:"audioPacketsReceived"`
	VideoStreams                  []StreamStatusVideo `json:"videoStreams"`
	WHEPSessions                  []whepSessionStatus `json:"whepSessions"`
	DataChannelCount              int                 `json:"dataChannelCount"`
	DataChannelMessagesReceived   uint64              `json:"dataChannelMessagesReceived"`
	DataChannelBytesSent          uint64              `json:"dataChannelBytesSent"`
	DataChannelBytesReceived      uint64              `json:"dataChannelBytesReceived"`
	WHIPConnectionEstablishedTime uint64              `json:"whipConnectionEstablishedTime"`
	WHIPICEConnectionState        string              `json:"whipICEConnectionState"`
}

type whepSessionStatus struct {
	ID                        string `json:"id"`
	CurrentLayer              string `json:"currentLayer"`
	SequenceNumber            uint16 `json:"sequenceNumber"`
	Timestamp                 uint32 `json:"timestamp"`
	PacketsWritten            uint64 `json:"packetsWritten"`
	BytesWritten              uint64 `json:"bytesWritten"`
	FramesWritten             uint64 `json:"framesWritten"`
	KeyframesWritten          uint64 `json:"keyframesWritten"`
	PacketsDropped            uint64 `json:"packetsDropped"`
	PacketsSkippedForKeyframe uint64 `json:"packetsSkippedForKeyframe"`
	LayerSwitches             uint64 `json:"layerSwitches"`
	SessionStartEpoch         uint64 `json:"sessionStartEpoch"`
	ConnectionEstablishedTime uint64 `json:"connectionEstablishedTime"`
	FirstPacketTime           uint64 `json:"firstPacketTime"`
	LastPacketTime            uint64 `json:"lastPacketTime"`
	ICEConnectionState        string `json:"iceConnectionState"`
}

func GetStreamStatuses() []StreamStatus {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	out := make([]StreamStatus, 0, len(streamMap))

	for streamKey, stream := range streamMap {
		stream.whepSessionsLock.RLock()
		whepSessions := make([]whepSessionStatus, 0, len(stream.whepSessions))
		for id, whepSession := range stream.whepSessions {
			currentLayer, ok := whepSession.currentLayer.Load().(string)
			if !ok {
				continue
			}

			iceState, _ := whepSession.iceConnectionState.Load().(string)

			whepSessions = append(whepSessions, whepSessionStatus{
				ID:                        id,
				CurrentLayer:              currentLayer,
				SequenceNumber:            whepSession.sequenceNumber,
				Timestamp:                 whepSession.timestamp,
				PacketsWritten:            whepSession.packetsWritten,
				BytesWritten:              whepSession.bytesWritten.Load(),
				FramesWritten:             whepSession.framesWritten.Load(),
				KeyframesWritten:          whepSession.keyframesWritten.Load(),
				PacketsDropped:            whepSession.packetsDropped.Load(),
				PacketsSkippedForKeyframe: whepSession.packetsSkippedForKeyframe.Load(),
				LayerSwitches:             whepSession.layerSwitches.Load(),
				SessionStartEpoch:         whepSession.sessionStartEpoch,
				ConnectionEstablishedTime: whepSession.connectionEstablishedTime.Load(),
				FirstPacketTime:           whepSession.firstPacketTime.Load(),
				LastPacketTime:            whepSession.lastPacketTime.Load(),
				ICEConnectionState:        iceState,
			})
		}
		stream.whepSessionsLock.RUnlock()

		streamStatusVideo := make([]StreamStatusVideo, 0, len(stream.videoTracks))
		for _, videoTrack := range stream.videoTracks {
			var lastKeyFrameSeen, firstPacketTime, lastPacketTime, lastRTCPTime time.Time
			if v, ok := videoTrack.lastKeyFrameSeen.Load().(time.Time); ok {
				lastKeyFrameSeen = v
			}
			if v, ok := videoTrack.firstPacketTime.Load().(time.Time); ok {
				firstPacketTime = v
			}
			if v, ok := videoTrack.lastPacketTime.Load().(time.Time); ok {
				lastPacketTime = v
			}
			if v, ok := videoTrack.lastRTCPTime.Load().(time.Time); ok {
				lastRTCPTime = v
			}

			packetsReceived := videoTrack.packetsReceived.Load()
			packetsLost := videoTrack.packetsLost.Load()
			bytesReceived := videoTrack.bytesReceived.Load()
			framesReceived := videoTrack.framesReceived.Load()

			var packetLossRate float64
			if packetsReceived > 0 {
				totalPackets := packetsReceived + packetsLost
				packetLossRate = (float64(packetsLost) / float64(totalPackets)) * 100.0
			}

			var averageBitrate, frameRate float64

			if !lastPacketTime.IsZero() && !firstPacketTime.IsZero() {
				duration := lastPacketTime.Sub(firstPacketTime).Seconds()
				if duration > 0 {
					averageBitrate = (float64(bytesReceived) * 8) / duration
					frameRate = float64(framesReceived) / duration
				}
			}

			streamStatusVideo = append(streamStatusVideo, StreamStatusVideo{
				RID:               videoTrack.rid,
				Codec:             videoTrack.codec,
				SSRC:              videoTrack.ssrc,
				PacketsReceived:   packetsReceived,
				PacketsLost:       packetsLost,
				BytesReceived:     bytesReceived,
				FramesReceived:    framesReceived,
				KeyframesReceived: videoTrack.keyframesReceived.Load(),
				LastKeyFrameSeen:  lastKeyFrameSeen,
				FirstPacketTime:   firstPacketTime,
				LastPacketTime:    lastPacketTime,
				StartTime:         videoTrack.startTime,
				Width:             videoTrack.width.Load(),
				Height:            videoTrack.height.Load(),
				Jitter:            videoTrack.jitter.Load(),
				RTT:               videoTrack.rtt.Load(),
				LastRTCPTime:      lastRTCPTime,
				Delay:             videoTrack.delay.Load(),
				TotalLost:         videoTrack.totalLost.Load(),
				LastSenderReport:  videoTrack.lastSenderReport.Load(),
				PacketLossRate:    packetLossRate,
				AverageBitrate:    averageBitrate,
				FrameRate:         frameRate,
			})
		}

		dataChannelCount := len(stream.publisherDataChannels)
		whipICEState, _ := stream.whipICEConnectionState.Load().(string)

		out = append(out, StreamStatus{
			StreamKey:                     streamKey,
			LhUserId:                      stream.lhUserId,
			FirstSeenEpoch:                stream.firstSeenEpoch,
			AudioPacketsReceived:          stream.audioPacketsReceived.Load(),
			VideoStreams:                  streamStatusVideo,
			WHEPSessions:                  whepSessions,
			DataChannelCount:              dataChannelCount,
			DataChannelMessagesReceived:   stream.dataChannelMessagesReceived.Load(),
			DataChannelBytesSent:          stream.dataChannelBytesSent.Load(),
			DataChannelBytesReceived:      stream.dataChannelBytesReceived.Load(),
			WHIPConnectionEstablishedTime: stream.whipConnectionEstablishedTime.Load(),
			WHIPICEConnectionState:        whipICEState,
		})
	}

	return out
}

func ensureDataChannelPair(label string, stream *stream, channel *webrtc.DataChannel, whepSessionId *string) error {
	if channel != nil {
		if whepSessionId == nil {
			stream.publisherDataChannels[label] = channel
		} else {
			if stream.subscriberDataChannels[*whepSessionId] == nil {
				stream.subscriberDataChannels[*whepSessionId] = make(map[string]*webrtc.DataChannel)
			}
			stream.subscriberDataChannels[*whepSessionId][label] = channel
		}
	}

	if stream.publisherDataChannels[label] == nil {
		var err error
		stream.publisherDataChannels[label], err = stream.publisherConnection.CreateDataChannel(label, nil)
		if err != nil {
			return err
		}
	}

	stream.publisherDataChannels[label].OnMessage(func(msg webrtc.DataChannelMessage) {
		stream.dataChannelMessagesReceived.Add(1)
		stream.dataChannelBytesReceived.Add(uint64(len(msg.Data)))

		stream.dataChannelsLock.RLock()
		defer stream.dataChannelsLock.RUnlock()

		for _, channels := range stream.subscriberDataChannels {
			if channel, ok := channels[label]; ok {
				if err := channel.Send(msg.Data); err != nil {
					logger.Error("Failed to send data channel message",
						zap.Error(err),
						zap.Uint16p("channelId", channel.ID()),
						zap.String("label", label),
					)
				} else {
					stream.dataChannelBytesSent.Add(uint64(len(msg.Data)))
				}
			}
		}
	})

	stream.publisherDataChannels[label].OnClose(func() {
		stream.dataChannelsLock.Lock()
		defer stream.dataChannelsLock.Unlock()

		delete(stream.publisherDataChannels, label)
		for _, channels := range stream.subscriberDataChannels {
			if channel, ok := channels[label]; ok {
				if err := channel.Close(); err != nil {
					logger.Error("Failed to send data channel message",
						zap.Error(err),
						zap.Uint16p("channelId", channel.ID()),
						zap.String("label", label),
					)
				}
			}
		}
	})

	for whepSessionId, peerConnection := range stream.subscriberConnections {
		if stream.subscriberDataChannels[whepSessionId] == nil {
			stream.subscriberDataChannels[whepSessionId] = make(map[string]*webrtc.DataChannel)
		}

		if stream.subscriberDataChannels[whepSessionId][label] == nil {
			var err error
			stream.subscriberDataChannels[whepSessionId][label], err = peerConnection.CreateDataChannel(label, nil)
			if err != nil {
				return err
			}
		}

		stream.subscriberDataChannels[whepSessionId][label].OnMessage(func(msg webrtc.DataChannelMessage) {
			stream.dataChannelsLock.RLock()
			defer stream.dataChannelsLock.RUnlock()

			if channel, ok := stream.publisherDataChannels[label]; ok {
				if err := channel.Send(msg.Data); err != nil {
					logger.Error("Failed to send data channel message",
						zap.Error(err),
						zap.Uint16p("channelId", channel.ID()),
						zap.String("label", label),
					)
				}
			}
		})

		stream.subscriberDataChannels[whepSessionId][label].OnClose(func() {
			stream.dataChannelsLock.Lock()
			defer stream.dataChannelsLock.Unlock()

			delete(stream.subscriberDataChannels[whepSessionId], label)
			if len(stream.subscriberDataChannels[whepSessionId]) == 0 {
				delete(stream.subscriberDataChannels, whepSessionId)
			}
		})
	}

	return nil
}
