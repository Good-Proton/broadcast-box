//go:build integration

package integration_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

const (
	h264PayloadType = webrtc.PayloadType(102)
	opusPayloadType = webrtc.PayloadType(111)
	h264FmtpLine    = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"
)

var (
	h264Feedback = []webrtc.RTCPFeedback{
		{Type: "goog-remb"},
		{Type: "ccm", Parameter: "fir"},
		{Type: "nack"},
		{Type: "nack", Parameter: "pli"},
	}

	h264SPS = []byte{0x67, 0x42, 0x00, 0x1f, 0xe5, 0x88, 0x68, 0x3c, 0x80}
	h264PPS = []byte{0x68, 0xce, 0x06, 0xe2}
	h264IDR = []byte{0x65, 0x88, 0x84, 0x21, 0xa0, 0x14, 0x01, 0x6e, 0x9b, 0x80}

	opusSilence = []byte{0xf8, 0xff, 0xfe}
)

type publisher struct {
	pc         *webrtc.PeerConnection
	videoTrack *webrtc.TrackLocalStaticRTP
	audioTrack *webrtc.TrackLocalStaticRTP
	cancel     context.CancelFunc
	closeOnce  sync.Once

	videoPackets atomic.Uint64
	audioPackets atomic.Uint64
}

func startPublisher(t *testing.T, endpoint string, streamKey string) *publisher {
	t.Helper()

	pc := newPeerConnection(t)
	connected, failed := observePeerConnection(pc)

	videoTrack, err := webrtc.NewTrackLocalStaticRTP(h264Capability(), "video", "integration")
	if err != nil {
		t.Fatalf("create video track: %v", err)
	}
	videoSender, err := pc.AddTrack(videoTrack)
	if err != nil {
		t.Fatalf("add video track: %v", err)
	}
	go drainSenderRTCP(videoSender)

	audioTrack, err := webrtc.NewTrackLocalStaticRTP(opusCapability(), "audio", "integration")
	if err != nil {
		t.Fatalf("create audio track: %v", err)
	}
	audioSender, err := pc.AddTrack(audioTrack)
	if err != nil {
		t.Fatalf("add audio track: %v", err)
	}
	go drainSenderRTCP(audioSender)

	offer := createLocalOffer(t, pc)
	answer := postOffer(t, endpoint, streamKey, offer)
	if err := pc.SetRemoteDescription(answer); err != nil {
		t.Fatalf("set WHIP answer: %v", err)
	}

	waitForPeerConnection(t, "publisher", connected, failed)

	publisher := &publisher{
		pc:         pc,
		videoTrack: videoTrack,
		audioTrack: audioTrack,
	}
	publisher.startMedia()
	return publisher
}

func (p *publisher) startMedia() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	go func() {
		ticker := time.NewTicker(33 * time.Millisecond)
		defer ticker.Stop()

		var seq uint16 = 1
		var timestamp uint32 = 90000
		var frame uint32

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				payload := h264Payload(frame)
				packet := &rtp.Packet{
					Header: rtp.Header{
						Version:        2,
						PayloadType:    uint8(h264PayloadType),
						SequenceNumber: seq,
						Timestamp:      timestamp,
						Marker:         true,
					},
					Payload: payload,
				}

				if err := p.videoTrack.WriteRTP(packet); err == nil {
					p.videoPackets.Add(1)
				}

				seq++
				timestamp += 3000
				frame++
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()

		var seq uint16 = 1
		var timestamp uint32 = 48000

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				packet := &rtp.Packet{
					Header: rtp.Header{
						Version:        2,
						PayloadType:    uint8(opusPayloadType),
						SequenceNumber: seq,
						Timestamp:      timestamp,
					},
					Payload: opusSilence,
				}

				if err := p.audioTrack.WriteRTP(packet); err == nil {
					p.audioPackets.Add(1)
				}

				seq++
				timestamp += 960
			}
		}
	}()
}

func (p *publisher) close() {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.pc != nil {
			_ = p.pc.Close()
		}
	})
}

type viewer struct {
	name      string
	pc        *webrtc.PeerConnection
	cancel    context.CancelFunc
	closeOnce sync.Once

	videoPackets atomic.Uint64
	videoFrames  atomic.Uint64
	audioPackets atomic.Uint64
}

func startViewer(t *testing.T, endpoint string, streamKey string, name string) *viewer {
	t.Helper()

	pc := newPeerConnection(t)
	connected, failed := observePeerConnection(pc)

	ctx, cancel := context.WithCancel(context.Background())
	viewer := &viewer{
		name:   name,
		pc:     pc,
		cancel: cancel,
	}

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		go viewer.readTrack(ctx, track)
	})

	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		cancel()
		t.Fatalf("%s add audio transceiver: %v", name, err)
	}
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		cancel()
		t.Fatalf("%s add video transceiver: %v", name, err)
	}

	offer := createLocalOffer(t, pc)
	answer := postOffer(t, endpoint, streamKey, offer)
	if err := pc.SetRemoteDescription(answer); err != nil {
		cancel()
		t.Fatalf("%s set WHEP answer: %v", name, err)
	}

	waitForPeerConnection(t, name, connected, failed)
	return viewer
}

func (v *viewer) readTrack(ctx context.Context, track *webrtc.TrackRemote) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = track.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		packet, _, err := track.ReadRTP()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		switch {
		case track.Kind() == webrtc.RTPCodecTypeAudio:
			v.audioPackets.Add(1)
		case track.Kind() == webrtc.RTPCodecTypeVideo && strings.EqualFold(track.Codec().MimeType, webrtc.MimeTypeH264):
			v.videoPackets.Add(1)
			if packet.Marker {
				v.videoFrames.Add(1)
			}
		}
	}
}

func (v *viewer) close() {
	v.closeOnce.Do(func() {
		if v.cancel != nil {
			v.cancel()
		}
		if v.pc != nil {
			_ = v.pc.Close()
		}
	})
}

func newPeerConnection(t *testing.T) *webrtc.PeerConnection {
	t.Helper()

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: opusCapability(),
		PayloadType:        opusPayloadType,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatalf("register opus codec: %v", err)
	}
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: h264Capability(),
		PayloadType:        h264PayloadType,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("register h264 codec: %v", err)
	}

	interceptorRegistry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(mediaEngine, interceptorRegistry); err != nil {
		t.Fatalf("register interceptors: %v", err)
	}

	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetIncludeLoopbackCandidate(true)
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})

	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(interceptorRegistry),
		webrtc.WithSettingEngine(settingEngine),
	)

	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create peer connection: %v", err)
	}
	return pc
}

func h264Capability() webrtc.RTPCodecCapability {
	return webrtc.RTPCodecCapability{
		MimeType:     webrtc.MimeTypeH264,
		ClockRate:    90000,
		SDPFmtpLine:  h264FmtpLine,
		RTCPFeedback: h264Feedback,
	}
}

func opusCapability() webrtc.RTPCodecCapability {
	return webrtc.RTPCodecCapability{
		MimeType:    webrtc.MimeTypeOpus,
		ClockRate:   48000,
		Channels:    2,
		SDPFmtpLine: "minptime=10;useinbandfec=1",
	}
}

func createLocalOffer(t *testing.T, pc *webrtc.PeerConnection) *webrtc.SessionDescription {
	t.Helper()

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatalf("set local offer: %v", err)
	}

	select {
	case <-gatherComplete:
	case <-time.After(10 * time.Second):
		t.Fatal("ICE gathering did not complete")
	}

	return pc.LocalDescription()
}

func postOffer(t *testing.T, endpoint string, streamKey string, offer *webrtc.SessionDescription) webrtc.SessionDescription {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(offer.SDP))
	if err != nil {
		t.Fatalf("create POST %s request: %v", endpoint, err)
	}
	req.Header.Set("Authorization", "Bearer "+streamKey)
	req.Header.Set("Content-Type", "application/sdp")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST %s response: %v", endpoint, err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s returned %d: %s", endpoint, resp.StatusCode, string(body))
	}

	return webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  string(body),
	}
}

func deleteWHIP(t *testing.T, endpoint string, streamKey string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		t.Fatalf("create DELETE %s request: %v", endpoint, err)
	}
	req.Header.Set("Authorization", "Bearer "+streamKey)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", endpoint, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read DELETE %s response: %v", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE %s returned %d: %s", endpoint, resp.StatusCode, string(body))
	}
}

func observePeerConnection(pc *webrtc.PeerConnection) (<-chan struct{}, <-chan webrtc.PeerConnectionState) {
	connected := make(chan struct{})
	failed := make(chan webrtc.PeerConnectionState, 1)
	var connectedOnce sync.Once

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateConnected:
			connectedOnce.Do(func() {
				close(connected)
			})
		case webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateFailed:
			select {
			case failed <- state:
			default:
			}
		}
	})

	return connected, failed
}

func waitForPeerConnection(t *testing.T, name string, connected <-chan struct{}, failed <-chan webrtc.PeerConnectionState) {
	t.Helper()

	select {
	case <-connected:
	case state := <-failed:
		t.Fatalf("%s peer connection reached %s before connected", name, state)
	case <-time.After(15 * time.Second):
		t.Fatalf("%s peer connection did not connect", name)
	}
}

func drainSenderRTCP(sender *webrtc.RTPSender) {
	for {
		if _, _, err := sender.ReadRTCP(); err != nil {
			return
		}
	}
}

func h264Payload(frame uint32) []byte {
	switch frame % 30 {
	case 0:
		return h264SPS
	case 1:
		return h264PPS
	default:
		return h264IDR
	}
}
