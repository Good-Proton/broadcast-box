package webrtc

import (
	"context"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
	"github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/require"
)

var testStreamInfo = &auth.StreamInfo{
	StreamKey: "test",
	LhUserId:  "",
}

func doesWHIPSessionExist() (ok bool) {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	_, ok = streamMap[testStreamInfo.StreamKey]
	return
}

func doesPublisherConnectionExist() bool {
	streamMapLock.Lock()
	defer streamMapLock.Unlock()

	stream, ok := streamMap[testStreamInfo.StreamKey]
	return ok && stream.publisherConnection != nil
}

func TestWHIPReleasesDataChannelsLockWhenEnsureDataChannelPairFails(t *testing.T) {
	Configure()

	streamInfo := &auth.StreamInfo{
		StreamKey: "whip-data-channel-lock-leak",
		LhUserId:  "",
	}
	whepSessionId := "stale-whep-session"
	label := "chat"

	staleSubscriber, err := newPeerConnection(apiWhep)
	require.NoError(t, err)
	require.NoError(t, staleSubscriber.Close())

	streamMapLock.Lock()
	testStream, err := getStream(streamInfo, "")
	require.NoError(t, err)
	testStream.subscriberConnections[whepSessionId] = staleSubscriber
	testStream.subscriberDataChannels[whepSessionId] = map[string]*webrtc.DataChannel{
		label: nil,
	}
	streamMapLock.Unlock()

	_, err = WHIP("unused offer", streamInfo)
	require.Error(t, err)

	lockAcquired := make(chan struct{})
	go func() {
		testStream.dataChannelsLock.Lock()
		defer testStream.dataChannelsLock.Unlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("dataChannelsLock remained locked after WHIP returned an error")
	}
}

// Asserts that a old PeerConnection doesn't destroy the new one
// when it disconnects
func TestReconnect(t *testing.T) {
	Configure()
	localTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264}, "video", "pion",
	)
	require.NoError(t, err)

	// Create the first WHIP Session
	firstPublisherConnected, firstPublisherConnectedDone := context.WithCancel(context.TODO())

	firstPublisher, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	require.NoError(t, err)

	firstPublisher.OnConnectionStateChange(func(c webrtc.PeerConnectionState) {
		if c == webrtc.PeerConnectionStateConnected {
			firstPublisherConnectedDone()

		}
	})

	_, err = firstPublisher.AddTrack(localTrack)
	require.NoError(t, err)

	offer, err := firstPublisher.CreateOffer(nil)
	require.NoError(t, err)
	require.NoError(t, firstPublisher.SetLocalDescription(offer))

	answer, err := WHIP(offer.SDP, testStreamInfo)
	require.NoError(t, err)

	require.NoError(t, firstPublisher.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer,
	}))

	require.True(t, doesWHIPSessionExist())
	<-firstPublisherConnected.Done()

	// Create the second WHIP Session
	secondPublisherConnected, secondPublisherConnectedDone := context.WithCancel(context.TODO())

	secondPublisher, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	require.NoError(t, err)

	secondPublisher.OnConnectionStateChange(func(c webrtc.PeerConnectionState) {
		if c == webrtc.PeerConnectionStateConnected {
			secondPublisherConnectedDone()

		}
	})

	_, err = secondPublisher.AddTrack(localTrack)
	require.NoError(t, err)

	offer, err = secondPublisher.CreateOffer(nil)
	require.NoError(t, err)
	require.NoError(t, secondPublisher.SetLocalDescription(offer))

	answer, err = WHIP(offer.SDP, testStreamInfo)
	require.NoError(t, err)

	require.NoError(t, secondPublisher.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer,
	}))

	require.True(t, doesWHIPSessionExist())
	<-secondPublisherConnected.Done()

	// Close the first WHIP Session, the session must still exist
	require.NoError(t, firstPublisher.Close())
	time.Sleep(time.Second)
	require.True(t, doesWHIPSessionExist())
	require.True(t, doesPublisherConnectionExist())

	// Close the second WHIP Session, the session must be gone
	require.NoError(t, secondPublisher.Close())
	time.Sleep(time.Second)
	require.False(t, doesWHIPSessionExist())
}
