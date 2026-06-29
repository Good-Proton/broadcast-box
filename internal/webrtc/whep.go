package webrtc

import (
	"log/slog"

	"github.com/glimesh/broadcast-box/internal/server/authorization"
	"github.com/glimesh/broadcast-box/internal/webrtc/codecs"
	"github.com/glimesh/broadcast-box/internal/webrtc/peerconnection"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
	"github.com/glimesh/broadcast-box/internal/webrtc/utils"
	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
)

func WHEP(offer string, profile authorization.PublicProfile) (string, string, error) {
	utils.DebugOutputOffer(offer)

	session, err := manager.SessionsManager.GetOrAddSession(profile, false)
	if err != nil {
		slog.Error("Failed to get stream for WHEP",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
			slog.String("lhUserId", profile.LhUserId),
		)
		return "", "", err
	}

	whepSessionID := uuid.New().String()

	peerConnection, err := peerconnection.CreateWHEPPeerConnection()
	if err != nil {
		slog.Error("Failed to create peer connection",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
			slog.String("lhUserId", profile.LhUserId),
			slog.String("whepSessionId", whepSessionID),
		)
		return "", "", err
	}

	audioTrack, videoTrack := codecs.GetDefaultTracks(profile.StreamKey)

	_, err = peerConnection.AddTrack(audioTrack)
	if err != nil {
		return "", "", err
	}

	videoRTCPSender, err := peerConnection.AddTrack(videoTrack)
	if err != nil {
		slog.Error("Failed to add video track",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
		)
		return "", "", err
	}

	if err := peerConnection.SetRemoteDescription(webrtc.SessionDescription{
		SDP:  offer,
		Type: webrtc.SDPTypeOffer,
	}); err != nil {
		slog.Error("Failed to set remote description",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
		)
		return "", "", err
	}

	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	answer, err := peerConnection.CreateAnswer(nil)

	if err != nil {
		slog.Error("Failed to create answer",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
		)
		return "", "", err
	} else if err = peerConnection.SetLocalDescription(answer); err != nil {
		slog.Error("Failed to set local description",
			slog.Any("err", err),
			slog.String("streamKey", profile.StreamKey),
		)
		return "", "", err
	}

	// TODO: Should this be before gatherComplete to assure registered events are triggered at correct time?
	if err := session.AddWHEP(
		whepSessionID,
		peerConnection,
		audioTrack,
		videoTrack,
		videoRTCPSender,
		func() {
			manager.SessionsManager.SendPLIByWHEPSessionID(whepSessionID)
		},
		profile.AllowDataChannelMessageSending,
	); err != nil {
		return "", "", err
	}

	<-gatherComplete
	slog.Info("WHEPSession.GatheringCompletePromise: Completed Gathering", slog.String("streamKey", profile.StreamKey))

	return utils.DebugOutputAnswer(utils.AppendCandidateToAnswer(peerConnection.LocalDescription().SDP)),
		whepSessionID,
		nil
}
