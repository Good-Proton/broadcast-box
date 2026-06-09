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
	"go.uber.org/zap"
)

func WHEP(offer string, profile authorization.PublicProfile) (string, string, error) {
	utils.DebugOutputOffer(offer)

	session, err := manager.SessionsManager.GetOrAddSession(profile, false)
	if err != nil {
		logger.Error("Failed to get stream for WHEP",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
			zap.String("lhUserId", streamInfo.LhUserId),
		)
		return "", "", err
	}

	whepSessionID := uuid.New().String()

	peerConnection, err := peerconnection.CreateWHEPPeerConnection()
	if err != nil {
		logger.Error("Failed to create peer connection",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
			zap.String("lhUserId", streamInfo.LhUserId),
			zap.String("whepSessionId", whepSessionId),
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
		logger.Error("Failed to add video track",
			zap.Error(err),
			zap.String("streamKey", streamInfo.StreamKey),
		)
		return "", "", err
	}

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
	); err != nil {
		return "", "", err
	}

	<-gatherComplete
	slog.Info("WHEPSession.GatheringCompletePromise: Completed Gathering", slog.String("streamKey", profile.StreamKey))

	return utils.DebugOutputAnswer(utils.AppendCandidateToAnswer(peerConnection.LocalDescription().SDP)),
		whepSessionID,
		nil
}
