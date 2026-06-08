package session

import (
	"log/slog"

	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/whep"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

func (s *Session) handleWHEPVideoRTCPSender(whepSession *whep.WHEPSession, rtcpSender *webrtc.RTPSender) {
	for {
		rtcpPackets, _, rtcpErr := rtcpSender.ReadRTCP()
		if rtcpErr != nil {
			slog.Error("WHEPSession.ReadRTCP.Error", "err", rtcpErr)
			return
		}

		for _, packet := range rtcpPackets {
			switch rtcpPacket := packet.(type) {
			case *rtcp.PictureLossIndication:
				whepSession.SendPLI()
			case *rtcp.ReceiverReport:
				for _, report := range rtcpPacket.Reports {
					whepSession.VideoJitter.Store(uint64(report.Jitter))
					whepSession.VideoDelay.Store(uint64(report.Delay))
					whepSession.VideoTotalLost.Store(uint64(report.TotalLost))
					whepSession.VideoLastSenderReport.Store(uint64(report.LastSenderReport))
				}
			}
		}
	}
}
