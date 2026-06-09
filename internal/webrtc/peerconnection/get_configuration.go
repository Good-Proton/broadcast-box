package peerconnection

import (
	"os"
	"strings"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/pion/webrtc/v4"
)

func getPeerConnectionConfig() webrtc.Configuration {
	config := webrtc.Configuration{}
	if stunServers := os.Getenv(environment.STUNServers); stunServers != "" {
		for stunServer := range strings.SplitSeq(stunServers, "|") {
			config.ICEServers = append(config.ICEServers, webrtc.ICEServer{
				URLs: []string{"stun:" + stunServer},
			})
		}
	}

	return config
}
