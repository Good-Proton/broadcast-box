package datadc

import (
	"log/slog"
	"sync"

	"github.com/pion/webrtc/v4"
)

const DataChannelLabel = "bb-data-v1"

type PeerStore interface {
	AddDataChannelPeer(peerID string, channel Sender, allowSending bool) *Peer
	RemoveDataChannelPeer(peer *Peer)
	BroadcastDataChannelFrom(sender *Peer, payload []byte, isString bool)
}

type Sender interface {
	Send(data []byte) error
	SendText(s string) error
}

type Channel interface {
	Sender
	Label() string
	OnOpen(func())
	OnMessage(func(webrtc.DataChannelMessage))
	OnClose(func())
	OnError(func(error))
}

type Peer struct {
	peerID       string
	channel      Sender
	allowSending bool

	writeLock sync.Mutex
}

func NewPeer(peerID string, channel Sender, allowSending bool) *Peer {
	return &Peer{peerID: peerID, channel: channel, allowSending: allowSending}
}

func (p *Peer) ID() string {
	return p.peerID
}

func (p *Peer) MessageSendingAllowed() bool {
	return p.allowSending
}

func Bind(streamKey string, peers PeerStore, peerID string, dataChannel Channel, allowSending bool) {
	if dataChannel.Label() != DataChannelLabel {
		return
	}

	if peers == nil {
		slog.Info("DataDC.Bind: peer store not configured")
		return
	}

	var (
		peer     *Peer
		peerLock sync.Mutex
		isClosed bool
	)

	register := func() *Peer {
		peerLock.Lock()
		defer peerLock.Unlock()
		if isClosed {
			return nil
		}

		if peer == nil {
			peer = peers.AddDataChannelPeer(peerID, dataChannel, allowSending)
		}
		return peer
	}

	closePeer := func() (*Peer, bool) {
		peerLock.Lock()
		defer peerLock.Unlock()
		if isClosed {
			return nil, false
		}

		isClosed = true
		return peer, true
	}

	dataChannel.OnOpen(func() {
		slog.Info("DataDC.Bind: open", "streamKey", streamKey, "peerID", peerID)
		register()
	})
	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		peer := register()
		if peer == nil || !peer.MessageSendingAllowed() {
			return
		}

		peers.BroadcastDataChannelFrom(peer, msg.Data, msg.IsString)
	})
	dataChannel.OnClose(func() {
		slog.Info("DataDC.Bind: closed", "streamKey", streamKey, "peerID", peerID)
		peer, _ := closePeer()
		peers.RemoveDataChannelPeer(peer)
	})
	dataChannel.OnError(func(err error) {
		peer, didClose := closePeer()
		if didClose {
			slog.Error("DataDC.Bind: error", "streamKey", streamKey, "peerID", peerID, "err", err)
			peers.RemoveDataChannelPeer(peer)
		}
	})
}

func (p *Peer) Send(payload []byte, isString bool) error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()

	if isString {
		return p.channel.SendText(string(payload))
	}

	return p.channel.Send(payload)
}
