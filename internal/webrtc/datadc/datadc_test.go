package datadc

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestBindReceiveOnlyRawDataChannelRegistersWithoutBroadcasting(t *testing.T) {
	store := &fakePeerStore{}
	channel := &fakeChannel{label: DataChannelLabel}

	Bind("stream-1", store, "viewer", channel, false)

	if channel.onOpen == nil {
		t.Fatal("expected open handler")
	}
	if channel.onMessage == nil {
		t.Fatal("expected message handler")
	}

	channel.onOpen()
	if len(store.added) != 1 {
		t.Fatalf("registered peers = %d, want 1", len(store.added))
	}

	if store.added[0].MessageSendingAllowed() {
		t.Fatal("expected receive-only peer to deny sending")
	}

	channel.onMessage(webrtc.DataChannelMessage{Data: []byte("blocked"), IsString: true})
	if len(store.broadcasts) != 0 {
		t.Fatalf("broadcasts = %d, want 0", len(store.broadcasts))
	}
}

func TestBindAllowedRawDataChannelRegistersAndBroadcasts(t *testing.T) {
	store := &fakePeerStore{}
	channel := &fakeChannel{label: DataChannelLabel}

	Bind("stream-1", store, "editor", channel, true)

	if channel.onOpen == nil {
		t.Fatal("expected open handler")
	}
	if channel.onMessage == nil {
		t.Fatal("expected message handler")
	}

	channel.onOpen()
	if len(store.added) != 1 {
		t.Fatalf("registered peers = %d, want 1", len(store.added))
	}
	if store.added[0].ID() != "editor" {
		t.Fatalf("registered peer id = %q, want %q", store.added[0].ID(), "editor")
	}

	channel.onMessage(webrtc.DataChannelMessage{Data: []byte("hello"), IsString: true})
	if len(store.broadcasts) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(store.broadcasts))
	}
	if store.broadcasts[0].sender != store.added[0] {
		t.Fatal("broadcast sender did not use registered peer")
	}
}

type fakePeerStore struct {
	added      []*Peer
	removed    []*Peer
	broadcasts []fakeBroadcast
}

func (f *fakePeerStore) AddDataChannelPeer(peerID string, channel Sender, allowSending bool) *Peer {
	peer := NewPeer(peerID, channel, allowSending)
	f.added = append(f.added, peer)
	return peer
}

func (f *fakePeerStore) RemoveDataChannelPeer(peer *Peer) {
	f.removed = append(f.removed, peer)
}

func (f *fakePeerStore) BroadcastDataChannelFrom(sender *Peer, payload []byte, isString bool) {
	f.broadcasts = append(f.broadcasts, fakeBroadcast{
		sender:   sender,
		payload:  append([]byte(nil), payload...),
		isString: isString,
	})
}

type fakeBroadcast struct {
	sender   *Peer
	payload  []byte
	isString bool
}

type fakeChannel struct {
	label string

	onOpen    func()
	onMessage func(webrtc.DataChannelMessage)
	onClose   func()
	onError   func(error)

	textMessages []string
	dataMessages [][]byte
}

func (f *fakeChannel) Label() string {
	return f.label
}

func (f *fakeChannel) OnOpen(handler func()) {
	f.onOpen = handler
}

func (f *fakeChannel) OnMessage(handler func(webrtc.DataChannelMessage)) {
	f.onMessage = handler
}

func (f *fakeChannel) OnClose(handler func()) {
	f.onClose = handler
}

func (f *fakeChannel) OnError(handler func(error)) {
	f.onError = handler
}

func (f *fakeChannel) Send(data []byte) error {
	f.dataMessages = append(f.dataMessages, append([]byte(nil), data...))
	return nil
}

func (f *fakeChannel) SendText(s string) error {
	f.textMessages = append(f.textMessages, s)
	return nil
}
