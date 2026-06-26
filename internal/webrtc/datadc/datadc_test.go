package datadc

import (
	"errors"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestBindDeniedRawDataChannelClosesWithoutRegisteringPeer(t *testing.T) {
	store := &fakePeerStore{}
	channel := &fakeChannel{label: DataChannelLabel}

	Bind("stream-1", store, "viewer", channel, false)

	if !channel.closed {
		t.Fatal("expected denied raw data channel to close")
	}

	if channel.onOpen != nil || channel.onMessage != nil || channel.onClose != nil || channel.onError != nil {
		t.Fatal("expected denied raw data channel to have no handlers")
	}

	if len(store.added) != 0 {
		t.Fatalf("registered peers = %d, want 0", len(store.added))
	}
}

func TestBindAllowedRawDataChannelRegistersAndBroadcasts(t *testing.T) {
	store := &fakePeerStore{}
	channel := &fakeChannel{label: DataChannelLabel}

	Bind("stream-1", store, "editor", channel, true)

	if channel.closed {
		t.Fatal("expected allowed raw data channel to stay open")
	}

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

func (f *fakePeerStore) AddDataChannelPeer(peerID string, channel Sender) *Peer {
	peer := NewPeer(peerID, channel)
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

	closed       bool
	closeErr     error
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

func (f *fakeChannel) Close() error {
	f.closed = true
	if f.closeErr != nil {
		return f.closeErr
	}
	return nil
}

func (f *fakeChannel) Send(data []byte) error {
	if f.closed {
		return errors.New("channel closed")
	}
	f.dataMessages = append(f.dataMessages, append([]byte(nil), data...))
	return nil
}

func (f *fakeChannel) SendText(s string) error {
	if f.closed {
		return errors.New("channel closed")
	}
	f.textMessages = append(f.textMessages, s)
	return nil
}
