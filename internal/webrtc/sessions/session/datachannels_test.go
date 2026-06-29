package session

import (
	"errors"
	"testing"

	"github.com/glimesh/broadcast-box/internal/webrtc/datadc"
	"github.com/stretchr/testify/assert"
)

func TestDataChannelBroadcast(t *testing.T) {
	s := &Session{
		StreamKey:        "stream-1",
		DataChannelPeers: map[string]*datadc.Peer{},
	}

	// Register peers
	senderChannel := &fakeDataChannel{}
	recipientChannel := &fakeDataChannel{}
	failingRecipientChannel := &fakeDataChannel{sendTextError: errors.New("send failed")}
	otherStreamChannel := &fakeDataChannel{}

	sender := s.AddDataChannelPeer("sender", senderChannel, true)
	recipient := s.AddDataChannelPeer("recipient", recipientChannel, true)
	failingRecipient := s.AddDataChannelPeer("failing-recipient", failingRecipientChannel, true)
	(&Session{
		StreamKey:        "stream-2",
		DataChannelPeers: map[string]*datadc.Peer{},
	}).AddDataChannelPeer("other-stream", otherStreamChannel, true)

	// Text broadcasts
	s.BroadcastDataChannelFrom(sender, []byte("hello"), true)
	assert.Empty(t, senderChannel.textMessages)
	assert.Empty(t, senderChannel.binaryMessages)
	assert.Equal(t, []string{"hello"}, recipientChannel.textMessages)
	assert.Empty(t, recipientChannel.binaryMessages)
	assert.Empty(t, otherStreamChannel.textMessages)
	assert.Empty(t, otherStreamChannel.binaryMessages)

	// Binary broadcasts
	s.BroadcastDataChannelFrom(sender, []byte{0x01, 0x02, 0x03}, false)
	assert.Equal(t, [][]byte{{0x01, 0x02, 0x03}}, recipientChannel.binaryMessages)
	assert.Equal(t, []string{"hello"}, recipientChannel.textMessages)

	// Send failures
	assert.True(t, s.isDataChannelPeerRegistered(failingRecipient))
	s.BroadcastDataChannelFrom(failingRecipient, []byte("still active"), true)
	assert.True(t, s.isDataChannelPeerRegistered(failingRecipient))
	assert.Equal(t, []string{"hello", "still active"}, recipientChannel.textMessages)

	// Unregister a peer
	s.RemoveDataChannelPeer(recipient)
	s.BroadcastDataChannelFrom(sender, []byte("after unregister"), true)
	assert.Equal(t, []string{"hello", "still active"}, recipientChannel.textMessages)

	// Replace a peer
	oldChannel := &fakeDataChannel{}
	newChannel := &fakeDataChannel{}
	oldPeer := s.AddDataChannelPeer("duplicate", oldChannel, true)
	newPeer := s.AddDataChannelPeer("duplicate", newChannel, true)

	s.RemoveDataChannelPeer(oldPeer)
	assert.True(t, s.isDataChannelPeerRegistered(newPeer))
	s.BroadcastDataChannelFrom(sender, []byte("replacement"), true)
	assert.Empty(t, oldChannel.textMessages)
	assert.Equal(t, []string{"replacement"}, newChannel.textMessages)
}

func TestDataChannelBroadcastReceiveOnlyPeer(t *testing.T) {
	s := &Session{
		StreamKey:        "stream-1",
		DataChannelPeers: map[string]*datadc.Peer{},
	}

	viewerChannel := &fakeDataChannel{}
	editorChannel := &fakeDataChannel{}
	recipientChannel := &fakeDataChannel{}

	viewer := s.AddDataChannelPeer("viewer", viewerChannel, false)
	editor := s.AddDataChannelPeer("editor", editorChannel, true)
	s.AddDataChannelPeer("recipient", recipientChannel, true)

	s.BroadcastDataChannelFrom(viewer, []byte("blocked"), true)
	assert.Empty(t, recipientChannel.textMessages)
	assert.Empty(t, editorChannel.textMessages)
	assert.Equal(t, uint64(0), s.DataChannelMessagesReceived.Load())
	assert.Equal(t, uint64(0), s.DataChannelBytesReceived.Load())

	s.BroadcastDataChannelFrom(editor, []byte("allowed"), true)
	assert.Equal(t, []string{"allowed"}, recipientChannel.textMessages)
	assert.Equal(t, []string{"allowed"}, viewerChannel.textMessages)
	assert.Equal(t, uint64(1), s.DataChannelMessagesReceived.Load())
	assert.Equal(t, uint64(len("allowed")), s.DataChannelBytesReceived.Load())
	assert.Equal(t, uint64(len("allowed")*2), s.DataChannelBytesSent.Load())
}

func (s *Session) isDataChannelPeerRegistered(peer *datadc.Peer) bool {
	s.DataChannelPeersLock.RLock()
	defer s.DataChannelPeersLock.RUnlock()
	return s.DataChannelPeers[peer.ID()] == peer
}

type fakeDataChannel struct {
	textMessages   []string
	binaryMessages [][]byte
	sendTextError  error
	sendError      error
}

func (f *fakeDataChannel) Send(data []byte) error {
	if f.sendError != nil {
		return f.sendError
	}

	f.binaryMessages = append(f.binaryMessages, append([]byte(nil), data...))
	return nil
}

func (f *fakeDataChannel) SendText(s string) error {
	if f.sendTextError != nil {
		return f.sendTextError
	}

	f.textMessages = append(f.textMessages, s)
	return nil
}
