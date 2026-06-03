package webrtc

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
)

func TestGetStreamStatusesLocksDataChannelMaps(t *testing.T) {
	Configure()

	streamInfo := &auth.StreamInfo{
		StreamKey: "status-data-channel-race",
		LhUserId:  "",
	}

	streamMapLock.Lock()
	testStream, err := getStream(streamInfo, "")
	streamMapLock.Unlock()
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}

			label := fmt.Sprintf("channel-%d", i%8)
			testStream.dataChannelsLock.Lock()
			testStream.publisherDataChannels[label] = nil
			delete(testStream.publisherDataChannels, label)
			testStream.dataChannelsLock.Unlock()
		}
	}()

	go func() {
		defer wg.Done()

		deadline := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(deadline) {
			_ = GetStreamStatuses()
		}
		close(done)
	}()

	wg.Wait()
}
