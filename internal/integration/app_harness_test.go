//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const httpListenerFDEnv = "BROADCAST_BOX_HTTP_LISTENER_FD"

type broadcastBoxProcess struct {
	baseURL string
	cancel  context.CancelFunc
	done    chan struct{}
	logs    *lockedBuffer
	process *os.Process

	mu      sync.Mutex
	waitErr error
}

func startBroadcastBox(t *testing.T) *broadcastBoxProcess {
	t.Helper()

	repoRoot := repositoryRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "broadcast-box")

	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build broadcast-box: %v\n%s", err, string(out))
	}

	httpListener, httpListenerFile := listenTCP(t)
	httpAddress := httpListener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Dir = repoRoot
	cmd.ExtraFiles = []*os.File{httpListenerFile}

	logs := &lockedBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = []string{
		"APP_ENV=development",
		"DISABLE_FRONTEND=true",
		"DISABLE_STATUS=false",
		httpListenerFDEnv + "=3",
		"HTTP_ADDRESS=" + httpAddress,
		"INCLUDE_LOOPBACK_CANDIDATE=true",
		"NETWORK_TYPES=udp4",
		"NETWORK_TEST_ON_START=false",
		"PUBLIC_IP_API_URL=",
		"JWT_PUBLIC_KEY=",
		"STATUS_AUTH_TOKEN=",
		"WEBHOOK_URL=",
		"SSL_KEY=",
		"SSL_CERT=",
		"ENABLE_HTTP_REDIRECT=",
		"HTTPS_REDIRECT_PORT=",
		"STUN_SERVERS=",
		"NAT_1_TO_1_IP=",
		"INCLUDE_PUBLIC_IP_IN_NAT_1_TO_1_IP=",
	}

	if err := cmd.Start(); err != nil {
		_ = httpListenerFile.Close()
		_ = httpListener.Close()
		cancel()
		t.Fatalf("start broadcast-box: %v", err)
	}
	_ = httpListenerFile.Close()
	_ = httpListener.Close()

	app := &broadcastBoxProcess{
		baseURL: "http://" + httpAddress,
		cancel:  cancel,
		done:    make(chan struct{}),
		logs:    logs,
		process: cmd.Process,
	}
	go func() {
		err := cmd.Wait()
		app.mu.Lock()
		app.waitErr = err
		app.mu.Unlock()
		close(app.done)
	}()

	t.Cleanup(func() {
		app.stop()
		if t.Failed() {
			t.Logf("broadcast-box logs:\n%s", app.logs.String())
		}
	})

	waitForHealth(t, app)
	return app
}

func waitForHealth(t *testing.T, app *broadcastBoxProcess) {
	t.Helper()

	client := http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	var lastErr string

	for time.Now().Before(deadline) {
		select {
		case <-app.done:
			t.Fatalf("broadcast-box exited before healthcheck passed: %v\n%s", app.err(), app.logs.String())
		default:
		}

		resp, err := client.Get(app.baseURL + "/api/healthcheck")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Sprintf("status=%d", resp.StatusCode)
		} else {
			lastErr = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("broadcast-box healthcheck did not pass: %s\n%s", lastErr, app.logs.String())
}

func (app *broadcastBoxProcess) stop() {
	app.cancel()
	select {
	case <-app.done:
		return
	case <-time.After(5 * time.Second):
		if app.process != nil {
			_ = app.process.Kill()
		}
		<-app.done
	}
}

func (app *broadcastBoxProcess) err() error {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.waitErr
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve integration test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func listenTCP(t *testing.T) (*net.TCPListener, *os.File) {
	t.Helper()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on TCP port: %v", err)
	}

	file, err := listener.File()
	if err != nil {
		_ = listener.Close()
		t.Fatalf("create TCP listener file: %v", err)
	}

	return listener, file
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
