//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type broadcastBoxProcess struct {
	baseURL string
	cancel  context.CancelFunc
	done    chan struct{}
	logs    *lockedBuffer
	process *os.Process
	jwtKey  *ecdsa.PrivateKey

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

	httpPort := freeTCPPort(t)
	udpMuxPort := freeUDPPort(t)
	jwtKey, jwtPublicKeyPEM := testJWTKey(t)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Dir = repoRoot

	logs := &lockedBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = []string{
		"APP_ENV=development",
		"DISABLE_FRONTEND=true",
		"DISABLE_STATUS=false",
		"HTTP_ADDRESS=127.0.0.1:" + fmt.Sprint(httpPort),
		"INCLUDE_LOOPBACK_CANDIDATE=true",
		"NETWORK_TYPES=udp4",
		"NETWORK_TEST_ON_START=false",
		"PUBLIC_IP_API_URL=",
		"JWT_PUBLIC_KEY=" + jwtPublicKeyPEM,
		"NAT_1_TO_1_IP=127.0.0.1",
		"STATUS_AUTH_TOKEN=",
		"SSL_KEY=",
		"SSL_CERT=",
		"ENABLE_HTTP_REDIRECT=",
		"HTTPS_REDIRECT_PORT=",
		"STUN_SERVERS=",
		"INCLUDE_PUBLIC_IP_IN_NAT_1_TO_1_IP=",
		"UDP_MUX_PORT=" + fmt.Sprint(udpMuxPort),
	}

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start broadcast-box: %v", err)
	}

	app := &broadcastBoxProcess{
		baseURL: "http://127.0.0.1:" + fmt.Sprint(httpPort),
		cancel:  cancel,
		done:    make(chan struct{}),
		logs:    logs,
		process: cmd.Process,
		jwtKey:  jwtKey,
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

func testJWTKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test JWT key: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal test JWT public key: %v", err)
	}

	publicKeyPEM := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})), "\n", "\\n")

	return privateKey, publicKeyPEM
}

func (app *broadcastBoxProcess) token(t *testing.T, sessionID string, accessType string, whepAccessType string) string {
	t.Helper()

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, struct {
		SessionId      string `json:"sessionId"`
		LhUserId       string `json:"lhUserId"`
		AccessType     string `json:"accessType"`
		WHEPAccessType string `json:"whepAccessType"`
		WorkerIp       string `json:"workerIp"`
		jwt.RegisteredClaims
	}{
		SessionId:      sessionID,
		LhUserId:       "integration-user",
		AccessType:     accessType,
		WHEPAccessType: whepAccessType,
		WorkerIp:       "127.0.0.1",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	})

	signedToken, err := token.SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign integration JWT: %v", err)
	}
	return signedToken
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

func freeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate TCP port: %v", err)
	}
	defer listener.Close() // nolint:errcheck

	return listener.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate UDP port: %v", err)
	}
	defer conn.Close() // nolint:errcheck

	return conn.LocalAddr().(*net.UDPAddr).Port
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
