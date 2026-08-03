package main

import (
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/glimesh/broadcast-box/internal/chat"
	"github.com/glimesh/broadcast-box/internal/console"
	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/networktest"
	"github.com/glimesh/broadcast-box/internal/server"
	"github.com/glimesh/broadcast-box/internal/server/authorization"
	"github.com/glimesh/broadcast-box/internal/webrtc"

	"net/http"
	_ "net/http/pprof"
)

func main() {
	environment.SetupLogger()
	environment.LoadEnvironmentVariables()
	console.HandleConsoleFlags()
	if authorization.IsJwtEnabled() {
		if err := authorization.Initialize(); err != nil {
			slog.Error("Authorization startup failed", "err", err)
			os.Exit(1)
		}
	}

	if shouldProfileApplication := os.Getenv(environment.EnableProfiling); strings.EqualFold(shouldProfileApplication, "true") {
		go func() {
			runtime.SetBlockProfileRate(1)
			runtime.SetMutexProfileFraction(1)
			slog.Error("pprof server exited", "err", http.ListenAndServe("localhost:6060", nil))
		}()
	}

	slog.Info("Booting up Broadcast Box")

	chatManager := chat.NewManager()
	webrtc.Setup(chatManager)

	if shouldNetworkTest := os.Getenv(environment.NetworkTestOnStart); strings.EqualFold(shouldNetworkTest, "true") {
		networktest.RunNetworkTest()
	}

	server.StartWebServer()
}
