package server

import (
	"os"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/server/handlers"
)

// HTTP Setup
func StartWebServer() {
	setupHTTPRedirect()

	serverMux := handlers.GetServeMuxHandler()

	if os.Getenv(environment.SSLKey) != "" && os.Getenv(environment.SSLCert) != "" {
		startHTTPSServer(serverMux)
	} else {
		startHTTPServer(serverMux)
	}
}
