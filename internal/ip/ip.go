package ip

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/glimesh/broadcast-box/internal/environment"
)

const defaultPublicIpApiUrl = "http://ip-api.com/json/"

func GetPublicIP() string {
	apiUrl := os.Getenv(environment.PublicIpApiUrl)
	if apiUrl == "" {
		apiUrl = defaultPublicIpApiUrl
	}

	req, err := http.Get(apiUrl)

	if err != nil {
		slog.Error("Failed to get Public IP", "err", err)
		os.Exit(1)
	}

	defer func() {
		if closeErr := req.Body.Close(); closeErr != nil {
			slog.Error("Failed to get Public IP", "err", closeErr)
			os.Exit(1)
		}
	}()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		slog.Error("Failed to get Public IP", "err", err)
		os.Exit(1)
	}

	ip := struct {
		Query string
	}{}

	if err = json.Unmarshal(body, &ip); err != nil {
		plainIp := strings.TrimSpace(string(body))
		if net.ParseIP(plainIp) != nil {
			return plainIp
		}

		slog.Error("Failed to get Public IP", "err", err)
		os.Exit(1)
	}

	if ip.Query == "" {
		slog.Error("Failed to get Public IP", "err", "Query entry was not populated")
		os.Exit(1)
	}

	return ip.Query
}
