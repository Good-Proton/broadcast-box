package ip

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/glimesh/broadcast-box/internal/environment"
)

const defaultPublicIpApiUrl = "http://ip-api.com/json/"

func GetPublicIP() string {
	publicIP, err := ResolvePublicIP()
	if err != nil {
		slog.Error("Failed to get Public IP", "err", err)
		os.Exit(1)
	}

	return publicIP
}

func ResolvePublicIP() (string, error) {
	apiURL := os.Getenv(environment.PublicIpApiUrl)
	if apiURL == "" {
		apiURL = defaultPublicIpApiUrl
	}

	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("public IP request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("public IP request returned status %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("public IP response read failed: %w", err)
	}

	var payload struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if publicIP := normalizeIP(payload.Query); publicIP != "" {
			return publicIP, nil
		}
	}

	if publicIP := normalizeIP(string(body)); publicIP != "" {
		return publicIP, nil
	}

	return "", fmt.Errorf("public IP response did not contain a valid IP")
}

func ResolveAdvertisedIPs() ([]string, error) {
	if configured := strings.TrimSpace(os.Getenv(environment.NAT1To1IP)); configured != "" {
		addresses := make([]string, 0)
		for _, value := range strings.Split(configured, "|") {
			address := normalizeIP(value)
			if address == "" {
				return nil, fmt.Errorf("NAT_1_TO_1_IP contains an invalid address")
			}
			addresses = append(addresses, address)
		}
		return addresses, nil
	}

	if os.Getenv(environment.IncludePublicIPInNAT1To1IP) == "" &&
		os.Getenv(environment.PublicIpApiUrl) == "" {
		return nil, fmt.Errorf("no advertised public IP source is configured")
	}

	publicIP, err := ResolvePublicIP()
	if err != nil {
		return nil, err
	}

	return []string{publicIP}, nil
}

func normalizeIP(value string) string {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return ""
	}

	return parsed.String()
}
