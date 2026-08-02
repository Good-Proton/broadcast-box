package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/glimesh/broadcast-box/internal/server/authorization"
)

const defaultTimeout = time.Second * 5

type webhookPayload struct {
	Action           Action            `json:"action"`
	IP               string            `json:"ip"`
	BearerToken      string            `json:"bearerToken"`
	QueryParams      map[string]string `json:"queryParams"`
	UserAgent        string            `json:"userAgent"`
	AdvertiseAddress string            `json:"advertiseAddress,omitempty"`
}

type webhookResponse struct {
	StreamKey string `json:"streamKey"`
}

type Action = authorization.Action

const (
	WHIPConnect = authorization.WHIPConnect
	WHEPConnect = authorization.WHEPConnect
)

func CallWebhook(url string, action Action, bearerToken string, request *http.Request) (string, error) {
	start := time.Now()

	queryParams := make(map[string]string)
	for k, v := range request.URL.Query() {
		if len(v) > 0 {
			queryParams[k] = v[0]
		}
	}

	payload, err := json.Marshal(webhookPayload{
		Action:           action,
		IP:               getIPAddress(request),
		BearerToken:      bearerToken,
		QueryParams:      queryParams,
		UserAgent:        request.UserAgent(),
		AdvertiseAddress: authorization.AdvertisedAddress(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	webhookRequest, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	webhookRequest.Header.Set("Content-Type", "application/json")

	client := http.Client{Timeout: defaultTimeout}
	response, err := client.Do(webhookRequest)
	if err != nil {
		return "", fmt.Errorf("webhook request failed after %v: %w", time.Since(start), err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.Error("webhook response body close failed", "err", err)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("webhook returned non-200 status: %d", response.StatusCode)
	}

	var result webhookResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode webhook response: %w", err)
	}

	return result.StreamKey, nil
}

func getIPAddress(request *http.Request) string {
	if forwardedFor := request.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		return forwardedFor
	}

	return request.RemoteAddr
}
