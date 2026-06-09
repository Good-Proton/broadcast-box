package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/server/helpers"
	"github.com/glimesh/broadcast-box/internal/webrtc/sessions/manager"
)

func statusHandler(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Add("Content-Type", "application/json")
	if !isStatusRequestAuthorized(request) {
		helpers.LogHTTPError(responseWriter, "Status authorization was invalid", http.StatusUnauthorized)
		return
	}

	streamKey := request.URL.Query().Get("key")

	if streamKey == "" {
		sessionStatusesHandler(responseWriter, request)
	} else {
		streamStatusHandler(responseWriter, request)
	}

}

func streamStatusHandler(responseWriter http.ResponseWriter, request *http.Request) {
	streamKey := request.URL.Query().Get("key")

	session, ok := manager.SessionsManager.GetSessionByID(streamKey)

	if !ok {
		slog.Info("Could not find active stream", "streamKey", streamKey)
		helpers.LogHTTPError(
			responseWriter,
			"No active stream found",
			http.StatusNotFound)

		return
	}

	statusResult := session.GetStreamStatus()

	if err := json.NewEncoder(responseWriter).Encode(statusResult); err != nil {
		helpers.LogHTTPError(
			responseWriter,
			"Internal Server Error",
			http.StatusInternalServerError)
		slog.Error("API.Status Error", "err", err)
	}

	responseWriter.Header().Add("Content-Type", "application/json")
}

func isStatusRequestAuthorized(request *http.Request) bool {
	statusAuthToken := environment.SanitizeValue(os.Getenv(environment.StatusAuthToken))
	if statusAuthToken == "" {
		return true
	}

	return helpers.ResolveBearerToken(request.Header.Get("Authorization")) == statusAuthToken
}

func sessionStatusesHandler(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method == "DELETE" {
		return
	}

	if isStatusDisabled() {
		helpers.LogHTTPError(
			responseWriter,
			"Status Service Unavailable",
			http.StatusServiceUnavailable)

		return
	}

	if err := json.NewEncoder(responseWriter).Encode(manager.SessionsManager.GetSessionStates(false)); err != nil {
		helpers.LogHTTPError(
			responseWriter,
			"Internal Server Error",
			http.StatusInternalServerError)

		slog.Error("Internal Server Error", "err", err)
	}

	responseWriter.Header().Add("Content-Type", "application/json")
}

func isStatusDisabled() bool {
	disableStatus := os.Getenv(environment.DisableStatus)
	if disableStatus == "" {
		return false
	}

	isDisabled, err := strconv.ParseBool(disableStatus)
	if err != nil {
		return true
	}

	return isDisabled
}
