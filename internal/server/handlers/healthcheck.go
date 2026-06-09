package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func healthcheckHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	responseWriter.Header().Add("Content-Type", "application/json")
	responseWriter.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(responseWriter).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Error("Healthcheck response encode failed", slog.Any("err", err))
	}
}
