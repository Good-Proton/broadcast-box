package handlers

import (
	"net/http"

	"github.com/glimesh/broadcast-box/internal/metrics"
	"github.com/glimesh/broadcast-box/internal/server/helpers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func metricsHandler(responseWriter http.ResponseWriter, request *http.Request) {
	if !isStatusRequestAuthorized(request) {
		helpers.LogHTTPError(responseWriter, "Metrics authorization was invalid", http.StatusUnauthorized)
		return
	}

	metrics.UpdateMetrics()
	promhttp.Handler().ServeHTTP(responseWriter, request)
}
