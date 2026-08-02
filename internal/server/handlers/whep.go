package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strings"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/server/authorization"
	"github.com/glimesh/broadcast-box/internal/server/helpers"
	"github.com/glimesh/broadcast-box/internal/server/webhook"
	"github.com/glimesh/broadcast-box/internal/webrtc"
	"github.com/glimesh/broadcast-box/internal/webrtc/utils"
)

func whepHandler(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost && request.Method != http.MethodPatch {
		helpers.LogHTTPError(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	offer, err := io.ReadAll(request.Body)
	if err != nil || string(offer) == "" {
		helpers.LogHTTPError(responseWriter, "error reading offer", http.StatusBadRequest)
		return
	}

	if request.Method == http.MethodPatch {
		if err := utils.ValidateOffer(string(offer)); err != nil {
			helpers.LogHTTPError(responseWriter, "invalid offer: "+err.Error(), http.StatusBadRequest)
			return
		}

		path := strings.Replace(request.URL.Path, "/api/whep", "", 1)
		segments := strings.Split(path, "/")
		sessionID := strings.TrimSpace(segments[len(segments)-1])

		if sessionID == "" {
			slog.Info("API.WHEP.Patch Error: Missing session id")
			helpers.LogHTTPError(responseWriter, "Missing session id", http.StatusBadRequest)
			return
		}

		slog.Info("API.WHEP.Patch: Patching session", "sessionID", sessionID)
		if err := patchHandler(responseWriter, request, sessionID, string(offer)); err != nil {
			slog.Error("API.WHEP.Patch Error", "err", err)
			helpers.LogHTTPError(responseWriter, err.Error(), http.StatusBadRequest)
		}

		return
	}

	authInfo, err := authorization.AuthenticateStreamRequest(request, authorization.WHEPConnect)
	if err != nil {
		helpers.LogHTTPError(responseWriter, "Authorization was invalid", http.StatusUnauthorized)
		return
	}

	streamKey := authInfo.StreamKey
	if webhookURL := os.Getenv(environment.WebhookURL); webhookURL != "" {
		streamKey, err = webhook.CallWebhook(webhookURL, webhook.WHEPConnect, streamKey, request)
		if err != nil {
			responseWriter.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	whipAnswer, sessionID, err := webrtc.WHEP(string(offer), authorization.PublicProfile{
		StreamKey:                      streamKey,
		LhUserId:                       authInfo.LhUserId,
		AllowDataChannelMessageSending: authInfo.AllowWHEPDataChannelMessageSending(),
	})
	if err != nil {
		slog.Error("API.WHEP: Setup Error", "err", err)
		helpers.LogHTTPError(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	responseWriter.Header().Add("Link", `<`+"/api/sse/"+sessionID+`>; rel="urn:ietf:params:whep:ext:core:server-sent-events"; events="layers"`)
	responseWriter.Header().Add("Link", `<`+"/api/layer/"+sessionID+`>; rel="urn:ietf:params:whep:ext:core:layer"`)

	responseWriter.Header().Add("Location", "/api/whep/"+sessionID)
	responseWriter.Header().Add("Content-Type", "application/sdp")
	responseWriter.WriteHeader(http.StatusCreated)

	if _, err = fmt.Fprint(responseWriter, whipAnswer); err != nil {
		slog.Error("API.WHEP Error", "err", err)
	} else {
		slog.Info("API.WHEP Completed")
	}
}

func patchHandler(res http.ResponseWriter, r *http.Request, sessionID, body string) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/trickle-ice-sdpfrag" {
		helpers.LogHTTPError(res, "invalid content type", http.StatusUnsupportedMediaType)
		return err
	}

	if err = webrtc.HandleWHEPPatch(sessionID, body); err != nil {
		return err
	}

	res.WriteHeader(http.StatusNoContent)

	return nil
}
