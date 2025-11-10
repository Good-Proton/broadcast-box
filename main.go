package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/glimesh/broadcast-box/internal/auth"
	"github.com/glimesh/broadcast-box/internal/config"
	"github.com/glimesh/broadcast-box/internal/logger"
	"github.com/glimesh/broadcast-box/internal/metrics"
	"github.com/glimesh/broadcast-box/internal/networktest"
	"github.com/glimesh/broadcast-box/internal/webrtc"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	envFileProd = ".env.production"
	envFileDev  = ".env.development"

	networkTestIntroMessage   = "\033[0;33mNETWORK_TEST_ON_START is enabled. If the test fails Broadcast Box will exit.\nSee the README for how to debug or disable NETWORK_TEST_ON_START\033[0m"
	networkTestSuccessMessage = "\033[0;32mNetwork Test passed.\nHave fun using Broadcast Box.\033[0m"
	networkTestFailedMessage  = "\033[0;31mNetwork Test failed.\n%s\nPlease see the README and join Discord for help\033[0m"
)

var (
	errNoBuildDirectoryErr = errors.New("\033[0;31mBuild directory does not exist, run `npm install` and `npm run build` in the web directory.\033[0m")
)

type (
	whepLayerRequestJSON struct {
		MediaId    string `json:"mediaId"`
		EncodingId string `json:"encodingId"`
	}

	httpSimpleResponse struct {
		Message string `json:"message"`
	}

	StreamInfoVerifier func(action string, r *http.Request) (*auth.StreamInfo, error)
)

func logHTTPError(w http.ResponseWriter, err error, code int) {
	logger.Error("HTTP error", zap.Error(err), zap.Int("status_code", code))
	http.Error(w, err.Error(), code)
}

func whipHandler(res http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		logHTTPError(res, errors.New("invalid request method"), http.StatusBadRequest)
		return
	}

	streamInfo, err := auth.GetStreamInfo("whip-connect", r)
	if err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}

	offer, err := io.ReadAll(r.Body)
	if err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}

	answer, err := webrtc.WHIP(string(offer), streamInfo)
	if err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}

	res.Header().Add("Location", "/api/whip")
	res.Header().Add("Content-Type", "application/sdp")
	res.WriteHeader(http.StatusCreated)
	if _, err = fmt.Fprint(res, answer); err != nil {
		logger.Error("Failed to write WHIP response", zap.Error(err))
	}
}

func whepHandlerFactory(streamInfoVerifier StreamInfoVerifier) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			logHTTPError(res, errors.New("invalid request method"), http.StatusBadRequest)
			return
		}

		streamInfo, err := streamInfoVerifier("whep-connect", req)
		if err != nil {
			logHTTPError(res, err, http.StatusBadRequest)
			return
		}

		offer, err := io.ReadAll(req.Body)
		if err != nil {
			logHTTPError(res, err, http.StatusBadRequest)
			return
		}

		answer, whepSessionId, err := webrtc.WHEP(string(offer), streamInfo)
		if err != nil {
			logHTTPError(res, err, http.StatusBadRequest)
			return
		}

		apiPath := req.Host + strings.TrimSuffix(req.URL.RequestURI(), "whep")
		res.Header().Add("Link", `<`+apiPath+"sse/"+whepSessionId+`>; rel="urn:ietf:params:whep:ext:core:server-sent-events"; events="layers"`)
		res.Header().Add("Link", `<`+apiPath+"layer/"+whepSessionId+`>; rel="urn:ietf:params:whep:ext:core:layer"`)
		res.Header().Add("Location", "/api/whep")
		res.Header().Add("Content-Type", "application/sdp")
		res.WriteHeader(http.StatusCreated)
		if _, err = fmt.Fprint(res, answer); err != nil {
			logger.Error("Failed to write WHEP response", zap.Error(err))
		}
	}
}

func whepHandler(res http.ResponseWriter, req *http.Request) {
	whepHandlerFactory(auth.GetStreamInfo)(res, req)
}

func whepServerSentEventsHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/event-stream")
	res.Header().Set("Cache-Control", "no-cache")
	res.Header().Set("Connection", "keep-alive")

	vals := strings.Split(req.URL.RequestURI(), "/")
	whepSessionId := vals[len(vals)-1]

	layers, err := webrtc.WHEPLayers(whepSessionId)
	if err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}

	if _, err = fmt.Fprintf(res, "event: layers\ndata: %s\n\n\n", string(layers)); err != nil {
		logger.Error("Failed to write SSE response", zap.Error(err))
	}
}

func whepLayerHandler(res http.ResponseWriter, req *http.Request) {
	var r whepLayerRequestJSON
	if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}

	vals := strings.Split(req.URL.RequestURI(), "/")
	whepSessionId := vals[len(vals)-1]

	if err := webrtc.WHEPChangeLayer(whepSessionId, r.EncodingId); err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
		return
	}
}

func statusHandler(res http.ResponseWriter, req *http.Request) {
	if os.Getenv("DISABLE_STATUS") == "true" {
		logHTTPError(res, errors.New("status Service Unavailable"), http.StatusServiceUnavailable)
		return
	}

	config, err := config.GetAppConfig()
	if err != nil {
		logHTTPError(res, err, http.StatusInternalServerError)
		return
	}
	if config.StatusAuthToken != "" {
		authHeader := req.Header.Get("Authorization")
		if authHeader != fmt.Sprintf("Bearer %s", config.StatusAuthToken) {
			logHTTPError(res, errors.New("unauthorized"), http.StatusUnauthorized)
			return
		}
	}

	res.Header().Add("Content-Type", "application/json")

	if err := json.NewEncoder(res).Encode(webrtc.GetStreamStatuses()); err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
	}
}

func indexHTMLWhenNotFound(fs http.FileSystem) http.Handler {
	fileServer := http.FileServer(fs)

	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		_, err := fs.Open(path.Clean(req.URL.Path)) // Do not allow path traversals.
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || strings.HasSuffix(err.Error(), "file name too long") {
				http.ServeFile(resp, req, "./web/build/index.html")
				return
			} else {
				logHTTPError(resp, err, http.StatusInternalServerError)
				return
			}
		}

		fileServer.ServeHTTP(resp, req)
	})
}

func healthCheckHandler(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(res).Encode(httpSimpleResponse{Message: "OK"}); err != nil {
		logHTTPError(res, err, http.StatusBadRequest)
	}
}

func metricsHandler(res http.ResponseWriter, req *http.Request) {
	config, err := config.GetAppConfig()
	if err != nil {
		logHTTPError(res, err, http.StatusInternalServerError)
		return
	}

	if config.StatusAuthToken != "" {
		authHeader := req.Header.Get("Authorization")
		if authHeader != fmt.Sprintf("Bearer %s", config.StatusAuthToken) {
			logHTTPError(res, errors.New("unauthorized"), http.StatusUnauthorized)
			return
		}
	}

	metrics.UpdateMetrics()
	promhttp.Handler().ServeHTTP(res, req)
}

func corsHandler(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Access-Control-Allow-Origin", "*")
		res.Header().Set("Access-Control-Allow-Methods", "*")
		res.Header().Set("Access-Control-Allow-Headers", "*")
		res.Header().Set("Access-Control-Expose-Headers", "*")

		if req.Method != http.MethodOptions {
			next(res, req)
		}
	}
}

func loadConfigs() error {
	if os.Getenv("APP_ENV") == "development" {
		logger.Info("Loading development config", zap.String("file", envFileDev))
		return godotenv.Load(envFileDev)
	} else {
		logger.Info("Loading production config", zap.String("file", envFileProd))
		if err := godotenv.Load(envFileProd); err != nil {
			return err
		}

		if _, err := os.Stat("./web/build"); os.IsNotExist(err) && os.Getenv("DISABLE_FRONTEND") != "true" {
			return errNoBuildDirectoryErr
		}

		return nil
	}
}

func main() {
	logger.MustInitialize()
	defer logger.Sync() // nolint:errcheck

	if err := loadConfigs(); err != nil {
		logger.Warn("Failed to find config in CWD, changing CWD to executable path")

		exePath, err := os.Executable()
		if err != nil {
			logger.Fatal("Failed to get executable path", zap.Error(err))
		}

		if err = os.Chdir(filepath.Dir(exePath)); err != nil {
			logger.Fatal("Failed to change working directory", zap.Error(err))
		}

		if err = loadConfigs(); err != nil {
			logger.Fatal("Failed to load configs", zap.Error(err))
		}
	}

	webrtc.Configure()
	_, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("Failed to load app config", zap.Error(err))
	}

	if os.Getenv("NETWORK_TEST_ON_START") == "true" {
		logger.Info(networkTestIntroMessage)

		go func() {
			time.Sleep(time.Second * 5)

			if networkTestErr := networktest.Run(whepHandlerFactory(
				func(action string, r *http.Request) (*auth.StreamInfo, error) {
					return &auth.StreamInfo{StreamKey: "networktest", LhUserId: ""}, nil
				},
			)); networkTestErr != nil {
				logger.Fatal(networkTestFailedMessage, zap.Error(networkTestErr))
			} else {
				logger.Info(networkTestSuccessMessage)
			}
		}()
	}

	httpsRedirectPort := "80"
	if val := os.Getenv("HTTPS_REDIRECT_PORT"); val != "" {
		httpsRedirectPort = val
	}

	if os.Getenv("HTTPS_REDIRECT_PORT") != "" || os.Getenv("ENABLE_HTTP_REDIRECT") != "" {
		go func() {
			redirectServer := &http.Server{
				Addr: ":" + httpsRedirectPort,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
				}),
			}

			logger.Info("Starting HTTP->HTTPS redirect server", zap.String("port", httpsRedirectPort))
			logger.Fatal("HTTPS redirect server failed", zap.Error(redirectServer.ListenAndServe()))
		}()
	}

	mux := http.NewServeMux()
	if os.Getenv("DISABLE_FRONTEND") != "true" {
		mux.Handle("/", indexHTMLWhenNotFound(http.Dir("./web/build")))
	}
	mux.HandleFunc("/api/whip", corsHandler(whipHandler))
	mux.HandleFunc("/api/whep", corsHandler(whepHandler))
	mux.HandleFunc("/api/sse/", corsHandler(whepServerSentEventsHandler))
	mux.HandleFunc("/api/layer/", corsHandler(whepLayerHandler))
	mux.HandleFunc("/api/status", corsHandler(statusHandler))
	mux.HandleFunc("/api/healthcheck", corsHandler(healthCheckHandler))
	mux.HandleFunc("/api/metrics", metricsHandler)

	server := &http.Server{
		Handler: mux,
		Addr:    os.Getenv("HTTP_ADDRESS"),
	}

	tlsKey := os.Getenv("SSL_KEY")
	tlsCert := os.Getenv("SSL_CERT")

	if tlsKey != "" && tlsCert != "" {
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{},
		}

		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			logger.Fatal("Failed to load TLS certificate", zap.Error(err))
		}

		server.TLSConfig.Certificates = append(server.TLSConfig.Certificates, cert)

		logger.Info("Starting HTTPS server", zap.String("address", os.Getenv("HTTP_ADDRESS")))
		logger.Fatal("HTTPS server failed", zap.Error(server.ListenAndServeTLS("", "")))
	} else {
		logger.Info("Starting HTTP server", zap.String("address", os.Getenv("HTTP_ADDRESS")))
		logger.Fatal("HTTP server failed", zap.Error(server.ListenAndServe()))
	}
}
