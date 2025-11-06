package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/glimesh/broadcast-box/internal/env"
	"github.com/glimesh/broadcast-box/internal/logger"
	"go.uber.org/zap"
)

type appConfig struct {
	PublicIp     string
	JwtPublicKey string
}

var (
	appCfg *appConfig
)

func GetAppConfig() (*appConfig, error) {
	if appCfg != nil {
		return appCfg, nil
	}

	return nil, errors.New("app config not loaded")
}

func LoadConfig() (*appConfig, error) {
	publicIp, err := findPublicIp()
	if err != nil {
		logger.Warn("Failed to load public IP", zap.Error(err))
	} else {
		logger.Info("Public IP found", zap.String("ip", publicIp))
	}

	jwtPublicKey := env.Sanitize(os.Getenv("JWT_PUBLIC_KEY"))
	if jwtPublicKey == "" {
		logger.Info("JWT public key not set in environment variables; JWT authentication will be disabled")
	} else {
		logger.Info("JWT public key loaded from environment variables; JWT authentication enabled")
	}

	appCfg = &appConfig{
		PublicIp:     publicIp,
		JwtPublicKey: jwtPublicKey,
	}

	return appCfg, nil
}

func IsJwtEnabled() bool {
	cfg, err := GetAppConfig()
	if err != nil {
		logger.Error("Cannot get app config", zap.Error(err))
		return false
	}

	return cfg.JwtPublicKey != ""
}

func findPublicIp() (publicIp string, err error) {
	ipApiUrl := os.Getenv("PUBLIC_IP_API_URL")
	if ipApiUrl == "" {
		return "", errors.New("PUBLIC_IP_API_URL environment variable is not set")
	}

	resp, err := http.Get(ipApiUrl)
	if err != nil {
		return "", fmt.Errorf("failed to get public IP: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("public IP API returned non-200 status: %d", resp.StatusCode)
	}

	var ipResponse string
	if _, err := fmt.Fscan(resp.Body, &ipResponse); err != nil {
		return "", fmt.Errorf("failed to read public IP API response: %w", err)
	}

	return ipResponse, nil
}
