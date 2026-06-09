package environment

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestGetSlogHandlerJSONMode(t *testing.T) {
	t.Setenv(loggingMode, loggingModeJSON)

	var output bytes.Buffer
	logger := slog.New(getSlogHandler(&output, slog.LevelInfo))
	logger.Info("hello", slog.String("key", "value"))

	var logEntry map[string]any
	if err := json.Unmarshal(output.Bytes(), &logEntry); err != nil {
		t.Fatalf("expected json log entry: %v", err)
	}

	if logEntry["msg"] != "hello" {
		t.Fatalf("msg = %v, want %q", logEntry["msg"], "hello")
	}

	if logEntry["key"] != "value" {
		t.Fatalf("key = %v, want %q", logEntry["key"], "value")
	}
}
