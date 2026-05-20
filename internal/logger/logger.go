package logger

import (
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	instance *zap.Logger
	once     sync.Once
)

func getLogger() *zap.Logger {
	if instance == nil {
		_ = Initialize()
	}

	if instance == nil {
		return zap.NewNop()
	}

	return instance
}

func Debug(message string, fields ...zap.Field) {
	getLogger().Debug(message, fields...)
}

func Info(message string, fields ...zap.Field) {
	getLogger().Info(message, fields...)
}

func Warn(message string, fields ...zap.Field) {
	getLogger().Warn(message, fields...)
}

func Error(message string, fields ...zap.Field) {
	getLogger().Error(message, fields...)
}

func Fatal(message string, fields ...zap.Field) {
	getLogger().Fatal(message, fields...)
}

func Sync() error {
	if instance != nil {
		return instance.Sync()
	}
	return nil
}

func Initialize() error {
	var err error
	once.Do(func() {
		logLevel, levelErr := zap.ParseAtomicLevel(os.Getenv("LOG_LEVEL"))
		if levelErr != nil {
			logLevel = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		}

		options := []zap.Option{zap.AddCallerSkip(1)}

		if os.Getenv("APP_ENV") != "production" {
			config := zap.NewDevelopmentConfig()
			config.Level = logLevel
			instance, err = config.Build(
				options...,
			)
		} else {
			config := zap.NewProductionConfig()
			config.Level = logLevel
			instance, err = config.Build(
				options...,
			)
		}

		if err == nil && instance != nil {
			instance.Info("Initialized logger", zap.String("setLevel", logLevel.String()))
		}
	})
	return err
}

func MustInitialize() {
	if err := Initialize(); err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
}
