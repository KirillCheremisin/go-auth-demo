package config

import (
	"os"
	"strconv"
)

type Config struct {
	SessionSecret   string
	JWTSecret       string
	SessionPath     string
	DatabaseURL     string
	EncryptSessions bool

	RedisURL     string
	SessionStore string // "files" или "redis"

	GRPCPort string
}

func Load() *Config {
	return &Config{
		SessionSecret:   getEnv("SESSION_SECRET", "fallback-secret-key"),
		JWTSecret:       getEnv("JWT_SECRET", "fallback-jwt-secret"),
		SessionPath:     getEnv("SESSION_FILE_PATH", "./sessions"),
		DatabaseURL:     getEnv("DATABASE_URL", ""),
		EncryptSessions: getEnvBool("ENCRYPT_SESSIONS", true), // По умолчанию шифруем

		RedisURL:     getEnv("REDIS_URL", ""),
		SessionStore: getEnv("SESSION_STORE", "files"),

		GRPCPort: getEnv("GRPC_PORT", "50051"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}
