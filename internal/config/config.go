package config

import (
	"os"
)

type Config struct {
	SessionSecret string
	JWTSecret     string
	DatabaseURL   string
	RedisURL      string
	GRPCPort      string
}

func Load() *Config {
	return &Config{
		SessionSecret: getEnv("SESSION_SECRET", "fallback-secret-key"),
		JWTSecret:     getEnv("JWT_SECRET", "fallback-jwt-secret"),
		DatabaseURL:   getEnv("DATABASE_URL", ""),

		RedisURL: getEnv("REDIS_URL", ""),

		GRPCPort: getEnv("GRPC_PORT", "50051"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
