package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-demo/internal/auth"
	"auth-demo/internal/config"
	"auth-demo/internal/grpc"
	"auth-demo/internal/handlers"
	"auth-demo/internal/storage"

	_ "auth-demo/docs"

	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Auth Demo API
// @version 1.0
// @description Демонстрационное приложение аутентификации на Go
// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT токен в формате "Bearer {token}"

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name auth-session
// @description Сессионная cookie
func main() {
	// Загрузка .env файла
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using defaults")
	}

	cfg := config.Load()

	// Конфигурация
	sessionSecret := os.Getenv("SESSION_SECRET")
	jwtSecret := os.Getenv("JWT_SECRET")

	if sessionSecret == "" {
		sessionSecret = "fallback-secret-key-change-me"
	}
	if jwtSecret == "" {
		jwtSecret = "fallback-jwt-secret-change-me"
	}

	// Инициализация компонентов
	userStorage, err := storage.NewPostgresStorage(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer userStorage.Close()

	sessionManager := auth.NewSessionManager(
		cfg.SessionSecret,
		cfg.RedisURL,
	)

	jwtManager := auth.NewJWTManager(cfg.JWTSecret)

	authHandler := handlers.NewAuthHandler(userStorage, sessionManager, jwtManager)

	// Настройка маршрутизатора
	r := mux.NewRouter()

	// swagger
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Public routes
	r.HandleFunc("/register", authHandler.Register).Methods("POST")
	r.HandleFunc("/login", authHandler.Login).Methods("POST")
	r.HandleFunc("/login-jwt", authHandler.LoginJWT).Methods("POST")
	r.HandleFunc("/refresh-token", authHandler.RefreshToken).Methods("POST")

	// Session-protected routes
	sessionRouter := r.PathPrefix("/session").Subrouter()
	sessionRouter.Use(authHandler.SessionMiddleware)
	sessionRouter.HandleFunc("/profile", authHandler.GetProfile).Methods("GET")
	sessionRouter.HandleFunc("/logout", authHandler.Logout).Methods("POST")
	sessionRouter.HandleFunc("/users", authHandler.GetAllUsers).Methods("GET")

	// JWT-protected routes
	jwtRouter := r.PathPrefix("/jwt").Subrouter()
	jwtRouter.Use(authHandler.JWTMiddleware)
	jwtRouter.HandleFunc("/profile", authHandler.GetProfileJWT).Methods("GET")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "OK", "message": "Server is running!"}`))
	}).Methods("GET")

	// Создаем и запускаем gRPC сервер
	grpcServer := grpc.NewServer(cfg, userStorage)

	// Запускаем gRPC сервер в отдельной goroutine
	go func() {
		log.Printf("🚀 gRPC server starting on port %s", cfg.GRPCPort)
		if err := grpcServer.Start(); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	// Создаем HTTP сервер с таймаутами
	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Запускаем HTTP сервер в отдельной goroutine
	go func() {
		log.Println("🚀 HTTP server starting on http://localhost:8080")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	log.Println("🚀 Server starting on http://localhost:8080")
	log.Printf("🔧 gRPC Port: %s", cfg.GRPCPort)
	log.Printf("📍 Redis URL: %s", cfg.RedisURL)
	log.Println("📍 Available endpoints:")
	log.Println("   GET  /health")
	log.Println("   POST /register")
	log.Println("   POST /login")
	log.Println("   POST /login-jwt")
	log.Println("   POST /refresh-token")
	log.Println("   GET  /session/profile (protected)")
	log.Println("   POST /session/logout (protected)")
	log.Println("   GET  /session/users (protected)")
	log.Println("   GET  /jwt/profile (protected)")

	//log.Fatal(http.ListenAndServe(":8080", r))

	// === GRACEFUL SHUTDOWN ===
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down servers...")

	// Останавливаем gRPC сервер
	grpcServer.Stop()

	// Останавливаем HTTP сервер
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	} else {
		log.Println("🛑 Stopping HTTP server...")
	}

	log.Println("✅ Servers stopped gracefully")
}
