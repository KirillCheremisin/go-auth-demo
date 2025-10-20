package main

import (
    "log"
    "net/http"
    "os"
    
    "auth-demo/internal/auth"
    "auth-demo/internal/handlers"
    "auth-demo/internal/storage"
    
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    _ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
    // Загрузка .env файла
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, using defaults")
    }
    
    // Конфигурация
    sessionSecret := os.Getenv("SESSION_SECRET")
    jwtSecret := os.Getenv("JWT_SECRET")
    sessionPath := os.Getenv("SESSION_FILE_PATH")
    
    if sessionSecret == "" {
        sessionSecret = "fallback-secret-key-change-me"
    }
    if jwtSecret == "" {
        jwtSecret = "fallback-jwt-secret-change-me"
    }
    if sessionPath == "" {
        sessionPath = "./sessions"
    }
    
    // Инициализация компонентов
    //userStorage := storage.NewMemoryStorage()
    userStorage, err := storage.NewPostgresStorage(os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer userStorage.Close() 
    
    // Пока используем заглушку для sessionManager
    //sessionManager := auth.NewFileSystemStore(sessionPath, []byte(sessionSecret))
    sessionManager := auth.NewSessionManager(sessionPath, sessionSecret)
    jwtManager := auth.NewJWTManager(jwtSecret)
    
    authHandler := handlers.NewAuthHandler(userStorage, sessionManager, jwtManager)
    
    // Настройка маршрутизатора
    r := mux.NewRouter()
    
    // Public routes
    r.HandleFunc("/register", authHandler.Register).Methods("POST")
    r.HandleFunc("/login", authHandler.Login).Methods("POST")
    r.HandleFunc("/login-jwt", authHandler.LoginJWT).Methods("POST")
    
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
    
    log.Println("🚀 Server starting on http://localhost:8080")
    log.Printf("📁 Session files will be stored in: %s\n", sessionPath)
    log.Println("📍 Available endpoints:")
    log.Println("   GET  /health")
    log.Println("   POST /register")
    log.Println("   POST /login") 
    log.Println("   POST /login-jwt")
    log.Println("   GET  /session/profile (protected)")
    log.Println("   POST /session/logout (protected)")
    log.Println("   GET  /session/users (protected)") 
    log.Println("   GET  /jwt/profile (protected)")
    
    log.Fatal(http.ListenAndServe(":8080", r))
}