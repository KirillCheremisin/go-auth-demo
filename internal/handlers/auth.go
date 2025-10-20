package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"auth-demo/internal/auth"
	"auth-demo/internal/storage"
)

type SessionManager interface {
	GetSession(r *http.Request, name string) (*auth.UniversalSession, error)
	SaveSession(w http.ResponseWriter, r *http.Request, session *auth.UniversalSession) error
	DestroySession(w http.ResponseWriter, r *http.Request, session *auth.UniversalSession)
}

type AuthHandler struct {
	userStorage    storage.Storage
	sessionManager SessionManager
	jwtManager     *auth.JWTManager
}

func NewAuthHandler(userStorage storage.Storage, sessionManager SessionManager, jwtManager *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		userStorage:    userStorage,
		sessionManager: sessionManager,
		jwtManager:     jwtManager,
	}
}

// Register обрабатывает регистрацию пользователя
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.userStorage.CreateUser(request.Email, request.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]string{
		"message": "User registered successfully",
		"user_id": user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Login обрабатывает вход через сессии
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Проверяем существование пользователя и пароль
	user, err := h.userStorage.VerifyPassword(request.Email, request.Password)
	if err != nil {
		http.Error(w, `{"error": "Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// Создаем сессию
	session, err := h.sessionManager.GetSession(r, "auth-session")
	if err != nil {
		http.Error(w, `{"error": "Failed to create session"}`, http.StatusInternalServerError)
		return
	}

	// Сохраняем данные пользователя в сессии в зависимости от типа
	session.Set("user_id", user.ID)
	session.Set("email", user.Email)
	session.Set("authenticated", true)

	// Сохраняем сессию
	if err := h.sessionManager.SaveSession(w, r, session); err != nil {
		http.Error(w, `{"error": "Failed to save session"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message": "Login successful",
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
		},
		"session_type": "cookie_based",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LoginJWT обрабатывает вход через JWT токены
func (h *AuthHandler) LoginJWT(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Проверяем пользователя
	user, err := h.userStorage.VerifyPassword(request.Email, request.Password)
	if err != nil {
		http.Error(w, `{"error": "Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// Генерируем JWT токен
	// Генерируем access и refresh токены
	accessToken, err := h.jwtManager.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate refresh token"}`, http.StatusInternalServerError)
		return
	}

	// Хешируем и сохраняем refresh token
	tokenHash := hashToken(refreshToken)
	if err := h.userStorage.StoreRefreshToken(user.ID, tokenHash); err != nil {
		http.Error(w, `{"error": "Failed to store refresh token"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message": "Login successful (JWT)",
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
		},
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    15 * 60, // 15 минут в секундах
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RefreshToken обновляет access token используя refresh token
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if request.RefreshToken == "" {
		http.Error(w, `{"error": "Refresh token required"}`, http.StatusBadRequest)
		return
	}

	// Валидируем refresh token
	tokenHash := hashToken(request.RefreshToken)
	userID, err := h.userStorage.ValidateRefreshToken(tokenHash)
	if err != nil {
		http.Error(w, `{"error": "Invalid refresh token"}`, http.StatusUnauthorized)
		return
	}

	// Получаем данные пользователя
	user, err := h.userStorage.GetUserByID(userID)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Генерируем новый access token
	accessToken, err := h.jwtManager.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   15 * 60, // 15 минут
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SessionMiddleware проверяет валидность сессии
func (h *AuthHandler) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.sessionManager.GetSession(r, "auth-session")
		if err != nil {
			http.Error(w, `{"error": "Session error"}`, http.StatusInternalServerError)
			return
		}

		// Используем метод IsAuthenticated
		if !session.IsAuthenticated() {
			http.Error(w, `{"error": "Unauthorized - please login"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JWTMiddleware проверяет JWT токен
func (h *AuthHandler) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			http.Error(w, `{"error": "Invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]
		claims, err := h.jwtManager.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Добавляем данные пользователя в контекст запроса
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		ctx = context.WithValue(ctx, "jwt_claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetProfile возвращает данные пользователя
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionManager.GetSession(r, "auth-session")
	if err != nil {
		http.Error(w, `{"error": "Session error"}`, http.StatusInternalServerError)
		return
	}

	if !session.IsAuthenticated() {
		http.Error(w, `{"error": "Unauthorized - please login"}`, http.StatusUnauthorized)
		return
	}

	userID := session.GetUserID()
	if userID == "" {
		http.Error(w, `{"error": "User not found in session"}`, http.StatusUnauthorized)
		return
	}

	user, err := h.userStorage.GetUserByID(userID)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"message": "Profile data (session auth)",
		"user": map[string]interface{}{
			"id":         user.ID,
			"email":      user.Email,
			"created_at": user.CreatedAt,
		},
		"session_info": map[string]interface{}{
			"authenticated": session.IsAuthenticated(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) GetProfileJWT(w http.ResponseWriter, r *http.Request) {
	// Получаем токен из заголовка Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
		return
	}

	// Проверяем формат: "Bearer <token>"
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		http.Error(w, `{"error": "Invalid authorization format"}`, http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[7:]

	// Валидируем токен
	claims, err := h.jwtManager.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	// Получаем данные пользователя
	user, err := h.userStorage.GetUserByID(claims.UserID)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"message": "Profile data (JWT auth)",
		"user": map[string]interface{}{
			"id":         user.ID,
			"email":      user.Email,
			"created_at": user.CreatedAt,
		},
		"token_info": map[string]interface{}{
			"issued_at":  claims.IssuedAt,
			"expires_at": claims.ExpiresAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Logout выход пользователя, остановка сессии
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionManager.GetSession(r, "auth-session")
	if err != nil {
		http.Error(w, `{"error": "Session error"}`, http.StatusInternalServerError)
		return
	}

	// Уничтожаем сессию
	h.sessionManager.DestroySession(w, r, session)

	response := map[string]string{
		"message": "Logout successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetAllUsers возвращает список всех зарегистрированных пользователей
func (h *AuthHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userStorage.GetAllUsers()
	if err != nil {
		http.Error(w, `{"error": "Failed to get users"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message": "List of registered users",
		"count":   len(users),
		"users":   users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Вспомогательная функция для хеширования токена
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
