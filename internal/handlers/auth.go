package handlers

import (
    "encoding/json"
    "net/http"
    
    "auth-demo/internal/auth"
    "auth-demo/internal/storage"

    "github.com/gorilla/sessions"
)

type SessionManager interface {
    GetSession(r *http.Request, name string) (*sessions.Session, error)
    SaveSession(w http.ResponseWriter, r *http.Request, session *sessions.Session) error
    DestroySession(w http.ResponseWriter, r *http.Request, session *sessions.Session)
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
    
    // Сохраняем данные пользователя в сессии
    session.Values["user_id"] = user.ID
    session.Values["email"] = user.Email
    session.Values["authenticated"] = true
    
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

// LoginJWT обрабатывает вход через JWT
func (h *AuthHandler) LoginJWT(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Здесь будет проверка пароля и генерация JWT
    // Пока просто возвращаем успех
    response := map[string]string{
        "message": "JWT login endpoint - TODO",
    }
    
    w.Header().Set("Content-Type", "application/json")
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
        
        // Проверяем аутентификацию
        if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
            http.Error(w, `{"error": "Unauthorized - please login"}`, http.StatusUnauthorized)
            return
        }
        
        // // Добавляем данные пользователя в контекст запроса
        // if userID, ok := session.Values["user_id"].(string); ok {
        //     // Можно добавить в контекст: r = r.WithContext(context.WithValue(r.Context(), "user_id", userID))
        // }
        
        next.ServeHTTP(w, r)
    })
}

func (h *AuthHandler) JWTMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // TODO: проверка JWT
        next.ServeHTTP(w, r)
    })
}

// GetProfile возвращает данные пользователя
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
    session, err := h.sessionManager.GetSession(r, "auth-session")
    if err != nil {
        http.Error(w, `{"error": "Session error"}`, http.StatusInternalServerError)
        return
    }
    
    userID, ok := session.Values["user_id"].(string)
    if !ok {
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
            "authenticated": session.Values["authenticated"],
        },
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) GetProfileJWT(w http.ResponseWriter, r *http.Request) {
    response := map[string]string{
        "message": "Profile endpoint (JWT) - TODO",
    }
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