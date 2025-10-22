package auth

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

// SessionInterface универсальный интерфейс для сессий
type SessionInterface interface {
	Set(key string, value interface{})
	Get(key string) interface{}
	Save(w http.ResponseWriter, r *http.Request) error
	Destroy(w http.ResponseWriter, r *http.Request)
	IsAuthenticated() bool
	GetUserID() string
}

// UniversalSession обертка для работы с зашифрованными сессиями
type UniversalSession struct {
	session        *sessions.Session
	sessionManager *SessionManager
}

func NewUniversalSession(session *sessions.Session, sessionManager *SessionManager) *UniversalSession {
	return &UniversalSession{
		session:        session,
		sessionManager: sessionManager,
	}
}

func (us *UniversalSession) Set(key string, value interface{}) {
	us.session.Values[key] = value
}

func (us *UniversalSession) Get(key string) interface{} {
	return us.session.Values[key]
}

func (us *UniversalSession) Save(w http.ResponseWriter, r *http.Request) error {
	return us.session.Save(r, w)
}

func (us *UniversalSession) Destroy(w http.ResponseWriter, r *http.Request) {
	// Надежно получаем session ID
	sessionID := us.getSessionID(r)
	if sessionID == "" {
		log.Printf("⚠️ Cannot destroy session - ID not found")
		return
	}

	// Удаляем из Redis
	us.sessionManager.redisStorage.DeleteSession(sessionID)

	// Удаляем cookie
	us.clearSessionCookie(w)
}

func (us *UniversalSession) IsAuthenticated() bool {
	if auth := us.Get("authenticated"); auth != nil {
		if isAuth, ok := auth.(bool); ok {
			return isAuth
		}
	}
	return false
}

func (us *UniversalSession) GetUserID() string {
	if userID := us.Get("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// Вспомогательный метод для получения ID сессии
func (us *UniversalSession) getSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("auth-session"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

// Вспомогательный метод для очистки cookie
func (us *UniversalSession) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "auth-session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

// GenerateSessionID генерирует уникальный ID для сессии
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
