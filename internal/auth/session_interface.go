package auth

import (
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

// UniversalSession обертка для работы с разными типами сессий
type UniversalSession struct {
	encryptSessions bool
	session         interface{}
	sessionManager  *SessionManager
}

func NewUniversalSession(encryptSessions bool, session interface{}, sessionManager *SessionManager) *UniversalSession {
	return &UniversalSession{
		encryptSessions: encryptSessions,
		session:         session,
		sessionManager:  sessionManager,
	}
}

func (us *UniversalSession) Set(key string, value interface{}) {
	if us.encryptSessions {
		us.session.(*sessions.Session).Values[key] = value
	} else {
		us.session.(*Session).Values[key] = value
	}
}

func (us *UniversalSession) Get(key string) interface{} {
	if us.encryptSessions {
		return us.session.(*sessions.Session).Values[key]
	} else {
		return us.session.(*Session).Values[key]
	}
}

func (us *UniversalSession) Save(w http.ResponseWriter, r *http.Request) error {
	if us.encryptSessions {
		return us.session.(*sessions.Session).Save(r, w)
	} else {
		return us.session.(*Session).Save(w)
	}
}

func (us *UniversalSession) Destroy(w http.ResponseWriter, r *http.Request) {
	if us.encryptSessions {
		// Надежно получаем session ID
		sessionID := us.getSessionID(r)
		if sessionID == "" {
			log.Printf("⚠️ Cannot destroy session - ID not found")
			return
		}

		// Удаляем из хранилища
		if us.sessionManager.sessionStore == "redis" {
			us.sessionManager.redisStorage.DeleteSession(sessionID)
		}

		// Удаляем cookie
		us.clearSessionCookie(w)

	} else {
		us.session.(*Session).Destroy(w)
	}
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

// Вспомогательный метод для получения ID
func (us *UniversalSession) getSessionID(r *http.Request) string {
	// Пробуем разные источники в порядке приоритета
	sources := []string{"auth-session", "gorilla.sessions", "session"}

	for _, name := range sources {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			return cookie.Value
		}
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
