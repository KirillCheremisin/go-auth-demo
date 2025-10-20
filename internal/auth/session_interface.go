package auth

import (
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
}

func NewUniversalSession(encryptSessions bool, session interface{}) *UniversalSession {
	return &UniversalSession{
		encryptSessions: encryptSessions,
		session:         session,
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
		session := us.session.(*sessions.Session)
		session.Options.MaxAge = -1
		session.Save(r, w)
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
