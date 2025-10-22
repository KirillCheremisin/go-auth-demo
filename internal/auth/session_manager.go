package auth

import (
	"auth-demo/internal/storage"
	"net/http"

	"github.com/gorilla/sessions"
)

type SessionManager struct {
	store        sessions.Store
	redisStorage *storage.RedisSessionStorage
}

func NewSessionManager(secret string, redisURL string) *SessionManager {
	redisStorage := storage.NewRedisSessionStorage(redisURL)
	store := NewRedisStore(redisStorage)

	return &SessionManager{
		store:        store,
		redisStorage: redisStorage,
	}
}

// GetSession возвращает сессию по имени
func (sm *SessionManager) GetSession(r *http.Request, name string) (*UniversalSession, error) {
	session, err := sm.store.Get(r, name)
	if err != nil {
		return nil, err
	}

	return NewUniversalSession(session, sm), nil
}

// SaveSession сохраняет сессию
func (sm *SessionManager) SaveSession(w http.ResponseWriter, r *http.Request, session *UniversalSession) error {
	return session.Save(w, r)
}

// DestroySession удаляет сессию
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request, session *UniversalSession) {
	session.Destroy(w, r)
}
