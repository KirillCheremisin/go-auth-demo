package auth

import (
	"auth-demo/internal/storage"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

type SessionManager struct {
	store           sessions.Store
	noEncryptStore  *NoEncryptionStore
	encryptSessions bool
	redisStorage    *storage.RedisSessionStorage
	sessionStore    string
}

func NewSessionManager(sessionPath, secret string, encryptSessions bool, redisURL, sessionStore string) *SessionManager {
	os.MkdirAll(sessionPath, 0755)

	var store sessions.Store
	var noEncryptStore *NoEncryptionStore
	var redisStorage *storage.RedisSessionStorage

	if sessionStore == "redis" {
		// Используем Redis
		redisStorage = storage.NewRedisSessionStorage(redisURL)
		if encryptSessions {
			// Redis с шифрованием (через gorilla/sessions)
			// Пока используем файловое хранилище, но с Redis бэкендом
			store = NewRedisStore(redisStorage)
		} else {
			// Redis без шифрования
			noEncryptStore = NewNoEncryptionStore(sessionPath) // Пока оставим файлы
		}
	} else {
		// Файловое хранилище
		if encryptSessions {
			// Файлы с шифрованием
			store = sessions.NewFilesystemStore(sessionPath, []byte(secret))
			store.(*sessions.FilesystemStore).Options = &sessions.Options{
				Path:     "/",
				MaxAge:   3600 * 24,
				HttpOnly: true,
				Secure:   false,
			}
		} else {
			// Файлы без шифрования
			noEncryptStore = NewNoEncryptionStore(sessionPath)
		}
	}

	return &SessionManager{
		store:           store,
		noEncryptStore:  noEncryptStore,
		encryptSessions: encryptSessions,
		redisStorage:    redisStorage,
		sessionStore:    sessionStore,
	}
}

// GetSession возвращает сессию по имени
func (sm *SessionManager) GetSession(r *http.Request, name string) (*UniversalSession, error) {
	var session interface{}
	var err error

	if sm.encryptSessions {
		session, err = sm.store.Get(r, name)
	} else {
		session, err = sm.noEncryptStore.Get(r, name)
	}

	if err != nil {
		return nil, err
	}

	return NewUniversalSession(sm.encryptSessions, session, sm), nil
}

// SaveSession сохраняет сессию
func (sm *SessionManager) SaveSession(w http.ResponseWriter, r *http.Request, session *UniversalSession) error {
	return session.Save(w, r)
}

// DestroySession удаляет сессию
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request, session *UniversalSession) {
	session.Destroy(w, r)
}
