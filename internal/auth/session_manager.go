package auth

import (
	"encoding/gob"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

type SessionManager struct {
	store           sessions.Store
	noEncryptStore  *NoEncryptionStore
	encryptSessions bool
}

func NewSessionManager(sessionPath, secret string, encryptSessions bool) *SessionManager {
	os.MkdirAll(sessionPath, 0755)

	var store sessions.Store
	var noEncryptStore *NoEncryptionStore

	if encryptSessions {
		// Режим с шифрованием - используем нормальный секрет
		store = sessions.NewFilesystemStore(sessionPath, []byte(secret))

		// Настройки сессии
		if fsStore, ok := store.(*sessions.FilesystemStore); ok {
			fsStore.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   3600 * 24,
				HttpOnly: true,
				Secure:   false,
			}
		}

		gob.Register(map[string]interface{}{})
	} else {
		// Режим БЕЗ шифрования - используем пустой секрет
		noEncryptStore = NewNoEncryptionStore(sessionPath)
	}

	return &SessionManager{
		store:           store,
		noEncryptStore:  noEncryptStore,
		encryptSessions: encryptSessions,
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

	return NewUniversalSession(sm.encryptSessions, session), nil
}

// SaveSession сохраняет сессию
func (sm *SessionManager) SaveSession(w http.ResponseWriter, r *http.Request, session *UniversalSession) error {
	return session.Save(w, r)
}

// DestroySession удаляет сессию
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request, session *UniversalSession) {
	session.Destroy(w, r)
}
