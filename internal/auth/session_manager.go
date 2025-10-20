package auth

import (
    "encoding/gob"
    "net/http"
    "os"
    "path/filepath"
    
    "github.com/gorilla/sessions"
)

type SessionManager struct {
    store sessions.Store
    sessionPath string
}

func NewSessionManager(sessionPath, secret string) *SessionManager {
    // Создаем папку для сессий если её нет
    os.MkdirAll(sessionPath, 0755)
    
    // Создаем файловое хранилище сессий
    store := sessions.NewFilesystemStore(sessionPath, []byte(secret))
    
    // Настройки сессии
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600 * 24, // 24 часа
        HttpOnly: true,
        Secure:   false, // true в production с HTTPS
    }
    
    // Регистрируем типы для gob
    gob.Register(map[string]interface{}{})
    
    return &SessionManager{
        store: store,
        sessionPath: sessionPath,
    }
}

// GetSession возвращает сессию по имени
func (sm *SessionManager) GetSession(r *http.Request, name string) (*sessions.Session, error) {
    return sm.store.Get(r, name)
}

// SaveSession сохраняет сессию
func (sm *SessionManager) SaveSession(w http.ResponseWriter, r *http.Request, session *sessions.Session) error {
    return session.Save(r, w)
}

// DestroySession удаляет сессию
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
    // Получаем ID сессии из cookie
    if cookie, err := r.Cookie(session.Name()); err == nil {
        sessionID := cookie.Value
        // Удаляем физический файл
        sm.deleteSessionFile(sessionID)
    }

    session.Options.MaxAge = -1 // Устанавливаем время жизни в прошлое
    session.Save(r, w)
}

// deleteSessionFile физически удаляет файл сессии
func (sm *SessionManager) deleteSessionFile(sessionID string) {
    if sessionID == "" {
        return
    }
    
    filePath := filepath.Join(sm.sessionPath, "session_"+sessionID)
    os.Remove(filePath)
}