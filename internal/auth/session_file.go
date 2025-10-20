package auth

import (
    "encoding/gob"
    "net/http"
    "os"
    "path/filepath"
    "sync"
)

// FileSystemStore реализует хранилище сессий в файлах
type FileSystemStore struct {
    path    string
    secret  []byte
    options *Options
    mu      sync.RWMutex
}

type Options struct {
    Path     string
    MaxAge   int
    HttpOnly bool
}

func NewFileSystemStore(sessionPath string, secret []byte) *FileSystemStore {
    // Создаем папку для сессий если её нет
    os.MkdirAll(sessionPath, 0755)
    
    return &FileSystemStore{
        path:   sessionPath,
        secret: secret,
        options: &Options{
            Path:     "/",
            MaxAge:   3600 * 24, // 24 часа
            HttpOnly: true,
        },
    }
}

// Get возвращает сессию по имени
func (s *FileSystemStore) Get(r *http.Request, name string) (*Session, error) {
    return s.getSession(r, name)
}

// New создает новую сессию
func (s *FileSystemStore) New(r *http.Request, name string) (*Session, error) {
    session := NewSession(s, name)
    session.Options = &Options{
        Path:     s.options.Path,
        MaxAge:   s.options.MaxAge,
        HttpOnly: s.options.HttpOnly,
    }
    session.IsNew = true
    
    // Пытаемся загрузить существующую сессию
    if cookie, errCookie := r.Cookie(name); errCookie == nil {
        if err := s.load(session, cookie.Value); err == nil {
            session.IsNew = false
        }
    }
    
    return session, nil
}

// Save сохраняет сессию
func (s *FileSystemStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
    // Генерируем ID сессии если нужно
    if session.ID == "" {
        session.ID = generateSessionID()
    }
    
    // Сохраняем в файл
    if err := s.save(session); err != nil {
        return err
    }
    
    // Устанавливаем cookie
    cookie := &http.Cookie{
        Name:     session.Name(),
        Value:    session.ID,
        Path:     session.Options.Path,
        MaxAge:   session.Options.MaxAge,
        HttpOnly: session.Options.HttpOnly,
    }
    http.SetCookie(w, cookie)
    return nil
}

func (s *FileSystemStore) save(session *Session) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    filename := filepath.Join(s.path, session.ID+".session")
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    encoder := gob.NewEncoder(file)
    return encoder.Encode(session.Values)
}

func (s *FileSystemStore) load(session *Session, id string) error {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    filename := filepath.Join(s.path, id+".session")
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    decoder := gob.NewDecoder(file)
    return decoder.Decode(&session.Values)
}

func (s *FileSystemStore) getSession(r *http.Request, name string) (*Session, error) {
    return s.New(r, name)
}

func generateSessionID() string {
    // Простая реализация - в продакшене используйте crypto/rand
    return "session-" + string(rune(len("temp")))
}