package auth

import (
    "net/http"
)

// Session представляет сессию пользователя
type Session struct {
    ID      string
    Values  map[string]interface{}
    Options *Options
    IsNew   bool
    store   *FileSystemStore
    name    string
}

func NewSession(store *FileSystemStore, name string) *Session {
    return &Session{
        Values: make(map[string]interface{}),
        store:  store,
        name:   name,
        IsNew:  true,
    }
}

func (s *Session) Name() string {
    return s.name
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
    return s.store.Save(r, w, s)
}

// Get возвращает значение из сессии
func (s *Session) Get(key string) interface{} {
    if value, exists := s.Values[key]; exists {
        return value
    }
    return nil
}

// Set устанавливает значение в сессии
func (s *Session) Set(key string, value interface{}) {
    s.Values[key] = value
}

// Delete удаляет значение из сессии
func (s *Session) Delete(key string) {
    delete(s.Values, key)
}