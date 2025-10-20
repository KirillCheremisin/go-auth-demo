package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// NoEncryptionStore хранит сессии в JSON файлах без шифрования
type NoEncryptionStore struct {
	path    string
	options *Options
}

type Options struct {
	Path     string
	MaxAge   int
	HttpOnly bool
	Secure   bool
}

func NewNoEncryptionStore(path string) *NoEncryptionStore {
	return &NoEncryptionStore{
		path: path,
		options: &Options{
			Path:     "/",
			MaxAge:   3600 * 24, // 24 часа
			HttpOnly: true,
			Secure:   false,
		},
	}
}

// Session представляет сессию без шифрования
type Session struct {
	ID      string
	Values  map[string]interface{}
	Options *Options
	store   *NoEncryptionStore
}

func (s *NoEncryptionStore) Get(r *http.Request, name string) (*Session, error) {
	return s.getSession(r, name)
}

func (s *NoEncryptionStore) New(r *http.Request, name string) (*Session, error) {
	session := &Session{
		Values:  make(map[string]interface{}),
		Options: s.options,
		store:   s,
	}

	// Пытаемся загрузить существующую сессию из cookie
	if cookie, err := r.Cookie(name); err == nil {
		session.ID = cookie.Value
		if err := s.load(session); err == nil {
			return session, nil
		}
	}

	// Создаем новую сессию
	session.ID = generateSessionID()
	return session, nil
}

// Save сохраняет сессию
func (s *Session) Save(w http.ResponseWriter) error {
	return s.store.Save(w, s)
}

func (s *NoEncryptionStore) Save(w http.ResponseWriter, session *Session) error {
	// Сохраняем в файл
	if err := s.save(session); err != nil {
		return err
	}

	// Устанавливаем cookie
	cookie := &http.Cookie{
		Name:     "auth-session",
		Value:    session.ID,
		Path:     session.Options.Path,
		MaxAge:   session.Options.MaxAge,
		HttpOnly: session.Options.HttpOnly,
		Secure:   session.Options.Secure,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (s *NoEncryptionStore) save(session *Session) error {
	filename := filepath.Join(s.path, session.ID+".json")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	data := map[string]interface{}{
		"values":   session.Values,
		"created":  time.Now(),
		"lifetime": session.Options.MaxAge,
	}

	return json.NewEncoder(file).Encode(data)
}

func (s *NoEncryptionStore) load(session *Session) error {
	filename := filepath.Join(s.path, session.ID+".json")
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var data struct {
		Values map[string]interface{} `json:"values"`
	}

	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return err
	}

	session.Values = data.Values
	return nil
}

func (s *NoEncryptionStore) getSession(r *http.Request, name string) (*Session, error) {
	return s.New(r, name)
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *Session) Destroy(w http.ResponseWriter) error {
	// Удаляем cookie
	cookie := &http.Cookie{
		Name:   "auth-session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)

	// Удаляем файл сессии
	if s.ID != "" {
		filename := filepath.Join(s.store.path, s.ID+".json")
		os.Remove(filename)
	}
	return nil
}
