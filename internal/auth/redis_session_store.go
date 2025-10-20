package auth

import (
	"net/http"
	"time"

	"auth-demo/internal/storage"

	"github.com/gorilla/sessions"
)

type RedisStore struct {
	redisStorage *storage.RedisSessionStorage
	options      *sessions.Options
}

func NewRedisStore(redisStorage *storage.RedisSessionStorage) *RedisStore {
	return &RedisStore{
		redisStorage: redisStorage,
		options: &sessions.Options{
			Path:     "/",
			MaxAge:   3600 * 24, // 24 часа
			HttpOnly: true,
			Secure:   false,
		},
	}
}

func (rs *RedisStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(rs, name)
}

func (rs *RedisStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(rs, name)
	session.Options = &sessions.Options{
		Path:     rs.options.Path,
		MaxAge:   rs.options.MaxAge,
		HttpOnly: rs.options.HttpOnly,
		Secure:   rs.options.Secure,
	}
	session.IsNew = true

	// Пытаемся загрузить из Redis
	if cookie, err := r.Cookie(name); err == nil {
		sessionID := cookie.Value
		if data, err := rs.redisStorage.GetSession(sessionID); err == nil {
			session.Values = convertToInterfaceMap(data)
			session.IsNew = false
		}
	}

	return session, nil
}

func (rs *RedisStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Генерируем ID сессии если нужно
	if session.ID == "" {
		session.ID = generateSessionID()
	}

	redisData := convertToStringMap(session.Values)

	// Сохраняем в Redis
	err := rs.redisStorage.StoreSession(
		session.ID,
		redisData,
		time.Duration(session.Options.MaxAge)*time.Second,
	)
	if err != nil {
		return err
	}

	// Устанавливаем cookie
	cookie := &http.Cookie{
		Name:     session.Name(),
		Value:    session.ID,
		Path:     session.Options.Path,
		MaxAge:   session.Options.MaxAge,
		HttpOnly: session.Options.HttpOnly,
		Secure:   session.Options.Secure,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (rs *RedisStore) Delete(sessionID string) error {
	return rs.redisStorage.DeleteSession(sessionID)
}

// Вспомогательные функции для конвертации типов

// convertToStringMap конвертирует map[interface{}]interface{} → map[string]interface{}
func convertToStringMap(input map[interface{}]interface{}) map[string]interface{} {
	output := make(map[string]interface{})
	for k, v := range input {
		if keyStr, ok := k.(string); ok {
			output[keyStr] = v
		}
	}
	return output
}

// convertToInterfaceMap конвертирует map[string]interface{} → map[interface{}]interface{}
func convertToInterfaceMap(input map[string]interface{}) map[interface{}]interface{} {
	output := make(map[interface{}]interface{})
	for k, v := range input {
		output[k] = v
	}
	return output
}
