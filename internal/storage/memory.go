package storage

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string
	Email     string
	Password  string
	CreatedAt time.Time
}

type Storage interface {
	CreateUser(email, password string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id string) (*User, error)
	VerifyPassword(email, password string) (*User, error)
	GetAllUsers() ([]*User, error)
}

type MemoryStorage struct {
	users map[string]*User
	mu    sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users: make(map[string]*User),
	}
}

func (s *MemoryStorage) CreateUser(email, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Проверяем существование пользователя
	if _, exists := s.users[email]; exists {
		return nil, errors.New("user already exists")
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:        generateUserID(),
		Email:     email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	s.users[email] = user
	return user, nil
}

func (s *MemoryStorage) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (s *MemoryStorage) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.ID == id {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}

func generateUserID() string {
	// bytes := make([]byte, 8) // 16 hex символов
	// rand.Read(bytes)
	// return "user-" + hex.EncodeToString(bytes)
	return "user-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// VerifyPassword проверяет пароль пользователя
func (s *MemoryStorage) VerifyPassword(email, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	// Сравниваем хешированный пароль с введенным
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid password")
	}

	return user, nil
}

// GetAllUsers возвращает список всех зарегистрированных пользователей
func (s *MemoryStorage) GetAllUsers() ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		// Не возвращаем пароли из соображений безопасности
		safeUser := &User{
			ID:        user.ID,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			Password:  "***HIDDEN***", // Пароль скрыт
		}
		users = append(users, safeUser)
	}

	return users, nil
}
