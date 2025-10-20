package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	//"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

// PostgresStorage реализует Storage интерфейс для PostgreSQL
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage создает новое подключение к PostgreSQL
func NewPostgresStorage(connectionString string) (*PostgresStorage, error) {
	db, err := sql.Open("pgx", connectionString)
	if err != nil {
		return nil, err
	}

	// Проверяем подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return &PostgresStorage{db: db}, nil
}

// CreateUser создает нового пользователя в PostgreSQL
func (p *PostgresStorage) CreateUser(email, password string) (*User, error) {
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

	// Вставляем пользователя в БД
	query := `INSERT INTO users (id, email, password_hash, password_text, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err = p.db.Exec(query, user.ID, user.Email, user.Password, password, user.CreatedAt)
	if err != nil {
		// Проверяем на нарушение уникальности email
		if err.Error() == "pq: duplicate key value violates unique constraint \"users_email_key\"" {
			return nil, errors.New("user already exists")
		}
		return nil, err
	}

	return user, nil
}

// GetUserByEmail ищет пользователя по email
func (p *PostgresStorage) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, password_hash, created_at FROM users WHERE email = $1`
	row := p.db.QueryRow(query, email)

	user := &User{}
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

// GetUserByID ищет пользователя по ID
func (p *PostgresStorage) GetUserByID(id string) (*User, error) {
	query := `SELECT id, email, password_hash, created_at FROM users WHERE id = $1`
	row := p.db.QueryRow(query, id)

	user := &User{}
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

// VerifyPassword проверяет email и пароль пользователя
func (p *PostgresStorage) VerifyPassword(email, password string) (*User, error) {
	user, err := p.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	// Сравниваем хешированный пароль с введенным
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid password")
	}

	return user, nil
}

// GetAllUsers возвращает список всех пользователей
func (p *PostgresStorage) GetAllUsers() ([]*User, error) {
	query := `SELECT id, email, password_hash, created_at FROM users ORDER BY created_at`
	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		// Скрываем пароль
		user.Password = "***HIDDEN***"
		users = append(users, user)
	}

	return users, nil
}

// Close закрывает подключение к БД
func (p *PostgresStorage) Close() error {
	return p.db.Close()
}
