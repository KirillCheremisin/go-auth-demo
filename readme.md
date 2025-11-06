# Auth Demo - Go Authentication Service

## 📋 Краткое описание
Простое демонстрационное приложение на Go, реализующее различные способы аутентификации и авторизации. Поддерживает session-based аутентификацию с хранением сессий в Redis и token-based аутентификацию через JWT.
Пользователи и refresh-токены хранятся в Postgres

## Эндпоинты:

HTTP:
* публичные:
    * GET /health
    * POST /register
    * POST /login  
    * POST /login-jwt
    * POST /refresh-token
* приватные
    * GET /session/profile
    * POST /session/logout
    * GET /session/users
    * GET /jwt/profile

gRPC:
* UserService
    * GetUserProfile
    * ListUsers
    * UpdateUserProfile

## 🚀 Описание эндпоинтов HTTP

### 🩺 Health Check
#### Проверка состояния сервера
**Endpoint:** `GET /health`

### 🔓 Public Endpoints (не требуют аутентификации)
#### 1. Регистрация пользователя

**Endpoint:** `POST /register`
```json
{
"email": "user@example.com",
"password": "password123"
}
```
Поток данных: Client → AuthHandler → PostgresStorage → PostgreSQL

#### 2. Вход через сессии

**Endpoint:** `POST /login`
```json
{
"email": "user@example.com",
"password": "password123"
}
```
Поток данных: Client → AuthHandler → PostgresStorage → SessionManager → Redis

#### 3. Вход через JWT

**Endpoint:** `POST /login-jwt`
```json
{
"email": "user@example.com",
"password": "password123"
}
```
Пример ответа:
```json
{
"access_token": "eyJhbGciOiJ...",
"refresh_token": "eyJhbGciOiJ...",
"token_type": "Bearer",
"expires_in": 900
}
```
Поток данных: Client → AuthHandler → PostgresStorage → JWTManager

#### 4. Обновление access token

**Endpoint:** `POST /refresh-token`
```json
{
"refresh_token": "eyJhbGciOiJ..."
}
```
Поток данных: Client → AuthHandler → PostgresStorage → JWTManager

### 🔐 Session-Protected Endpoints (требуют cookie сессии)

#### 5. Получение профиля
**Endpoint:** `GET /session/profile`

**Заголовки**: Cookie: auth-session=<session_id>

Поток данных: Client → AuthHandler → SessionManager → Redis → PostgresStorage

#### 6. Выход из системы
**Endpoint:** `POST /session/logout`

**Заголовки**: Cookie: auth-session=<session_id>
Поток данных: Client → AuthHandler → SessionManager → Redis

#### 7. Список пользователей
**Endpoint:** `GET /session/users`

**Заголовки**: Cookie: auth-session=<session_id>
Поток данных: Client → AuthHandler → PostgresStorage

🔑 JWT-Protected Endpoints (требуют Bearer token)
#### 8. Получение профиля через JWT
**Endpoint:** `GET /jwt/profile`

**Заголовки**: Authorization: Bearer <access_token>
Поток данных: Client → AuthHandler → JWTManager → PostgresStorage


## 📡 gRPC Endpoints

### User Service Methods (пока без аутентификации)

#### 1. Получение профиля пользователя
**Method:** `GetUserProfile`
```protobuf
rpc GetUserProfile(GetUserRequest) returns (UserProfile)
message GetUserRequest {
  string user_id = 1;
  //string access_token = 2;
}
```

#### 2. Список пользователей
**Method:** `ListUsers`
```protobuf
rpc ListUsers(ListUsersRequest) returns (ListUsersResponse)
message ListUsersRequest {
  //string access_token = 1;
  int32 page = 2;
  int32 limit = 3;
}
```

#### 3. Обновление профиля пользователя
**Method:** `UpdateUserProfile`
```protobuf
rpc UpdateUserProfile(UpdateUserRequest) returns (UserProfile)
message UpdateUserRequest {
  string user_id = 1;
  //string access_token = 2;
  optional string email = 3;
  optional string display_name = 4;
}
```



## ⚙️ Настройка и запуск
### 1. Предварительные требования
Go 1.25+

PostgreSQL 12+

Redis 6+

### 2. Установка зависимостей
go mod download

### 3. Создание .env файла
Создайте файл .env в корне проекта:
```env
DATABASE_URL=postgres://username:password@localhost:5432/auth_demo?sslmode=disable
SESSION_SECRET=your-super-secret-session-key-change-in-production
JWT_SECRET=your-super-secret-jwt-key-change-in-production
REDIS_URL=localhost:6379
GRPC_PORT=50051
```

### 4. Настройка базы данных
```sql
CREATE DATABASE auth_demo;

CREATE TABLE IF NOT EXISTS users (
id VARCHAR(36) PRIMARY KEY,
email VARCHAR(255) UNIQUE NOT NULL,
password_hash VARCHAR(255) NOT NULL,
created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS refresh_tokens (
id SERIAL PRIMARY KEY,
user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
token_hash VARCHAR(64) UNIQUE NOT NULL,
expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
revoked BOOLEAN DEFAULT FALSE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
```

### 5. Запуск сервисов
Запуск Redis
redis-server

Или через Docker
docker run -d -p 6379:6379 redis

Запуск приложения
go run main.go

### 6. Генерация gRPC кода
generate_proto.bat

## 📦 Зависимости
Основные зависимости:

* Gorilla Mux - HTTP роутинг
* Gorilla Sessions - управление сессиями
* JWT v5 - JWT токены
* pgx - PostgreSQL драйвер
* go-redis - Redis клиент
* gRPC - gRPC фреймворк

## Утилиты:
godotenv - загрузка .env файлов

bcrypt - хеширование паролей

## 🏗️ Архитектура
HTTP Client → HTTP Server (8080) → Auth Handler → Session Manager → Redis

↓

JWT Manager → PostgreSQL

↓

gRPC Client → gRPC Server (50051) → User Service → PostgreSQL

## 🔐 Особенности безопасности
Сессии хранятся в Redis с шифрованием

Пароли хешируются с bcrypt

JWT access tokens: 1 минута

JWT refresh tokens: 7 дней

HTTPS рекомендуется для продакшена

## 🧪 Тестирование
Пример запроса для регистрации и входа:

Регистрация
```bash
curl -X POST http://localhost:8080/register
-H "Content-Type: application/json"
-d '{"email":"test@example.com","password":"test123"}'
```

Вход через сессии
```bash
curl -X POST http://localhost:8080/login
-H "Content-Type: application/json"
-d '{"email":"test@example.com","password":"test123"}'
-c cookies.txt
```

Получение профиля (сессии)
```bash
curl http://localhost:8080/session/profile -b cookies.txt
```

Вход через JWT
```bash
curl -X POST http://localhost:8080/login-jwt
-H "Content-Type: application/json"
-d '{"email":"test@example.com","password":"test123"}'
```

Приложение будет доступно по адресу: http://localhost:8080
Спецификация Swagger будет доступна по адресу: http://localhost:8080/swagger/
Схема plantuml в файле /docs/components.plantuml