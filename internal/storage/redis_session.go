package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisSessionStorage struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisSessionStorage(redisURL string) *RedisSessionStorage {
	client := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // нет пароля
		DB:       0,  // база по умолчанию
	})

	return &RedisSessionStorage{
		client: client,
		ctx:    context.Background(),
	}
}

func (r *RedisSessionStorage) StoreSession(sessionID string, data map[string]interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return r.client.Set(r.ctx, "session:"+sessionID, jsonData, expiration).Err()
}

func (r *RedisSessionStorage) GetSession(sessionID string) (map[string]interface{}, error) {
	data, err := r.client.Get(r.ctx, "session:"+sessionID).Bytes()
	if err != nil {
		return nil, err
	}

	var sessionData map[string]interface{}
	err = json.Unmarshal(data, &sessionData)
	return sessionData, err
}

func (r *RedisSessionStorage) DeleteSession(sessionID string) error {
	return r.client.Del(r.ctx, "session:"+sessionID).Err()
}

func (r *RedisSessionStorage) Close() error {
	return r.client.Close()
}
