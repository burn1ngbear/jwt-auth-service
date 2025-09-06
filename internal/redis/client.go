package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

// InitializeRedis initializes the Redis client.
func InitializeRedis(addr string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: addr,
	})
}

// Set stores a key-value pair in Redis with an expiration time.
func Set(key string, value interface{}, expiration time.Duration) error {
	return rdb.Set(ctx, key, value, expiration).Err()
}

// Get retrieves a value from Redis by key.
func Get(key string) (string, error) {
	val, err := rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

// Del deletes a key from Redis.
func Del(key string) error {
	return rdb.Del(ctx, key).Err()
}
