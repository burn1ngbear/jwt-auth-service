package auth20

import (
	"context"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client
var ctx = context.Background()

// TODO: Размернуть Redis в контейнере.
func InitRedis() {
	// TODO: Вынести в конфиг.
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Адрес Redis-сервера
		Password: "",               // Пароль (если есть)
		DB:       0,                // Номер базы данных
	})

	// Проверка подключения
	_, err := RedisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Ошибка подключения к Redis: %v", err)
	}
	fmt.Println("Успешное подключение к Redis")
}
