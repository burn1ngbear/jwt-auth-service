package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// Секретные ключи
var accessSecret = []byte("access_secret_key")
var refreshSecret = []byte("refresh_secret_key")

// Настройка Redis
var rdb = redis.NewClient(&redis.Options{
	Addr: "localhost:6380", // Адрес Redis, например, Docker: "redis:6379"
})

// Контекст для работы с Redis
var ctx = context.Background()

// Структура пользователя
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Генерация access и refresh токенов
func generateTokens(user User) (string, string, error) {
	// Генерация Access-токена (15 минут)
	accessTokenExp := time.Now().Add(15 * time.Minute).Unix()
	accessClaims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
		"exp":     accessTokenExp,
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(accessSecret)
	if err != nil {
		return "", "", err
	}

	// Генерация Refresh-токена (7 дней)
	refreshTokenExp := time.Now().Add(7 * 24 * time.Hour).Unix()
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     refreshTokenExp,
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	// Сохранение токенов в Redis с указанием времени жизни (TTL)
	err = rdb.Set(ctx, accessToken, user.ID, 15*time.Minute).Err()
	if err != nil {
		return "", "", err
	}

	err = rdb.Set(ctx, refreshToken, user.ID, 7*24*time.Hour).Err()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// Проверка Refresh-токена и выдача новых токенов
func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Получение refresh токена из тела запроса
	var requestBody map[string]string
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil || requestBody["refresh_token"] == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	refreshToken := requestBody["refresh_token"]

	// Проверяем Refresh-токен
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return refreshSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Проверяем наличие токена в Redis
	_, err = rdb.Get(ctx, refreshToken).Result()
	if err == redis.Nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Failed to check token in Redis", http.StatusInternalServerError)
		return
	}

	// Генерация новых токенов
	claims := token.Claims.(jwt.MapClaims)
	user := User{
		ID:    int(claims["user_id"].(float64)),
		Email: string(claims["email"].(string)),
		Name:  string(claims["name"].(string)),
	}
	accessToken, newRefreshToken, err := generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to create new tokens", http.StatusInternalServerError)
		return
	}

	// Удаляем старый Refresh-токен из Redis (чтобы он больше не использовался)
	rdb.Del(ctx, refreshToken)

	// Возвращаем новые токены
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

// Проверка Access токена
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Заголовок Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}
	accessToken := authHeader[len("Bearer "):]

	// Проверяем токен
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return accessSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Проверяем наличие токена в Redis
	_, err = rdb.Get(ctx, accessToken).Result()
	if err == redis.Nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Failed to check token in Redis", http.StatusInternalServerError)
		return
	}

	// Возвращаем информацию о пользователе
	claims := token.Claims.(jwt.MapClaims)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": claims["user_id"],
		"email":   claims["email"],
		"name":    claims["name"],
	})
}

// Создание новых токенов
func createTokenHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to create tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) <= len("Bearer ") {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		accessToken := authHeader[len("Bearer "):]
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return accessSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "claims", token.Claims.(jwt.MapClaims)))
		next(w, r)
	}
}

func main() {
	// Роуты
	http.HandleFunc("/create-token", createTokenHandler)   // Создание токенов
	http.HandleFunc("/refresh-token", refreshTokenHandler) // Обновление токенов
	http.HandleFunc("/get-user", withAuth(getUserHandler)) // Проверка Access токена

	// Запуск сервера
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
