package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Секреты для подписи токенов
var accessSecret = []byte("access_secret_key")
var refreshSecret = []byte("refresh_secret_key")

// Структура пользователя
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Глобальная "имитация базы данных" для хранения refresh-токенов
var refreshStore = map[string]User{}

// Создание access токена (15 минут) и refresh токена (7 дней)
func generateTokens(user User) (accessToken, refreshToken string, err error) {
	// Access токен с коротким сроком действия
	accessClaims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}
	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(accessSecret)
	if err != nil {
		return "", "", err
	}

	// Refresh токен с длинным сроком действия
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	// Сохраняем refresh токен в "хранилище"
	refreshStore[refreshToken] = user

	return accessToken, refreshToken, nil
}

// Handler для создания токенов
func createTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Читаем данные пользователя из тела запроса
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Генерируем токены
	accessToken, refreshToken, err := generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Возвращаем токены
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Handler для обновления токенов по refresh токену
func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем refresh токен из JSON тела запроса
	var requestBody map[string]string
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil || requestBody["refresh_token"] == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	refreshToken := requestBody["refresh_token"]

	// Проверяем refresh токен
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

	// Проверяем, что токен есть в нашем "хранилище"
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid refresh token claims", http.StatusUnauthorized)
		return
	}

	user, ok := refreshStore[refreshToken]
	if !ok {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	// Генерируем новый access и refresh токены
	accessToken, newRefreshToken, err := generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Обновляем refresh токен в хранилище
	delete(refreshStore, refreshToken)   // Удаляем старый токен
	refreshStore[newRefreshToken] = user // Сохраняем новый

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

// Handler для проверки access токена
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем access токен из заголовка Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[len("Bearer "):]

	// Разбираем access токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return accessSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired access token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Failed to parse token claims", http.StatusUnauthorized)
		return
	}

	// Возвращаем данные пользователя
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": claims["user_id"],
		"email":   claims["email"],
		"name":    claims["name"],
	})
}

func main() {
	http.HandleFunc("/create-token", createTokenHandler)   // Выдача токенов
	http.HandleFunc("/refresh-token", refreshTokenHandler) // Обновление токенов
	http.HandleFunc("/get-user", getUserHandler)           // Проверка access токена

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
