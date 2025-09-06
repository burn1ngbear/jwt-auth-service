package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret = []byte("your-secret-key") // В продакшене используйте безопасное хранилище секретов
)

// Claims структура для хранения данных в JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// User структура для представления пользователя
type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // В реальном приложении храните хеш пароля
}

// Временное хранилище для рефреш-токенов (в реальном приложении используйте БД)
var refreshTokens = make(map[string]time.Time)

func main() {
	// Регистрируем обработчики
	// Регистрируем middleware для требуемых методов
	http.Handle("/login", requirePOST(http.HandlerFunc(loginHandler)))
	http.Handle("/logout", requirePOST(http.HandlerFunc(logoutHandler)))
	http.Handle("/refresh", requirePOST(http.HandlerFunc(refreshHandler)))
	http.Handle("/user/me", requireAuth(http.HandlerFunc(userHandler)))

	// Запуск HTTP-сервера на порту 8080
	port := ":8080"
	log.Printf("🔄 Запуск HTTP-сервера на http://localhost%s", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("❌ Ошибка при запуске сервера: %v", err)
	}
}

// Middleware для проверки метода запроса
func requirePOST(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// Middleware для проверки JWT токена
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Обработчик для /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь должна быть проверка учетных данных
	// Для примера используем фиксированные значения
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	if user.Username != "testuser" || user.Password != "testpass" {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	// Создаем access токен
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Создаем refresh токен
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Сохраняем refresh токен
	refreshTokens[refreshTokenString] = time.Now().Add(24 * time.Hour)

	// Возвращаем токены клиенту
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
	})
}

// Обработчик для /logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Удаляем refresh токен
	delete(refreshTokens, request.RefreshToken)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("✅ Вы успешно вышли из системы"))
}

// Обработчик для /refresh
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Проверяем валидность refresh токена
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(request.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Неверный refresh токен", http.StatusUnauthorized)
		return
	}

	// Проверяем, не истек ли срок действия refresh токена
	if expTime, exists := refreshTokens[request.RefreshToken]; !exists || time.Now().After(expTime) {
		http.Error(w, "Refresh токен истек или недействителен", http.StatusUnauthorized)
		return
	}

	// Удаляем старый refresh токен
	delete(refreshTokens, request.RefreshToken)

	// Создаем новую пару токенов
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Создаем новый refresh токен
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	newRefreshTokenString, err := newRefreshToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Сохраняем новый refresh токен
	refreshTokens[newRefreshTokenString] = time.Now().Add(24 * time.Hour)

	// Возвращаем новые токены клиенту
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": newRefreshTokenString,
	})
}

// Обработчик для /user/me
func userHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Извлекаем claims из контекста (в реальном приложении)
	// Здесь для простоты просто возвращаем фиктивные данные
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"role":     "user",
	})
}
