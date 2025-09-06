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
	jwtSecret = []byte("your-secret-key")
)

// User структура для представления пользователя
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// Claims структура для хранения данных в JWT
type Claims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ClientIP  string `json:"client_ip"`  // IP клиента
	UserAgent string `json:"user_agent"` // User-Agent клиента
	jwt.RegisteredClaims
}

// Временное хранилище пользователей
var users = map[string]User{
	"testuser": {
		ID:       1,
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
		Role:     "user",
	},
	"admin": {
		ID:       2,
		Username: "admin",
		Password: "adminpass",
		Email:    "admin@example.com",
		Role:     "admin",
	},
}

// Временное хранилище для рефреш-токенов
var refreshTokens = make(map[string]time.Time)

func main() {
	// Регистрируем обработчики
	http.Handle("/login", requirePOST(http.HandlerFunc(loginHandler)))
	http.Handle("/logout", requirePOST(http.HandlerFunc(logoutHandler)))
	http.Handle("/refresh", requirePOST(http.HandlerFunc(refreshHandler)))
	http.Handle("/user/me", requireAuth(http.HandlerFunc(userHandler)))

	// Запускаем сервер
	log.Println("🚀 Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

// Middleware для проверки JWT токена и соответствия клиентских данных
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

		// Проверяем соответствие IP и User-Agent
		currentIP := getClientIP(r)
		currentUserAgent := r.UserAgent()

		if claims.ClientIP != currentIP {
			http.Error(w, "Несоответствие IP адреса", http.StatusUnauthorized)
			return
		}

		if claims.UserAgent != currentUserAgent {
			http.Error(w, "Несоответствие User-Agent", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Функция для получения реального IP клиента
func getClientIP(r *http.Request) string {
	// Пытаемся получить IP из заголовков (если за прокси)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Если заголовков нет, используем RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Обработчик для /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Проверяем учетные данные
	user, exists := users[creds.Username]
	if !exists || user.Password != creds.Password {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	// Получаем данные о клиенте
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()

	// Создаем access токен с данными о клиенте
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "go-jwt-server",
		},
	})

	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Создаем refresh токен (без данных о клиенте)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "go-jwt-server",
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
		"client_ip":     clientIP,
		"user_agent":    userAgent,
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

	// Получаем текущие данные о клиенте
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()

	// Создаем новую пару токенов
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:    claims.UserID,
		Username:  claims.Username,
		Email:     claims.Email,
		Role:      claims.Role,
		ClientIP:  clientIP,
		UserAgent: userAgent,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "go-jwt-server",
		},
	})

	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Создаем новый refresh токен
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:   claims.UserID,
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "go-jwt-server",
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
		"client_ip":     clientIP,
		"user_agent":    userAgent,
	})
}

// Обработчик для /user/me
func userHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Получаем claims из токена
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	// Возвращаем данные пользователя из токена
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":    claims.UserID,
		"username":   claims.Username,
		"email":      claims.Email,
		"role":       claims.Role,
		"client_ip":  claims.ClientIP,
		"user_agent": claims.UserAgent,
	})
}
