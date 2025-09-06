package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/burn1ngbear/jwt-auth-service/internal/user"
	"github.com/burn1ngbear/jwt-auth-service/internal/utils"

	"github.com/golang-jwt/jwt/v5"
)

// UserCredentials структура для представления учетных данных пользователя
type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginHandler обрабатывает запросы на вход в систему
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds UserCredentials

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	user, exists := user.GetUserByUsername(creds.Username)
	if !exists || user.Password != creds.Password {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	clientIP := utils.GetClientIP(r)
	userAgent := r.UserAgent()

	accessToken, err := GenerateAccessToken(user.ID, user.Username, user.Email, user.Role, clientIP, userAgent)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	refreshToken, err := GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	refreshTokens[refreshToken] = time.Now().Add(24 * time.Hour)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"client_ip":     clientIP,
		"user_agent":    userAgent,
	})
}

// logoutHandler обрабатывает запросы на выход из системы
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	delete(refreshTokens, request.RefreshToken)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("✅ Вы успешно вышли из системы"))
}

// refreshHandler обрабатывает запросы на обновление токенов
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(request.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Неверный refresh токен", http.StatusUnauthorized)
		return
	}

	if expTime, exists := refreshTokens[request.RefreshToken]; !exists || time.Now().After(expTime) {
		http.Error(w, "Refresh токен истек или недействителен", http.StatusUnauthorized)
		return
	}

	delete(refreshTokens, request.RefreshToken)

	clientIP := utils.GetClientIP(r)
	userAgent := r.UserAgent()

	accessToken, err := GenerateAccessToken(claims.UserID, claims.Username, claims.Email, claims.Role, clientIP, userAgent)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := GenerateRefreshToken(claims.UserID, claims.Username)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	refreshTokens[newRefreshToken] = time.Now().Add(24 * time.Hour)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"client_ip":     clientIP,
		"user_agent":    userAgent,
	})
}
