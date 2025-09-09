package auth

import (
	"encoding/json"
	"fmt"
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

// LoginHandler обрабатывает запросы на вход в систему
func LoginHandler(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	// w.Header().Set("Access-Control-Allow-Origin", "http://0.0.0.0:4444")

	// Устанавливаем ДВА токена в ответ
	// Первый токен - сессионный
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    fmt.Sprintf("sess_%d", time.Now().Unix()),
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Второй токен - для аутентификации
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    fmt.Sprintf("auth_%d", time.Now().UnixNano()),
		Path:     "/",
		Expires:  time.Now().Add(7 * 24 * time.Hour), // 7 дней
		HttpOnly: false,                              // Доступен через JavaScript
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Третий токен - дополнительный (опционально)
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    fmt.Sprintf("csrf_%x", time.Now().UnixNano()),
		Path:     "/",
		Expires:  time.Now().Add(2 * time.Hour), // 2 часа
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	// Возвращаем JSON ответ
	w.Header().Set("Content-Type", "application/json")
	response := fmt.Sprintf(`{
		"status": "success",
		"message": "Login successful. Two tokens set.",
		"timestamp": "%s",
		"cookies_received": {%s},
		"cookies_set": ["session_token", "auth_token", "csrf_token"]
		"accessToken": "%s",
		"refreshToken": "%s"
	}`, time.Now().Format(time.RFC3339), formatCookiesJSON(r), accessToken, refreshToken)

	fmt.Println("Response:", response) // Логируем ответ сервера
	w.Write([]byte(response))
}

// Вспомогательная функция для форматирования cookies в JSON
func formatCookiesJSON(r *http.Request) string {
	var result string
	first := true
	for _, cookie := range r.Cookies() {
		if !first {
			result += ","
		}
		result += fmt.Sprintf(`"%s": "%s"`, cookie.Name, cookie.Value)
		first = false
	}
	return result
}

// LogoutHandler обрабатывает запросы на выход из системы
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refreshToken"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	delete(refreshTokens, request.RefreshToken)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("✅ Вы успешно вышли из системы"))
}

// RefreshHandler обрабатывает запросы на обновление токенов
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refreshToken"`
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

	user, _ := user.GetUserByUsername(claims.Username)

	accessToken, err := GenerateAccessToken(user.ID, user.Username, user.Email, user.Role, clientIP, userAgent)

	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	refreshTokens[newRefreshToken] = time.Now().Add(24 * time.Hour)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"accessToken":  accessToken,
		"refreshToken": newRefreshToken,
	})
}

func UserHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString := authHeader[len("Bearer "):]

	claims, err := ValidateToken(tokenString)
	if err != nil {
		http.Error(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"id":       claims.UserID,
		"username": claims.Username,
		"email":    claims.Email,
		"role":     claims.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
