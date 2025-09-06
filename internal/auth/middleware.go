package auth

import (
	"net/http"
	"strings"

	"github.com/burn1ngbear/jwt-auth-service/internal/utils"
	"github.com/golang-jwt/jwt/v5"
)

// Middleware for checking the request method
func RequirePOST(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// Middleware for checking JWT token and client data
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
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

		// Check IP and User-Agent match
		currentIP := utils.GetClientIP(r)
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
