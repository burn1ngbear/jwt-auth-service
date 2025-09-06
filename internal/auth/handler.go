package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

var rdb *redis.Client

func InitRedis(client *redis.Client) {
	rdb = client
}

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

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody map[string]string
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil || requestBody["refresh_token"] == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	refreshToken := requestBody["refresh_token"]

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

	_, err = rdb.Get(ctx, refreshToken).Result()
	if err == redis.Nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Failed to check token in Redis", http.StatusInternalServerError)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	user := User{
		ID: int(claims["user_id"].(float64)),
	}
	accessToken, newRefreshToken, err := generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to create new tokens", http.StatusInternalServerError)
		return
	}

	rdb.Del(ctx, refreshToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}
