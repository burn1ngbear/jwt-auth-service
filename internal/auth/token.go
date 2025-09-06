package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var accessSecret = []byte("access_secret_key")
var refreshSecret = []byte("refresh_secret_key")

type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func generateTokens(user User) (string, string, error) {
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

	refreshTokenExp := time.Now().Add(7 * 24 * time.Hour).Unix()
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     refreshTokenExp,
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
