package main

import (
	"fmt"
	"log"
	"net/http"

	auth "github.com/burn1ngbear/jwt-auth-service/internal/auth"
	redis "github.com/burn1ngbear/jwt-auth-service/internal/redis"
)

func main() {
	// Initialize Redis client
	redis.Init()

	// Set up routes
	http.HandleFunc("/create-token", auth.CreateTokenHandler)        // Create tokens
	http.HandleFunc("/refresh-token", auth.RefreshTokenHandler)      // Refresh tokens
	http.HandleFunc("/get-user", auth.WithAuth(auth.GetUserHandler)) // Get user info

	// Start the server
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
