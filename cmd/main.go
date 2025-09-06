package main

import (
	"log"
	"net/http"

	"github.com/burn1ngbear/jwt-auth-service/internal/auth/handler"
	"github.com/burn1ngbear/jwt-auth-service/internal/auth/middleware"
)

func main() {
	// Register handlers
	http.Handle("/login", middleware.RequirePOST(http.HandlerFunc(handler.LoginHandler)))
	http.Handle("/logout", middleware.RequirePOST(http.HandlerFunc(handler.LogoutHandler)))
	http.Handle("/refresh", middleware.RequirePOST(http.HandlerFunc(handler.RefreshHandler)))
	http.Handle("/user/me", middleware.RequireAuth(http.HandlerFunc(handler.UserHandler)))

	// Start the server
	log.Println("🚀 Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
