package main

import (
	"log"
	"net/http"

	"github.com/burn1ngbear/jwt-auth-service/internal/auth"
)

func main() {
	// Register handlers
	http.Handle("/login", auth.RequirePOST(http.HandlerFunc(auth.LoginHandler)))
	http.Handle("/logout", auth.RequirePOST(http.HandlerFunc(auth.LogoutHandler)))
	http.Handle("/refresh", auth.RequirePOST(http.HandlerFunc(auth.RefreshHandler)))
	http.Handle("/user/me", auth.RequireAuth(http.HandlerFunc(auth.UserHandler)))

	// Start the server

	log.Println("🚀 Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
