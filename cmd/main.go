package main

import (
	"log"
	"net/http"

	"github.com/burn1ngbear/jwt-auth-service/internal/auth"
	"github.com/burn1ngbear/jwt-auth-service/internal/auth20"
)

// docker-compose.yaml -> app -> volumes
var fileFolder string = "/var/www/html"

func main() {
	// Обработчик для главной страницы
	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	// Формируем абсолютный путь к файлу
	// 	indexPath := filepath.Join(fileFolder, "index.html")
	// 	http.ServeFile(w, r, indexPath) // Используем абсолютный путь
	// })

	// Register handlers
	http.Handle("/login", auth.RequirePOST(http.HandlerFunc(auth.LoginHandler)))
	http.Handle("/logout", auth.RequirePOST(http.HandlerFunc(auth.LogoutHandler)))
	http.Handle("/refresh", auth.RequirePOST(http.HandlerFunc(auth.RefreshHandler)))
	http.Handle("/user/me", auth.RequireAuth(http.HandlerFunc(auth.UserHandler)))

	auth20.InitRedis()

	http.Handle("/auth/external-service", http.HandlerFunc(auth20.ExternalService))
	http.Handle("/auth/returnTo/", http.HandlerFunc(auth20.ReturnTo))

	// Start the server
	log.Println("🚀 Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
