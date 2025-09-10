package auth20

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/burn1ngbear/jwt-auth-service/internal/utils"
	"github.com/google/uuid"
)

// Записывает запрос на авторизацию в кеш для индетификации callback запроса и редиректит на сторонний сервис авторизации.
func ExternalService(w http.ResponseWriter, r *http.Request) {
	// нужно трекать что пользователь авторизуется.
	uuidValue := uuid.New().String()
	// Редирект на новый URL с кодом 301 (Moved Permanently)
	redirectTo := utils.GetLinkToExternalService(uuidValue)
	http.Redirect(w, r, redirectTo, http.StatusMovedPermanently)
}

func ReturnTo(w http.ResponseWriter, r *http.Request) {
	// Извлекаем UUID из пути
	uuidValue := strings.TrimPrefix(r.URL.Path, "/auth/returnTo/")

	if uuidValue == "" {
		http.Error(w, "UUID required", http.StatusBadRequest)
		return
	}

	// Теперь у вас есть uuidValue для использования
	fmt.Printf("UUID: %s\n", uuidValue)
}
