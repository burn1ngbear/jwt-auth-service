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
	// Мы должны получить адрес на который должны вернуть пользователя
	// 		после автризации через сторонний сервис в func ReturnTo.

	// нужно трекать что пользователь авторизуется.
	uuidValue := uuid.New().String()
	// Записать uuid и адрес в хранилище.

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

	// TODO:
	//  - Проверка что в хварилище есть UUID
	//  - Делаем запрос на сторонний сервис авторзации для подтверждения данных
	// 		из-за того что callback может приходить с разных адресов
	//		а адрес хранилища данных один.
	//  - Создаём сущность (если не было) по полученным данным, записываем в COOKIE
	// 		запроса accessToken refreshToken и редиректим на разранее подготовленную страницу.
}
