package auth20

import (
	"net/http"
	"strings"
	"time"

	"github.com/burn1ngbear/jwt-auth-service/internal/utils"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Записывает запрос на авторизацию в кеш для индетификации callback запроса и редиректит на сторонний сервис авторизации.
func ExternalService(w http.ResponseWriter, r *http.Request) {
	// Получение обратной ссылки для будущего возврата, после аутентификации.
	returnToURL := r.URL.Query().Get("returnTo")
	if returnToURL == "" {
		http.Error(w, "Parametr returnTo required", http.StatusBadRequest)
		return
	}

	// нужно трекать что пользователь авторизуется.
	uuidValue := uuid.New().String()

	// Сохранение в Redis с TTL 10 минут
	err := RedisClient.Set(ctx, uuidValue, returnToURL, 10*time.Minute).Err()
	if err != nil {
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	// Редирект на сервис аутентификации.
	redirectTo := utils.GetLinkToExternalService(uuidValue)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func ReturnTo(w http.ResponseWriter, r *http.Request) {
	// Извлекаем UUID из пути
	uuidValue := strings.TrimPrefix(r.URL.Path, "/auth/returnTo/")
	if uuidValue == "" {
		http.Error(w, "UUID required", http.StatusBadRequest)
		return
	}

	// Извлечение адреса возврата из Redis
	returnToURL, err := RedisClient.Get(ctx, uuidValue).Result()
	if err == redis.Nil {
		// TODO: редирект на base_domain
		http.Error(w, "Сессия не найдена или истекла", http.StatusBadRequest)
		return
	} else if err != nil {
		// TODO: редирект на base_domain
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	// Удаление UUID из Redis после использования (опционально)
	RedisClient.Del(ctx, uuidValue)

	http.Redirect(w, r, returnToURL, http.StatusFound)
}
