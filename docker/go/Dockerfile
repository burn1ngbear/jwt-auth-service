FROM golang:1.21-alpine

WORKDIR /app

# Установка зависимостей
RUN apk add --no-cache git

# Копируем файлы модулей и загружаем зависимости
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN go build -o main .

# Экспортируем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./main"]