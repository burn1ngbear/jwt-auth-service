FROM golang:1.21.6-alpine

WORKDIR /app

COPY ./src/app ./src/app

RUN go mod tidy

CMD ["go", "run", "./src/app/main.go"]