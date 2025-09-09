FROM golang:alpine AS builder

WORKDIR /build

COPY ./go.mod ./go.mod
COPY ./go.sum ./go.sum

RUN go mod download

COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./static ./static

RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go

FROM scratch AS app


WORKDIR /app

COPY --from=builder /build/main /app/main

CMD ["./main"]