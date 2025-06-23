# Используем многоэтапную сборку
FROM golang:1.24.1-alpine as builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-proxy .

# Финальный образ
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/waf-proxy .

# Установка зависимостей для работы с SSL
RUN apk --no-cache add ca-certificates

EXPOSE 8081
CMD ["./waf-proxy"]