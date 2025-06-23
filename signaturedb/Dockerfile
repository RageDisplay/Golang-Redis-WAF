FROM golang:1.24.1-alpine as builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o signaturedb .

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/signaturedb .

EXPOSE 8082
CMD ["./signaturedb"]