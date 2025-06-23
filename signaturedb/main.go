package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

type SignatureServer struct {
	redisClient *redis.Client
}

func NewSignatureServer(redisAddr string) *SignatureServer {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	return &SignatureServer{
		redisClient: rdb,
	}
}

func (s *SignatureServer) LoadInitialSignatures() {
	ctx := context.Background()

	// SQL Injection patterns
	sqlPatterns := []string{
		`(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bdelete\b.*\bfrom\b)`,
		`(?i)(\bdrop\b|\bupdate\b.*\bset\b|'|--|\bwaitfor\b.*\bdelay\b)`,
		`(?i)(\bexec\b|\bxp_cmdshell\b|\btruncate\b|\bdeclare\b)`,
		`(?i)(\bor\b.*\b\d+\s*=\s*\d+)`,
	}

	// XSS patterns
	xssPatterns := []string{
		`(?i)(<script.*?>|javascript:|on\w+\s*=)`,
		`(?i)(<\w+.*?\s+on\w+\s*=|alert\(|document\.cookie)`,
		`(?i)(eval\(|window\.location|vbscript:)`,
	}

	// Command Injection
	cmdPatterns := []string{
		`(?i)(;|\||&)\s*(pwd|ls|cat|echo|rm|mv|cp|chmod|wget|curl)`,
		`\b(rm\s+-rf|chmod\s+777)\b`,
	}

	// Path Traversal
	pathPatterns := []string{
		`(\.\./|\.\.\\)`,
		`(/etc/passwd|/bin/sh|/etc/shadow)`,
	}

	// Add all patterns to Redis
	s.redisClient.SAdd(ctx, "waf:sqli", sqlPatterns)
	s.redisClient.SAdd(ctx, "waf:xss", xssPatterns)
	s.redisClient.SAdd(ctx, "waf:cmdi", cmdPatterns)
	s.redisClient.SAdd(ctx, "waf:pathtraversal", pathPatterns)
}

func (s *SignatureServer) Start(addr string) {
	r := mux.NewRouter()

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	log.Printf("Signature Server started on %s", addr)

	<-done
	log.Println("Server stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exited properly")
}

func main() {
	redisAddr := "localhost:6379"
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		redisAddr = addr
	}

	server := NewSignatureServer(redisAddr)
	server.LoadInitialSignatures()

	server.Start(":8082")
}
