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

	// SQL Injection patterns - СТАНДАРТНЫЕ
	sqlPatterns := []string{
		`(?i)(union.*select|select.*from|insert.*into|delete.*from)`,
		`(?i)(drop.*table|update.*set|waitfor.*delay)`,
		`(?i)(exec|xp_cmdshell|truncate|declare)`,
		`(?i)(or.*\d+\s*=\s*\d+)`,
		`(--|#|\/\*)`,
	}

	// XSS patterns
	xssPatterns := []string{
		`(<script|javascript:|on\w+=)`,
		`(alert\(|document\.cookie|eval\()`,
		`(vbscript:|window\.location)`,
	}

	// Command Injection - ПРОСТЫЕ ПАТТЕРНЫ
	cmdPatterns := []string{
		`(\|.*whoami)`,
		`(;.*whoami)`,
		`(&.*whoami)`,
		`(\|.*pwd)`,
		`(;.*pwd)`,
		`(&.*pwd)`,
		`(\|.*ls)`,
		`(;.*ls)`,
		`(&.*ls)`,
		`(\|.*cat)`,
		`(;.*cat)`,
		`(&.*cat)`,
		`(\|.*rm)`,
		`(;.*rm)`,
		`(&.*rm)`,
		`(\|.*id)`,
		`(;.*id)`,
		`(&.*id)`,
		`(rm -rf)`,
		`(chmod 777)`,
	}

	// Path Traversal - ПРОСТЫЕ ПАТТЕРНЫ
	pathPatterns := []string{
		`(\.\.\/)`,
		`(\.\.\\)`,
		`(\/etc\/passwd)`,
		`(\/etc\/shadow)`,
		`(\/bin\/sh)`,
		`(\\windows\\system32)`,
	}

	// Clear existing patterns
	s.redisClient.Del(ctx, "waf:sqli", "waf:xss", "waf:cmdi", "waf:pathtraversal")

	// Add all patterns to Redis
	s.redisClient.SAdd(ctx, "waf:sqli", sqlPatterns)
	s.redisClient.SAdd(ctx, "waf:xss", xssPatterns)
	s.redisClient.SAdd(ctx, "waf:cmdi", cmdPatterns)
	s.redisClient.SAdd(ctx, "waf:pathtraversal", pathPatterns)

	log.Printf("Loaded %d SQLi patterns", len(sqlPatterns))
	log.Printf("Loaded %d XSS patterns", len(xssPatterns))
	log.Printf("Loaded %d CMDi patterns", len(cmdPatterns))
	log.Printf("Loaded %d Path Traversal patterns", len(pathPatterns))
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
