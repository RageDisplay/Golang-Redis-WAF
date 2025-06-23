package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Определяем структуры запроса и ответа
type AnalysisRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type AnalysisResponse struct {
	ThreatLevel int      `json:"threat_level"`
	Matches     []string `json:"matches,omitempty"`
	Action      string   `json:"action"`
}

type Analyzer struct {
	rateLimiter *RateLimiter
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		rateLimiter: NewRateLimiter(100, time.Minute),
	}
}

func (a *Analyzer) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var req AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !a.rateLimiter.Allow(clientIP) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	analysis := a.analyzeRequest(&req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

func (a *Analyzer) analyzeRequest(req *AnalysisRequest) *AnalysisResponse {
	threatLevel := 0
	var matches []string

	// Проверка методов
	if req.Method == "TRACE" || req.Method == "TRACK" {
		threatLevel += 3
		matches = append(matches, "suspicious_method:"+req.Method)
	}

	// Проверка заголовков
	for name, value := range req.Headers {
		if strings.Contains(strings.ToLower(name), "x-forwarded") {
			threatLevel += 1
		}
		if strings.Contains(strings.ToLower(value), "select") {
			threatLevel += 2
		}
	}

	// Проверка URL
	if len(req.URL) > 1024 {
		threatLevel += 2
		matches = append(matches, "long_url")
	}

	// Проверка тела запроса
	lowerBody := strings.ToLower(req.Body)
	if strings.Contains(lowerBody, "<script") {
		threatLevel += 5
		matches = append(matches, "xss_pattern")
	}

	if strings.Contains(lowerBody, "union select") {
		threatLevel += 8
		matches = append(matches, "sqli_pattern")
	}

	// Определение действия
	action := "allow"
	if threatLevel > 7 {
		action = "block"
	} else if threatLevel > 4 {
		action = "captcha"
	}

	return &AnalysisResponse{
		ThreatLevel: threatLevel,
		Matches:     matches,
		Action:      action,
	}
}

func (a *Analyzer) Start(addr string) {
	http.HandleFunc("/analyze", a.analyzeHandler)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Analyzer started on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	analyzer := NewAnalyzer()
	analyzer.Start(":" + port)
}
