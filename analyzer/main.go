package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

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

	// Dangerous methods
	if req.Method == "TRACE" || req.Method == "TRACK" {
		threatLevel += 10
		matches = append(matches, "dangerous_method:"+req.Method)
	}

	// Check headers for obvious attacks
	for name, value := range req.Headers {
		lowerValue := strings.ToLower(value)

		if containsSQLPatterns(lowerValue) && len(lowerValue) > 30 {
			threatLevel += 5
			matches = append(matches, "sql_in_header:"+name)
		}
	}

	// Check URL for explicit attacks
	urlLower := strings.ToLower(req.URL)
	if containsExplicitSQLPatterns(urlLower) {
		threatLevel += 8
		matches = append(matches, "explicit_sqli_in_url")
	}

	if containsExplicitXSSPatterns(urlLower) {
		threatLevel += 8
		matches = append(matches, "explicit_xss_in_url")
	}

	// Check body for large attacks
	if len(req.Body) > 500 {
		lowerBody := strings.ToLower(req.Body)

		if containsExplicitSQLPatterns(lowerBody) {
			threatLevel += 10
			matches = append(matches, "explicit_sqli_in_body")
		}

		if containsExplicitXSSPatterns(lowerBody) {
			threatLevel += 10
			matches = append(matches, "explicit_xss_in_body")
		}
	}

	// Higher threshold for blocking
	action := "allow"
	if threatLevel > 12 {
		action = "block"
	} else if threatLevel > 6 {
		action = "captcha"
	}

	return &AnalysisResponse{
		ThreatLevel: threatLevel,
		Matches:     matches,
		Action:      action,
	}
}

func containsSQLPatterns(input string) bool {
	patterns := []string{
		`union.*select`, `select.*from`, `insert.*into`, `delete.*from`,
		`drop.*table`, `update.*set`, `xp_cmdshell`, `waitfor.*delay`,
		`1=1`, `or.*=.*`, `and.*=.*`, `--`, `#`, `/\*`, `\*/`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+pattern, input); matched {
			return true
		}
	}
	return false
}

func containsExplicitSQLPatterns(input string) bool {
	patterns := []string{
		`union\s+select\s+null`, `xp_cmdshell`, `waitfor\s+delay`,
		`1=1--`, `or\s+1=1--`, `and\s+1=1--`,
		`information_schema\.`, `pg_catalog\.`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+pattern, input); matched {
			return true
		}
	}
	return false
}

func containsExplicitXSSPatterns(input string) bool {
	patterns := []string{
		`<script>alert\(`, `<script>confirm\(`, `<script>prompt\(`,
		`javascript:alert\(`, `javascript:confirm\(`, `javascript:prompt\(`,
		`onclick=alert\(`, `onload=alert\(`, `onerror=alert\(`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+pattern, input); matched {
			return true
		}
	}
	return false
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
