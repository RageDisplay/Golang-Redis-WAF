package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

type WAFProxy struct {
	target         *url.URL
	proxy          *httputil.ReverseProxy
	redisClient    *redis.Client
	analyzerClient *http.Client
	config         *AppConfig
}

type AppConfig struct {
	TargetURL      string `json:"target_url"`
	ListenPort     string `json:"listen_port"`
	AppPort        string `json:"app_port"`
	EnableSQLi     bool   `json:"enable_sqli"`
	EnableXSS      bool   `json:"enable_xss"`
	EnableCMDi     bool   `json:"enable_cmdi"`
	EnablePath     bool   `json:"enable_path"`
	EnableAnalyzer bool   `json:"enable_analyzer"`
}

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

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Threats   []string  `json:"threats"`
	Action    string    `json:"action"`
}

func NewWAFProxy(target string, redisAddr string) (*WAFProxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	p := &WAFProxy{
		target:         u,
		proxy:          httputil.NewSingleHostReverseProxy(u),
		redisClient:    rdb,
		analyzerClient: &http.Client{Timeout: 500 * time.Millisecond},
	}

	p.proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.Method == http.MethodPost || resp.Request.Method == http.MethodPut {
			resp.Header.Del("Content-Length")
		}
		return nil
	}

	originalDirector := p.proxy.Director
	p.proxy.Director = func(req *http.Request) {
		originalDirector(req)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return p, nil
}

func (p *WAFProxy) checkRequest(r *http.Request) (bool, []string) {
	var threats []string

	// Check URL and query params
	if threatsFound := p.checkPatterns(r.URL.String() + " " + r.URL.RawQuery); len(threatsFound) > 0 {
		threats = append(threats, threatsFound...)
	}

	// Check headers
	for name, values := range r.Header {
		for _, value := range values {
			if threatsFound := p.checkPatterns(name + ": " + value); len(threatsFound) > 0 {
				threats = append(threats, threatsFound...)
			}
		}
	}

	// Check body for POST/PUT
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return true, []string{"invalid request body"}
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if threatsFound := p.checkPatterns(string(bodyBytes)); len(threatsFound) > 0 {
			threats = append(threats, threatsFound...)
		}
	}

	return len(threats) > 0, threats
}

func (p *WAFProxy) checkPatterns(input string) []string {
	ctx := context.Background()
	var threats []string

	// Check all pattern categories
	categories := []struct {
		name    string
		enabled bool
		key     string
	}{
		{"sqli", p.config != nil && p.config.EnableSQLi, "waf:sqli"},
		{"xss", p.config != nil && p.config.EnableXSS, "waf:xss"},
		{"cmdi", p.config != nil && p.config.EnableCMDi, "waf:cmdi"},
		{"pathtraversal", p.config != nil && p.config.EnablePath, "waf:pathtraversal"},
	}

	for _, category := range categories {
		if !category.enabled {
			continue
		}

		patterns, err := p.redisClient.SMembers(ctx, category.key).Result()
		if err != nil {
			log.Printf("Error getting patterns for %s: %v", category.name, err)
			continue
		}

		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("Error compiling pattern %s: %v", pattern, err)
				continue
			}

			if re.MatchString(input) {
				threats = append(threats, category.name+": "+pattern)
				// Update statistics
				p.updateStats(category.name)
			}
		}
	}

	return threats
}

func (p *WAFProxy) updateStats(threatType string) {
	ctx := context.Background()

	// Увеличиваем счетчик общего количества запросов
	p.redisClient.Incr(ctx, "waf:stats:total_requests")

	// Увеличиваем счетчик заблокированных запросов
	p.redisClient.Incr(ctx, "waf:stats:blocked_requests")

	// Увеличиваем счетчик для конкретного типа угроз
	p.redisClient.Incr(ctx, "waf:stats:threats:"+threatType)

	// Логируем блокировку
	logEntry := LogEntry{
		Timestamp: time.Now(),
		IP:        "127.0.0.1",
		Method:    "GET",
		URL:       "/",
		Threats:   []string{threatType},
		Action:    "block",
	}

	logData, _ := json.Marshal(logEntry)
	p.redisClient.LPush(ctx, "waf:logs", logData)
	// Ограничиваем список логов 1000 записями
	p.redisClient.LTrim(ctx, "waf:logs", 0, 999)
}

func (p *WAFProxy) analyzeRequest(r *http.Request) (*AnalysisResponse, error) {
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = strings.Join(values, ", ")
	}

	reqData := AnalysisRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: headers,
		Body:    string(bodyBytes),
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	analyzerURL := "http://analyzer:8083/analyze"
	if url := os.Getenv("ANALYZER_URL"); url != "" {
		analyzerURL = url
	}

	resp, err := p.analyzerClient.Post(analyzerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var analysisResp AnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&analysisResp); err != nil {
		return nil, err
	}

	return &analysisResp, nil
}

func (p *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// First check with fast pattern matching
	if isBlocked, threats := p.checkRequest(r); isBlocked {
		log.Printf("Request blocked by WAF. Threats: %v", threats)
		http.Error(w, "Request blocked by WAF", http.StatusForbidden)
		return
	}

	// Then perform deeper analysis if analyzer is enabled
	if p.config != nil && p.config.EnableAnalyzer {
		analysis, err := p.analyzeRequest(r)
		if err != nil {
			log.Printf("Analysis error: %v", err)
			// Continue with request if analysis fails
		} else if analysis.ThreatLevel > 5 { // Medium threat level
			log.Printf("Request blocked by analyzer. Threat level: %d", analysis.ThreatLevel)
			http.Error(w, "Request blocked by WAF analyzer", http.StatusForbidden)
			return
		}
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *WAFProxy) loadConfig() {
	ctx := context.Background()

	data, err := p.redisClient.Get(ctx, "waf:config").Result()
	if err != nil {
		log.Printf("Error loading config from Redis: %v", err)
		// Use default config if none exists
		p.config = &AppConfig{
			TargetURL:      "http://192.168.200.50:7000",
			ListenPort:     "8081",
			AppPort:        "7000",
			EnableSQLi:     true,
			EnableXSS:      true,
			EnableCMDi:     true,
			EnablePath:     true,
			EnableAnalyzer: true,
		}
		return
	}

	var config AppConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		log.Printf("Error parsing config: %v", err)
		return
	}

	p.config = &config

	// Update target URL if changed
	if config.TargetURL != "" && config.TargetURL != p.target.String() {
		newTarget, err := url.Parse(config.TargetURL)
		if err == nil {
			p.target = newTarget
			p.proxy = httputil.NewSingleHostReverseProxy(newTarget)
			log.Printf("Updated target URL to: %s", config.TargetURL)
		}
	}
}

func (p *WAFProxy) startConfigWatcher() {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			p.loadConfig()
		}
	}()
}

func main() {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "http://192.168.200.50:7000"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	proxy, err := NewWAFProxy(target, redisAddr)
	if err != nil {
		log.Fatal(err)
	}

	// Load initial configuration
	proxy.loadConfig()

	// Start configuration watcher
	proxy.startConfigWatcher()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("WAF Proxy started on :%s, protecting %s", port, target)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}
