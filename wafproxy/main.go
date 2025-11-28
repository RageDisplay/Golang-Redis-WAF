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
	TargetURL  string `json:"target_url"`
	ListenPort string `json:"listen_port"`
	EnableSQLi bool   `json:"enable_sqli"`
	EnableXSS  bool   `json:"enable_xss"`
	EnableCMDi bool   `json:"enable_cmdi"`
	EnablePath bool   `json:"enable_path"`
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
		Password: "",
		DB:       0,
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

	// Check URL and query params - ДЕКОДИРУЕМ URL
	fullURL := r.URL.String() + " " + r.URL.RawQuery
	decodedURL, _ := url.QueryUnescape(fullURL)
	log.Printf("Checking URL (decoded): %s", decodedURL)

	if threatsFound := p.checkPatterns(decodedURL, "url"); len(threatsFound) > 0 {
		threats = append(threats, threatsFound...)
	}

	// Check headers - ТОЛЬКО ДЛЯ ОПАСНЫХ ЗАГОЛОВКОВ
	for name, values := range r.Header {
		// Проверяем только подозрительные заголовки
		if p.isSuspiciousHeader(name) {
			for _, value := range values {
				if threatsFound := p.checkPatterns(name+": "+value, "header"); len(threatsFound) > 0 {
					threats = append(threats, threatsFound...)
				}
			}
		}
	}

	// Check body for POST/PUT - ДЕКОДИРУЕМ FORM DATA
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return true, []string{"invalid request body"}
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		bodyStr := string(bodyBytes)

		// Если это form data, декодируем её
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			decodedBody, _ := url.QueryUnescape(bodyStr)
			log.Printf("Checking body (decoded): %s", decodedBody)
			if threatsFound := p.checkPatterns(decodedBody, "body"); len(threatsFound) > 0 {
				threats = append(threats, threatsFound...)
			}
		} else {
			log.Printf("Checking body: %s", bodyStr)
			if threatsFound := p.checkPatterns(bodyStr, "body"); len(threatsFound) > 0 {
				threats = append(threats, threatsFound...)
			}
		}
	}

	log.Printf("Total threats found: %d", len(threats))
	return len(threats) > 0, threats
}

func (p *WAFProxy) isSuspiciousHeader(name string) bool {
	// Проверяем только потенциально опасные заголовки
	suspiciousHeaders := []string{
		"user-agent", "referer", "origin", "cookie",
		"x-forwarded-for", "x-real-ip", "authorization",
	}

	nameLower := strings.ToLower(name)
	for _, header := range suspiciousHeaders {
		if strings.Contains(nameLower, header) {
			return true
		}
	}
	return false
}

func (p *WAFProxy) checkPatterns(input, inputType string) []string {
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

			matches := re.FindStringSubmatch(input)
			if matches != nil {
				log.Printf("PATTERN MATCHED! Category: %s, Pattern: %s, Input: %s",
					category.name, pattern, input)

				// False positive проверки
				if p.isFalsePositive(input, category.name, pattern, inputType) {
					log.Printf("False positive, skipping")
					continue
				}
				threats = append(threats, category.name+": "+pattern)
				p.updateStats(category.name)
			}
		}
	}

	return threats
}

func (p *WAFProxy) isFalsePositive(input, category, pattern, inputType string) bool {
	inputLower := strings.ToLower(input)

	// Для SQLi: разрешаем простые параметры в URL
	if category == "sqli" && inputType == "url" {
		// Разрешаем очень короткие безопасные параметры
		if len(input) < 10 && regexp.MustCompile(`^[a-z0-9=&?\-_\.]+$`).MatchString(inputLower) {
			return true
		}
		// Разрешаем обычные параметры типа id=123
		if regexp.MustCompile(`^(id|name|page|size|search|q)=[a-z0-9]+$`).MatchString(inputLower) {
			return true
		}
	}

	// Для Command Injection в заголовках: игнорируем quality values (;q=0.9)
	if category == "cmdi" && inputType == "header" {
		if strings.Contains(inputLower, ";q=") {
			return true
		}
	}

	return false
}

func (p *WAFProxy) updateStats(threatType string) {
	ctx := context.Background()

	p.redisClient.Incr(ctx, "waf:stats:total_requests")
	p.redisClient.Incr(ctx, "waf:stats:blocked_requests")
	p.redisClient.Incr(ctx, "waf:stats:threats:"+threatType)

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
	p.redisClient.LTrim(ctx, "waf:logs", 0, 999)
}

func (p *WAFProxy) updateTotalRequests() {
	ctx := context.Background()
	p.redisClient.Incr(ctx, "waf:stats:total_requests")
}

func (p *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.updateTotalRequests()

	log.Printf("=== NEW REQUEST ===")
	log.Printf("Method: %s, URL: %s", r.Method, r.URL.String())

	// Check with pattern matching
	if isBlocked, threats := p.checkRequest(r); isBlocked {
		log.Printf("Request blocked by WAF. Threats: %v", threats)
		http.Error(w, "Request blocked by WAF", http.StatusForbidden)
		return
	}

	log.Printf("Request allowed, proxying to target")
	p.proxy.ServeHTTP(w, r)
}

func (p *WAFProxy) loadConfig() {
	ctx := context.Background()

	data, err := p.redisClient.Get(ctx, "waf:config").Result()
	if err != nil {
		log.Printf("Error loading config from Redis: %v", err)
		p.config = &AppConfig{
			TargetURL:  "http://192.168.200.50:7000",
			ListenPort: "8081",
			EnableSQLi: true,
			EnableXSS:  true,
			EnableCMDi: true,
			EnablePath: true,
		}
		return
	}

	var config AppConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		log.Printf("Error parsing config: %v", err)
		return
	}

	p.config = &config
	log.Printf("Loaded config: SQLi=%t, XSS=%t, CMDi=%t, Path=%t",
		config.EnableSQLi, config.EnableXSS, config.EnableCMDi, config.EnablePath)

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

	proxy.loadConfig()
	proxy.startConfigWatcher()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("WAF Proxy started on :%s, protecting %s", port, target)
	log.Fatal(http.ListenAndServe(":"+port, proxy))
}
