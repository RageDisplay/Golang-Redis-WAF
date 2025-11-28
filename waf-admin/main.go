package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

// Функции для шаблонов
var templateFuncs = template.FuncMap{
	"percent": func(part, total int64) string {
		if total == 0 {
			return "0.00"
		}
		return strconv.FormatFloat(float64(part)/float64(total)*100, 'f', 2, 64)
	},
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

type Stats struct {
	TotalRequests   int64            `json:"total_requests"`
	BlockedRequests int64            `json:"blocked_requests"`
	ThreatsByType   map[string]int64 `json:"threats_by_type"`
	LastUpdated     time.Time        `json:"last_updated"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Threats   []string  `json:"threats"`
	Action    string    `json:"action"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	// Инициализация Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	rdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})

	// Инициализация默认配置
	initDefaultConfig()

	r := mux.NewRouter()

	// Статические файлы
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// API маршруты
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/config", getConfigHandler).Methods("GET")
	api.HandleFunc("/config", updateConfigHandler).Methods("POST")
	api.HandleFunc("/stats", getStatsHandler).Methods("GET")
	api.HandleFunc("/logs", getLogsHandler).Methods("GET")
	api.HandleFunc("/ws", websocketHandler)

	// Веб-маршруты
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/config", configHandler)
	r.HandleFunc("/logs", logsHandler)
	r.HandleFunc("/stats", statsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("WAF Admin started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func initDefaultConfig() {
	// Проверяем, есть ли конфигурация в Redis
	exists, err := rdb.Exists(ctx, "waf:config").Result()
	if err != nil {
		log.Printf("Error checking config: %v", err)
		return
	}

	if exists == 0 {
		config := AppConfig{
			TargetURL:      "http://192.168.200.50:7000",
			ListenPort:     "8081",
			AppPort:        "7000",
			EnableSQLi:     true,
			EnableXSS:      true,
			EnableCMDi:     true,
			EnablePath:     true,
			EnableAnalyzer: true,
		}
		saveConfig(config)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("index.html").Funcs(templateFuncs).ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	config := getConfig()
	stats := getStats()

	data := struct {
		Config AppConfig
		Stats  Stats
	}{
		Config: config,
		Stats:  stats,
	}

	tmpl.Execute(w, data)
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/config.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	config := getConfig()
	tmpl.Execute(w, config)
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/logs.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/stats.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats := getStats()
	tmpl.Execute(w, stats)
}

func getConfigHandler(w http.ResponseWriter, r *http.Request) {
	config := getConfig()
	json.NewEncoder(w).Encode(config)
}

func updateConfigHandler(w http.ResponseWriter, r *http.Request) {
	var config AppConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	saveConfig(config)

	// Обновляем модули защиты в Redis
	updateProtectionModules(config)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func getStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := getStats()
	json.NewEncoder(w).Encode(stats)
}

func getLogsHandler(w http.ResponseWriter, r *http.Request) {
	logs := getRecentLogs(100)
	json.NewEncoder(w).Encode(logs)
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Отправляем обновления статистики каждые 5 секунд
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := getStats()
			if err := conn.WriteJSON(stats); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func getConfig() AppConfig {
	data, err := rdb.Get(ctx, "waf:config").Result()
	if err != nil {
		return AppConfig{}
	}

	var config AppConfig
	json.Unmarshal([]byte(data), &config)
	return config
}

func saveConfig(config AppConfig) {
	data, _ := json.Marshal(config)
	rdb.Set(ctx, "waf:config", data, 0)
}

func getStats() Stats {
	total, _ := rdb.Get(ctx, "waf:stats:total_requests").Int64()
	blocked, _ := rdb.Get(ctx, "waf:stats:blocked_requests").Int64()

	threats := make(map[string]int64)
	threats["sqli"], _ = rdb.Get(ctx, "waf:stats:threats:sqli").Int64()
	threats["xss"], _ = rdb.Get(ctx, "waf:stats:threats:xss").Int64()
	threats["cmdi"], _ = rdb.Get(ctx, "waf:stats:threats:cmdi").Int64()
	threats["pathtraversal"], _ = rdb.Get(ctx, "waf:stats:threats:pathtraversal").Int64()

	return Stats{
		TotalRequests:   total,
		BlockedRequests: blocked,
		ThreatsByType:   threats,
		LastUpdated:     time.Now(),
	}
}

func getRecentLogs(count int64) []LogEntry {
	logs, err := rdb.LRange(ctx, "waf:logs", 0, count-1).Result()
	if err != nil {
		return []LogEntry{}
	}

	var logEntries []LogEntry
	for _, logStr := range logs {
		var entry LogEntry
		if json.Unmarshal([]byte(logStr), &entry) == nil {
			logEntries = append(logEntries, entry)
		}
	}

	return logEntries
}

func updateProtectionModules(config AppConfig) {
	// Обновляем статус модулей в Redis
	modules := map[string]bool{
		"sqli":          config.EnableSQLi,
		"xss":           config.EnableXSS,
		"cmdi":          config.EnableCMDi,
		"pathtraversal": config.EnablePath,
	}

	for module, enabled := range modules {
		status := "0"
		if enabled {
			status = "1"
		}
		rdb.Set(ctx, "waf:module:"+module, status, 0)
	}
}
