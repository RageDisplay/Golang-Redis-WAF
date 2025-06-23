package main

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	limits   map[string][]time.Time
	capacity int
	interval time.Duration
}

func NewRateLimiter(capacity int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		limits:   make(map[string][]time.Time),
		capacity: capacity,
		interval: interval,
	}
}

func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	timestamps, exists := r.limits[ip]

	var validTimestamps []time.Time
	for _, ts := range timestamps {
		if now.Sub(ts) < r.interval {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	if exists && len(validTimestamps) >= r.capacity {
		return false
	}

	validTimestamps = append(validTimestamps, now)
	r.limits[ip] = validTimestamps
	return true
}
