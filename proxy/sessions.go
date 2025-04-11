package proxy

import (
	"fmt"
	"sync"
	"time"
)

type CacheItem struct {
	Value      Provider
	Expiration time.Time // Changed from int64 to time.Time
}

type Sessions struct {
	rcache map[string]CacheItem
	mu     sync.RWMutex
}

func NewSession() *Sessions {
	return &Sessions{
		rcache: make(map[string]CacheItem),
	}
}

func (r *Sessions) Cached(request *Request) (Provider, bool) {
	r.mu.RLock() // Changed to RLock for read-only operation
	defer r.mu.RUnlock()

	value, ok := r.rcache[request.SessionID]
	if !ok {
		return nil, false
	}

	// Check if the session has expired
	if time.Now().After(value.Expiration) {
		return nil, false
	}
	r.RefreshSession(request.SessionID, request.SessionDuration)
	return value.Value, true
}

func (r *Sessions) Start(request *Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Calculate expiration time based on session duration in seconds
	fmt.Println(request.SessionDuration)
	expirationTime := time.Now().Add(time.Duration(request.SessionDuration))

	r.rcache[request.SessionID] = CacheItem{
		Value:      request.Provider,
		Expiration: expirationTime,
	}
	return nil
}

func (r *Sessions) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear all cached items when closing
	for _, item := range r.rcache {
		item.Value.SetBinded(false)
	}
	r.rcache = make(map[string]CacheItem)
	return nil
}

func (c *Sessions) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.rcache {
		if now.After(v.Expiration) {
			v.Value.SetBinded(false)
			delete(c.rcache, k)
		}
	}
}

func (c *Sessions) StartAutoCleaner(interval time.Duration) *time.Ticker {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.CleanExpired()
		}
	}()
	return ticker
}

// Optional: Add a method to get the remaining time for a session
func (r *Sessions) GetRemainingTime(sessionID string) (time.Duration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.rcache[sessionID]
	if !ok {
		return 0, false
	}

	now := time.Now()
	if now.After(item.Expiration) {
		return 0, false
	}

	return item.Expiration.Sub(now), true
}

// Optional: Add a method to extend session time
func (r *Sessions) ExtendSession(sessionID string, additionalDuration time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.rcache[sessionID]
	if !ok {
		return false
	}

	// Only extend if not already expired
	if time.Now().Before(item.Expiration) {
		item.Expiration = item.Expiration.Add(additionalDuration)
		r.rcache[sessionID] = item
		return true
	}

	return false
}

func (r *Sessions) RefreshSession(sessionID string, additionalDuration time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.rcache[sessionID]
	if !ok {
		return false
	}

	// Only extend if not already expired
	if time.Now().Before(item.Expiration) {
		item.Expiration = time.Now().Add(time.Duration(additionalDuration))
		r.rcache[sessionID] = item
		return true
	}

	return false
}
