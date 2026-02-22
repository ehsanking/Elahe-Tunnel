package tunnel

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// IPRateLimiter holds the rate limiters for each IP address.
type IPRateLimiter struct {
	mu      sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewIPRateLimiter creates a new rate limiter.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

// getLimiter returns the rate limiter for the given IP address.
func (i *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.limiters[ip]
	if !exists {
		// Allow 5 requests per second with a burst of 10.
		limiter = rate.NewLimiter(5, 10)
		i.limiters[ip] = limiter
	}

	return limiter
}

// Limit is a middleware that applies rate limiting to an HTTP handler.
func (i *IPRateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // In a real-world scenario, you'd parse X-Forwarded-For
		if !i.getLimiter(ip).Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
