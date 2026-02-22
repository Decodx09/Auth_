package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/time/rate"
)

// In-memory rate limiter based on IP
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	visitors = make(map[string]*visitor)
	mu       sync.Mutex
)

// Run a background goroutine to clean up old visitors
func init() {
	go cleanupVisitors()
}

func cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		mu.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}

func getVisitor(ip string, r rate.Limit, b int) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	v, exists := visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(r, b)
		visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// RateLimit creates a middleware that limits requests per IP.
// r is the allowed request rate per second.
// b is the burst capacity.
func RateLimit(r rate.Limit, b int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		limiter := getVisitor(ip, r, b)
		if !limiter.Allow() {
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{"error": "Too many requests"})
		}
		return c.Next()
	}
}
