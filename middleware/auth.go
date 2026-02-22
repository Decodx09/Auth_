package middleware

import (
	"net/http"
	"strings"

	"github.com/Decodx09/sauth/utils"
	"github.com/gofiber/fiber/v2"
)

// AuthRequired ensures that the request is authenticated with a valid JWT
func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Authorization header missing"})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Authorization header format"})
		}

		tokenString := parts[1]
		payload, err := utils.ValidateAccessToken(tokenString)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
		}

		// Inject user ID and role into the context
		c.Locals("user_id", payload.UserID)
		c.Locals("role", payload.Role)
		return c.Next()
	}
}

// AdminRequired ensures that the request is made by an admin, must be placed after AuthRequired
func AdminRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role := c.Locals("role")
		if role == nil || role.(string) != "admin" {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Admin access required"})
		}
		return c.Next()
	}
}
