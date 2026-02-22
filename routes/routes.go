package routes

import (
	"github.com/Decodx09/sauth/controllers"
	"github.com/Decodx09/sauth/middleware"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/time/rate"
)

func SetupRouter() *fiber.App {
	app := fiber.New()

	// Frontend Server Routing
	app.Static("/css", "./public/css")
	app.Static("/js", "./public/js")

	// Single file serving mappings
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})
	app.Get("/verify-email", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})
	app.Get("/reset-password", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})

	// Generic limiters
	// authLimiter: 1 req/sec, burst 5
	authLimiter := middleware.RateLimit(rate.Limit(1), 5)

	api := app.Group("/api")

	// Public routes
	auth := api.Group("/auth")

	auth.Post("/register", authLimiter, controllers.Register)
	auth.Post("/login", authLimiter, controllers.Login)
	auth.Post("/refresh-token", controllers.RefreshToken)
	auth.Get("/verify-email", controllers.VerifyEmail)
	auth.Post("/forgot-password", authLimiter, controllers.ForgotPassword)
	auth.Post("/reset-password", authLimiter, controllers.ResetPassword)

	// Authenticated User Routes
	userRoutes := api.Group("/user", middleware.AuthRequired())

	userRoutes.Post("/logout", controllers.Logout)
	userRoutes.Post("/logout-all", controllers.LogoutAll)
	userRoutes.Get("/profile", controllers.GetProfile)
	userRoutes.Put("/profile", controllers.UpdateProfile)
	userRoutes.Post("/change-password", controllers.ChangePassword)
	userRoutes.Post("/deactivate", controllers.DeactivateAccount)

	auth.Post("/activate", controllers.ReactivateAccount)

	// Admin Routes
	adminRoutes := api.Group("/admin", middleware.AuthRequired(), middleware.AdminRequired())

	adminRoutes.Post("/logout-all-users", controllers.ForceLogoutAllUsers)

	return app
}
