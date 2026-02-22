package main

import (
	"log"
	"os"

	"github.com/Decodx09/sauth/config"
	"github.com/Decodx09/sauth/routes"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	// Initialize database
	config.ConnectDB()

	// Initialize router
	app := routes.SetupRouter()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	log.Printf("Server running on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
