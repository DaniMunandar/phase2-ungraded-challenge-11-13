package main

import (
	"os"
	"ungraded-challenge-11/config"
	"ungraded-challenge-11/docs"
	"ungraded-challenge-11/handler"

	_ "github.com/joho/godotenv/autoload"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title API Avengers
// @version 1.0
// @description API for managing Avengers
// @host localhost:8080
// @BasePath /api
func main() {
	e := echo.New()

	// Inisialisasi dokumen Swagger
	docs.SwaggerInfo.Title = "API Avengers"
	docs.SwaggerInfo.Description = "API for managing Avengers"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/api"

	// Mendaftarkan Echo-Swagger untuk routing
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.POST("/register", handler.RegisterUser)
	e.POST("/login", handler.LoginUser)

	e.GET("/stores", handler.GetStores)
	e.GET("/stores/:id", handler.GetStoreDetail)

	// Protected routes (require authentication)
	protected := e.Group("/api")
	protected.Use(handler.RequireAuth)
	protected.GET("/products", handler.GetProducts)
	protected.POST("/transactions", handler.CreateTransaction)

	// Database initialization
	config.InitDB()

	// Start the server
	port := os.Getenv("PORT")
	// e.Logger.Fatal(e.Start(port))
	e.Logger.Fatal(e.Start(":" + port))
}
