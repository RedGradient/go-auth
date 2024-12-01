package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "go-auth/src/config"
    "go-auth/src/email"
    "go-auth/src/handler"
    "go-auth/src/model"
    "go-auth/src/service"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "log"
)

func main() {
    // Craete connection to PostgreSQL database
    db, err := gorm.Open(postgres.Open(config.DSN))
    if err != nil {
        log.Fatalf("Cannot establish connection to database")
        return
    }

    // Create table for Refresh tokens
    err = db.AutoMigrate(model.RefreshTokenModel{})
    if err != nil {
        log.Fatalf("Migration error")
        return
    }

    // Setup controller
    tokenService := service.TokenService{DB: *db}
    emailSender := email.FakeEmailSender{From: config.CompanyEmailAddress}
    tokenController := handler.TokenController{
        TokenService: &tokenService,
        EmailSender: &emailSender,
    }

    // Setup application
    app := fiber.New()
    app.Use(logger.New())
    app.Post("/auth/token", tokenController.TokenHandler)
    app.Post("/auth/refresh", tokenController.RefreshHandler)
    log.Fatal(app.Listen(":3000"))
}
