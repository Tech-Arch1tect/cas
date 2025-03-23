package testutils

import (
	"testing"

	"cas/config"
	"cas/database"
	"cas/middleware"

	jwt "github.com/appleboy/gin-jwt/v2"
	"gorm.io/gorm"
)

type Env struct {
	DB            *gorm.DB
	Config        *config.Config
	JwtMiddleware *jwt.GinJWTMiddleware
}

func SetupTestEnv(t *testing.T) *Env {
	cfg := &config.Config{
		ListenPort:  "8080",
		DBType:      "sqlite",
		DBHost:      "localhost",
		DBPort:      "3306",
		DBUser:      "myapp",
		DBPassword:  "password",
		DBName:      ":memory:",
		Environment: "development",
		JwtSecret:   "testsecret123456",
	}

	db, err := database.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	jwtMiddleware, err := middleware.NewJwtMiddleware(cfg, db)
	if err != nil {
		t.Fatalf("Failed to create JWT middleware: %v", err)
	}

	return &Env{
		DB:            db,
		Config:        cfg,
		JwtMiddleware: jwtMiddleware,
	}
}
