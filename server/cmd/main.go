package main

import (
	"cas/config"
	"cas/controllers"
	"cas/database"
	"cas/middleware"
	"cas/router"
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

// @title CAS API
// @version 1.0
// @description API documentation for the CAS application.
// @BasePath /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	app := fx.New(
		fx.Provide(
			config.LoadConfig,
			database.NewDatabase,
			middleware.NewJwtMiddleware,
			controllers.NewAuthController,
			router.NewRouter,
		),
		fx.Invoke(registerHooks),
	)

	app.Run()
}

func registerHooks(lc fx.Lifecycle, r *gin.Engine, cfg *config.Config, db *gorm.DB) {
	database.StartTokenCleanup(db, time.Hour)

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := r.Run(":" + cfg.ListenPort); err != nil {
					log.Fatalf("Failed to start server: %v", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return nil
		},
	})
}
