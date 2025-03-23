package main

import (
	"cas/config"
	"cas/controllers"
	"cas/database"
	"cas/middleware"
	"cas/router"
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
)

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

func registerHooks(lc fx.Lifecycle, r *gin.Engine, cfg *config.Config) {
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
