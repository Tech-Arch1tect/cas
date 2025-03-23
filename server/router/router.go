package router

import (
	"cas/config"
	"cas/controllers"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

func NewRouter(cfg *config.Config, jwtMiddleware *jwt.GinJWTMiddleware, authController *controllers.AuthController) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	authController.SetupRoutes(r, jwtMiddleware)

	return r
}
