package router

import (
	"cas/config"
	"cas/controllers"
	"cas/middleware"

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
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORSMiddleware(cfg))

	pub := r.Group("/api/v1/auth")
	{
		pub.POST("/login", jwtMiddleware.LoginHandler)
		pub.POST("/register", authController.RegisterHandler)
		pub.GET("/refresh_token", authController.RefreshHandlerWithCookie(jwtMiddleware))
	}

	protected := r.Group("/api/v1/auth")
	protected.Use(jwtMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", authController.ProfileHandler)
	}

	return r
}
