package controllers

import (
	"cas/models"
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
}

func NewAuthController(db *gorm.DB) *AuthController {
	return &AuthController{DB: db}
}

type RegisterInput struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

func (ac *AuthController) RegisterHandler(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user := models.User{
		Username: input.Username,
		Email:    input.Email,
		Password: string(hashedPassword),
	}
	if err := ac.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func (ac *AuthController) ProfileHandler(c *gin.Context) {
	user, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func (ac *AuthController) SetupRoutes(r *gin.Engine, jwtMiddleware *jwt.GinJWTMiddleware) {
	authGroup := r.Group("/api/v1/auth")
	authGroup.Use(jwtMiddleware.MiddlewareFunc())
	{
		authGroup.POST("/login", jwtMiddleware.LoginHandler)
		authGroup.POST("/register", ac.RegisterHandler)
		authGroup.GET("/refresh_token", jwtMiddleware.RefreshHandler)
		authGroup.GET("/profile", ac.ProfileHandler)
	}
}
