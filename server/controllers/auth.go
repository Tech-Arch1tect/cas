package controllers

import (
	"cas/config"
	"cas/models"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthController struct {
	DB            *gorm.DB
	cfg           *config.Config
	jwtMiddleware *jwt.GinJWTMiddleware
}

func NewAuthController(db *gorm.DB, cfg *config.Config, jwtMiddleware *jwt.GinJWTMiddleware) *AuthController {
	return &AuthController{
		DB:            db,
		cfg:           cfg,
		jwtMiddleware: jwtMiddleware,
	}
}

type RegisterInput struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// RegisterHandler godoc
// @Summary Register a new user
// @Description Register a new user using username, email and password.
// @Tags auth
// @Accept json
// @Produce json
// @Param register body RegisterInput true "Register Input"
// @Success 200 {object} map[string]string "Registration successful"
// @Failure 400 {object} map[string]string "error message"
// @Router /auth/register [post]
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

// LoginHandler godoc
// @Summary Log in a user
// @Description Authenticates a user and returns a JWT token.
// @Tags auth
// @Accept json
// @Produce json
// @Param login body object{username=string,password=string} true "Login credentials"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string "error message"
// @Router /auth/login [post]
func (ac *AuthController) LoginHandler(c *gin.Context) {
	// Delegate to the JWT middleware login handler
	ac.jwtMiddleware.LoginHandler(c)
}

// ProfileHandler godoc
// @Summary Get user profile
// @Description Retrieve profile information of the authenticated user.
// @Tags auth
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string "error: User not found"
// @Router /auth/profile [get]
func (ac *AuthController) ProfileHandler(c *gin.Context) {
	user, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// RefreshHandlerWithCookie godoc
// @Summary Refresh JWT token
// @Description Refresh the JWT token and set a secure refresh cookie.
// @Tags auth
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string "message: error"
// @Router /auth/refresh_token [get]
func (ac *AuthController) RefreshHandlerWithCookie(mw *jwt.GinJWTMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, expire, err := mw.RefreshToken(c)
		if err != nil {
			mw.Unauthorized(c, http.StatusUnauthorized, err.Error())
			return
		}

		cookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    token,
			Domain:   ac.cfg.CookieDomain,
			Path:     "/",
			HttpOnly: true,
			Secure:   ac.cfg.CookieSecure,
			SameSite: http.SameSiteNoneMode,
			Expires:  time.Now().Add(mw.MaxRefresh),
		}
		http.SetCookie(c.Writer, cookie)
		c.JSON(http.StatusOK, gin.H{"token": token, "expire": expire.Unix()})
	}
}
