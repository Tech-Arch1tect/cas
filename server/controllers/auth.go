package controllers

import (
	"cas/config"
	"cas/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var identityKey = "id"

type AuthController struct {
	DB  *gorm.DB
	cfg *config.Config
}

func NewAuthController(db *gorm.DB, cfg *config.Config) *AuthController {
	return &AuthController{
		DB:  db,
		cfg: cfg,
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
// @Router /api/v1/auth/register [post]
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
// @Router /api/v1/auth/login [post]
func (ac *AuthController) LoginHandler(c *gin.Context) {
	var loginVals struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&loginVals); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := ac.DB.Where("username = ?", loginVals.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginVals.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	accessExp := time.Now().Add(15 * time.Minute)
	refreshExp := time.Now().Add(7 * 24 * time.Hour)

	accessClaims := jwt.MapClaims{
		identityKey: user.ID,
		"exp":       accessExp.Unix(),
		"iat":       time.Now().Unix(),
		"username":  user.Username,
		"email":     user.Email,
	}
	refreshClaims := jwt.MapClaims{
		identityKey: user.ID,
		"exp":       refreshExp.Unix(),
		"iat":       time.Now().Unix(),
		"type":      "refresh",
		"username":  user.Username,
		"email":     user.Email,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)

	privKeyData, err := os.ReadFile(ac.cfg.JwtPrivateKeyFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to read private key"})
		return
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to parse private key"})
		return
	}

	accessStr, err := accessToken.SignedString(privKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to sign access token"})
		return
	}
	refreshStr, err := refreshToken.SignedString(privKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to sign refresh token"})
		return
	}

	c.SetCookie("refresh_token", refreshStr, int(refreshExp.Sub(time.Now()).Seconds()), "/", ac.cfg.CookieDomain, ac.cfg.CookieSecure, true)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessStr,
		"expires":      accessExp.Unix(),
	})
}

// ProfileHandler godoc
// @Summary Get user profile
// @Description Retrieve profile information of the authenticated user.
// @Tags auth
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string "error: User not found"
// @Router /api/v1/auth/profile [get]
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
// @Router /api/v1/auth/refresh_token [get]
func (ac *AuthController) RefreshHandler(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token missing"})
		return
	}

	pubKeyData, err := os.ReadFile(ac.cfg.JwtPublicKeyFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to read public key"})
		return
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to parse public key"})
		return
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
		return
	}

	accessExp := time.Now().Add(15 * time.Minute)
	accessClaims := jwt.MapClaims{
		identityKey: claims[identityKey],
		"exp":       accessExp.Unix(),
		"iat":       time.Now().Unix(),
		"username":  claims["username"],
		"email":     claims["email"],
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)

	privKeyData, err := os.ReadFile(ac.cfg.JwtPrivateKeyFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to read private key"})
		return
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to parse private key"})
		return
	}
	newAccessStr, err := newAccessToken.SignedString(privKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to sign new access token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token": newAccessStr,
		"expires":      accessExp.Unix(),
	})
}
