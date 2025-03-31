package middleware

import (
	"cas/config"
	"cas/models"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var identityKey = "id"

func NewJwtMiddleware(cfg *config.Config, db *gorm.DB) (*jwt.GinJWTMiddleware, error) {
	return jwt.New(&jwt.GinJWTMiddleware{
		Realm:            "cas zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      cfg.JwtPrivateKeyFile,
		PubKeyFile:       cfg.JwtPublicKeyFile,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour,
		IdentityKey:      identityKey,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals struct {
				Username string `json:"username" binding:"required"`
				Password string `json:"password" binding:"required"`
			}
			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return nil, jwt.ErrMissingLoginValues
			}

			var user models.User
			if err := db.Where("username = ?", loginVals.Username).First(&user).Error; err != nil {
				return nil, jwt.ErrFailedAuthentication
			}
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginVals.Password)); err != nil {
				return nil, jwt.ErrFailedAuthentication
			}
			return &user, nil
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if _, ok := data.(*models.User); !ok {
				return false
			}

			tokenString := c.GetHeader("Authorization")
			if tokenString == "" {
				return false
			}
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")

			var blacklistedToken models.TokenBlacklist
			if err := db.Where("token = ? AND expires_at > ?", tokenString, time.Now()).First(&blacklistedToken).Error; err != nil {
				return true
			}
			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{"error": message})
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &models.User{
				Model: gorm.Model{
					ID: uint(claims[identityKey].(float64)),
				},
				Username: claims["username"].(string),
				Email:    claims["email"].(string),
			}
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if user, ok := data.(*models.User); ok {
				return jwt.MapClaims{
					identityKey: user.ID,
					"username":  user.Username,
					"email":     user.Email,
				}
			}
			return jwt.MapClaims{}
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
}
