package testutils

import (
	"cas/config"
	"cas/controllers"
	"cas/database"
	"cas/middleware"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	jwt "github.com/appleboy/gin-jwt/v2"
	"gorm.io/gorm"
)

type Env struct {
	DB             *gorm.DB
	Config         *config.Config
	JwtMiddleware  *jwt.GinJWTMiddleware
	AuthController *controllers.AuthController
}

func persistentRSAKeys(t *testing.T) (privateKeyPath string, publicKeyPath string) {
	privateKeyPath = "./private.key"
	publicKeyPath = "./public.key"

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
		privPem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		})
		if err := os.WriteFile(privateKeyPath, privPem, 0600); err != nil {
			t.Fatalf("Failed to write private key to %s: %v", privateKeyPath, err)
		}

		pubKey := &privKey.PublicKey
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			t.Fatalf("Failed to marshal public key: %v", err)
		}
		pubPem := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})
		if err := os.WriteFile(publicKeyPath, pubPem, 0644); err != nil {
			t.Fatalf("Failed to write public key to %s: %v", publicKeyPath, err)
		}
	} else if err != nil {
		t.Fatalf("Failed to stat private key file: %v", err)
	}

	return privateKeyPath, publicKeyPath
}

func SetupTestEnv(t *testing.T) *Env {
	privKeyPath, pubKeyPath := persistentRSAKeys(t)

	cfg := &config.Config{
		ListenPort:         "8080",
		DBType:             "sqlite",
		DBHost:             "localhost",
		DBPort:             "3306",
		DBUser:             "myapp",
		DBPassword:         "password",
		DBName:             ":memory:",
		Environment:        "development",
		CookieDomain:       "localhost",
		JwtPrivateKeyFile:  privKeyPath,
		JwtPublicKeyFile:   pubKeyPath,
		CorsAllowedOrigins: "http://localhost",
	}

	db, err := database.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	jwtMiddleware, err := middleware.NewJwtMiddleware(cfg, db)
	if err != nil {
		t.Fatalf("Failed to create JWT middleware: %v", err)
	}

	authController := controllers.NewAuthController(db, cfg, jwtMiddleware)

	return &Env{
		DB:             db,
		Config:         cfg,
		JwtMiddleware:  jwtMiddleware,
		AuthController: authController,
	}
}
