package database

import (
	"cas/config"
	"fmt"
	"log"
	"time"

	"cas/models"

	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewDatabase(cfg *config.Config) (*gorm.DB, error) {
	var (
		db  *gorm.DB
		err error
	)

	switch cfg.DBType {
	case "sqlite":
		if cfg.DBName == ":memory:" {
			db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		} else {
			db, err = gorm.Open(sqlite.Open(cfg.DBName+".db"), &gorm.Config{})
		}
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	default:
		err = fmt.Errorf("unsupported database type: %s", cfg.DBType)
	}

	if err != nil {
		return nil, err
	}

	if err = Migrate(db); err != nil {
		return nil, err
	}

	return db, nil
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.TokenBlacklist{},
	)
}

func CleanupExpiredTokens(db *gorm.DB) error {
	return db.Where("expires_at <= ?", time.Now()).Delete(&models.TokenBlacklist{}).Error
}

func StartTokenCleanup(db *gorm.DB, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := CleanupExpiredTokens(db); err != nil {
				log.Printf("Error cleaning up expired tokens: %v", err)
			} else {
				log.Printf("Successfully cleaned up expired tokens")
			}
		}
	}()
}
