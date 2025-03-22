package database

import (
	"cas/config"
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func InitDatabase(cfg *config.Config) (*gorm.DB, error) {
	switch cfg.DBType {
	case "sqlite":
		db, err := gorm.Open(sqlite.Open(cfg.DBName+".db"), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		return db, nil
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		return db, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.DBType)
	}
}

func Migrate(db *gorm.DB) error {
	// placeholder for migrations
	return nil
}
