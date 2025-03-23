package config

import (
	"log"

	"github.com/Tech-Arch1tect/config"
)

type Config struct {
	ListenPort  string `env:"LISTEN_PORT" validate:"required"`
	DBType      string `env:"DB_TYPE" validate:"required"`
	DBHost      string `env:"DB_HOST" validate:"required"`
	DBPort      string `env:"DB_PORT" validate:"required"`
	DBUser      string `env:"DB_USER" validate:"required"`
	DBPassword  string `env:"DB_PASSWORD" validate:"required"`
	DBName      string `env:"DB_NAME" validate:"required"`
	Environment string `env:"ENVIRONMENT" validate:"required,in=development|staging|production"`
}

func (c *Config) SetDefaults() {
	c.ListenPort = "8080"
	c.DBType = "sqlite"
	c.DBHost = "localhost"
	c.DBPort = "3306"
	c.DBUser = "myapp"
	c.DBPassword = "password"
	c.DBName = "cas"
	c.Environment = "production"
}

func LoadConfig() *Config {
	var cfg Config
	if err := config.Load(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded: %+v", cfg)
	return &cfg
}
