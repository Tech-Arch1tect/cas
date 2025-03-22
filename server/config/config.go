package config

import (
	"log"

	"github.com/Tech-Arch1tect/config"
)

type Config struct {
	ListenPort string `env:"LISTEN_PORT" validate:"required"`
}

func (c *Config) SetDefaults() {
	c.ListenPort = "8080"
}

func LoadConfig() *Config {
	var cfg Config
	if err := config.Load(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded: %+v", cfg)
	return &cfg
}
