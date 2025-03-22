package main

import (
	"cas/config"
	"cas/database"
	"log"
)

func main() {
	cfg := config.LoadConfig()
	db, err := database.InitDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = database.Migrate(db)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}
