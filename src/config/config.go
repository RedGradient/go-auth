package config

import (
	"fmt"
	"os"
)


const CompanyEmailAddress = "support@goauth.com"

var JwtSecret = []byte(getEnv("JWT_SECRET", "secret"))

var DSN = fmt.Sprintf(
	"host=%s user=%s password=%s port=%s dbname=%s",
	getEnv("DB_HOST", "localhost"),
	getEnv("DB_USER", "postgres"),
	getEnv("DB_PASSWORD", "password"),
	getEnv("DB_PORT", "5432"),
	getEnv("DB_NAME", "goauth"),
)

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}