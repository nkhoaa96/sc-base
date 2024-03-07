package local

import (
	"github.com/joho/godotenv"
	logg "log"
	"os"
	"syscall"
)

func Getenv(key string) string {
	err := godotenv.Load()
	if err != nil {
		//logg.Print("Error loading", err)
	}
	return os.Getenv(key)
}

func MustMapEnv(target *string, envKey string) {
	v := Getenv(envKey)
	if v == "" {
		logg.Print("environment variable %q not set", envKey)
	}
	*target = v
}
func Setenv(key, value string) error {
	err := syscall.Setenv(key, value)
	if err != nil {
		logg.Print("environment variable %q not set", key)
	}
	return nil
}
