package postgresql

import (
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/storage/local"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

type DatabaseAuth struct {
	Host     string
	Port     int
	UserName string
	Password string
}

func GetConnection() (db *gorm.DB, err error) {
	databas_eAuth, err := getDatabaseAuth()
	if err != nil {
		log.Printf("Cannot get DB ENV:", err)
		return nil, err
	}
	//psql := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d",
		databas_eAuth.Host, databas_eAuth.UserName, databas_eAuth.Password, local.Getenv("PG_DB_NAME"), databas_eAuth.Port)
	DB3, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf("Cannot connect to %s database", "postgres")
	}
	log.Printf("We are connected to the %s database", "postgres")
	return DB3, err
}

func getDatabaseAuth() (*DatabaseAuth, error) {
	var databaseAuth = DatabaseAuth{}
	if local.Getenv("ENVIRONMENT") == "dev" {
		databaseAuth = DatabaseAuth{
			Host:     local.Getenv("PG_DB_HOST"),
			Port:     5432,
			UserName: local.Getenv("KEY_VAULT_PG_DB_USER"),
			Password: local.Getenv("KEY_VAULT_PG_DB_PASS"),
		}
		return &databaseAuth, nil

	}
	return &databaseAuth, nil

}
