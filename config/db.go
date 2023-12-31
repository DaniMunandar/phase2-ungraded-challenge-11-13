package config

import (
	"os"

	_ "github.com/joho/godotenv/autoload"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB // Variabel global untuk koneksi database

func InitDB() {
	dsn := os.Getenv("DB_STRING")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Gagal terhubung ke database: " + err.Error())
	}
	DB = db
}

func CloseDB() {
	db, err := DB.DB()
	if err != nil {
		panic("Gagal mendapatkan objek *sql.DB: " + err.Error())
	}
	db.Close()
}
