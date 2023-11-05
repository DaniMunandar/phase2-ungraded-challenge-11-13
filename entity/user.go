package entity

type User struct {
	ID            uint `gorm:"primaryKey"`
	Username      string
	Password      string
	DepositAmount float64
}
