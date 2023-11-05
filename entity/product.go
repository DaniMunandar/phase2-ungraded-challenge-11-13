package entity

type Product struct {
	ID    uint `gorm:"primaryKey"`
	Name  string
	Stock int
	Price float64
}
