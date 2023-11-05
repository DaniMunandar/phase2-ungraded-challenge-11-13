package entity

// type Transaction struct {
// 	ID          uint `gorm:"primaryKey"`
// 	UserID      uint
// 	ProductID   uint
// 	Quantity    int
// 	TotalAmount float64
// }

// type Transaction struct {
// 	UserID      int     `json:"user_id"`
// 	ProductID   int     `json:"product_id"`
// 	Quantity    int     `json:"quantity"`
// 	TotalAmount float64 `json:"total_amount"`
// }

type Transaction struct {
	UserID      int
	StoreID     int // Add the StoreID field
	ProductID   int
	Quantity    int
	TotalAmount float64
}
