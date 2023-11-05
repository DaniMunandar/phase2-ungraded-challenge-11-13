package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
	"ungraded-challenge-11/config"
	"ungraded-challenge-11/entity"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var log = logrus.New()
var validate = validator.New()

func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

type UserRegistration struct {
	Username      string  `json:"username" validate:"required"`
	Password      string  `json:"password" validate:"required"`
	DepositAmount float64 `json:"deposit_amount" validate:"required"`
}

type UserLogin struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserDeposit struct {
	Username string  `json:"username" validate:"required"`
	Amount   float64 `json:"amount" validate:"required"`
}

type TransactionRequest struct {
	StoreID   int `json:"store_id" validate:"required"`
	ProductID int `json:"product_id" validate:"required"`
	Quantity  int `json:"quantity" validate:"required"`
}

type StoreResponse struct {
	NamaStore string `json:"nama_store"`
	Alamat    string `json:"alamat"`
}

type StoreDetailResponse struct {
	NamaStore  string  `json:"nama_store"`
	Alamat     string  `json:"alamat"`
	Koordinat  string  `json:"koordinat"`
	TotalSales float64 `json:"total_sales"`
	Rating     float64 `json:"rating"`
}

// @Summary Register a new user
// @Description Register a new user with the provided information
// @Tags Users
// @Accept json
// @Produce json
// @Param user body UserRegistration true "User Registration Information"
// @Success 201 {string} string "User registered successfully"
// @Failure 400 {string} string "Invalid request data"
// @Failure 500 {string} string "Failed to register user"
// @Router /register [post]
func RegisterUser(c echo.Context) error {
	// Parsing input JSON
	input := new(UserRegistration)
	if err := c.Bind(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Validasi input
	if err := validate.Struct(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Validation error")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Validation error: " + err.Error()})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to hash password")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to hash password"})
	}

	// Simpan user ke database
	user := entity.User{
		Username:      input.Username,
		Password:      string(hashedPassword),
		DepositAmount: input.DepositAmount,
	}
	if err := config.DB.Create(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to register user")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to register user"})
	}

	log.WithFields(logrus.Fields{"username": input.Username}).Info("User registered successfully")

	return c.JSON(http.StatusCreated, map[string]interface{}{"message": "User registered successfully"})
}

// @Summary Log in as a user
// @Description Log in with the provided username and password
// @Tags Users
// @Accept json
// @Produce json
// @Param user body UserLogin true "User Login Information"
// @Success 200 {string} string "Login successful"
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Invalid credentials"
// @Failure 500 {string} string "Failed to generate token"
// @Router /login [post]
func LoginUser(c echo.Context) error {
	// Parsing input JSON
	input := new(UserLogin)
	if err := c.Bind(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Validasi input
	if err := validate.Struct(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Validation error")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Validation error: " + err.Error()})
	}

	// Cari user berdasarkan username
	var user entity.User
	if err := config.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid credentials")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid credentials"})
	}

	// Verifikasi password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid credentials")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid credentials"})
	}

	// Generate JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = user.ID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to generate token")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to generate token"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"token": tokenString})
}

func DepositAmount(c echo.Context) error {
	// Parsing input JSON
	input := new(UserDeposit)
	if err := c.Bind(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Validasi input
	if err := validate.Struct(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Validation error")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Validation error: " + err.Error()})
	}

	// Cari user berdasarkan username
	var user entity.User
	if err := config.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("User not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "User not found"})
	}

	// Tambahkan jumlah ke saldo akun pengguna
	user.DepositAmount += input.Amount

	// Simpan perubahan ke database
	if err := config.DB.Save(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update amount")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update amount"})
	}

	log.WithFields(logrus.Fields{"username": user.Username}).Info("Amount deposited successfully")

	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Amount deposited successfully"})
}

// Middleware untuk memeriksa token JWT
func RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Mendapatkan token JWT dari header "Authorization"
		tokenString := c.Request().Header.Get("Authorization")
		if tokenString == "" {
			log.Error("Token is missing")
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Token is missing"})
		}

		// Memeriksa dan memverifikasi token JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("your-secret-key"), nil
		})
		if err != nil || !token.Valid {
			log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid token")
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid token"})
		}

		// Menyimpan ID pengguna yang diambil dari token JWT ke dalam konteks
		claims := token.Claims.(jwt.MapClaims)
		userID := int(claims["sub"].(float64))
		c.Set("user", userID)

		return next(c)
	}
}

// @Summary Get a list of products
// @Description Retrieve a list of available products
// @Tags Products
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {array} entity.Product "List of products"
// @Failure 500 {string} string "Failed to fetch products"
// @Router /api/products [get]
// GET /products - Memerlukan token JWT
func GetProducts(c echo.Context) error {
	// Memeriksa autentikasi token JWT
	_ = c.Get("user").(int)

	// Query produk dari database
	var products []entity.Product
	if err := config.DB.Find(&products).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to fetch products")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to fetch products"})
	}

	return c.JSON(http.StatusOK, products)
}

// @Summary Create a new transaction
// @Description Create a new transaction for a user to purchase products
// @Tags Transactions
// @Accept json
// @Produce json
// @Param transaction body TransactionRequest true "Transaction Information"
// @Security Bearer
// @Success 200 {string} string "Transaction successful"
// @Failure 400 {string} string "Invalid request data"
// @Failure 404 {string} string "Product not found"
// @Failure 400 {string} string "Quantity tidak mencukupi"
// @Failure 400 {string} string "Insufficient balance"
// @Failure 500 {string} string "Failed to create transaction"
// @Failure 500 {string} string "Failed to update user balance"
// @Failure 500 {string} string "Failed to update product stock"
// @Router /api/transactions [post]
// POST /transactions - Memerlukan token JWT
func CreateTransaction(c echo.Context) error {
	// Memeriksa autentikasi token JWT
	userID := c.Get("user").(int)

	// Mendapatkan data transaksi dari input JSON
	input := new(TransactionRequest)
	if err := c.Bind(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Validasi input
	if err := validate.Struct(input); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Validation error")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Validation error: " + err.Error()})
	}

	// Query produk dari database berdasarkan product_id
	var product entity.Product
	if err := config.DB.First(&product, input.ProductID).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Product not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "Product not found"})
	}

	// Query toko dari database berdasarkan store_id
	var store entity.Store
	if err := config.DB.First(&store, input.StoreID).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Store not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "Store not found"})
	}

	// Memeriksa apakah jumlah quantity yang diminta lebih besar dari stok produk yang tersedia
	if input.Quantity > product.Stock {
		log.Error("Quantity tidak mencukupi")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Insufficient quantity"})
	}

	// Menghitung total harga transaksi
	totalPrice := product.Price * float64(input.Quantity)

	// Query pengguna dari database berdasarkan userID
	var user entity.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("User not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "User not found"})
	}

	// Memeriksa apakah saldo pengguna mencukupi
	if user.DepositAmount < totalPrice {
		log.Error("Insufficient balance")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Insufficient balance"})
	}

	// Membuat transaksi
	transaction := entity.Transaction{
		UserID:      userID,
		StoreID:     input.StoreID,   // Menggunakan store_id
		ProductID:   int(product.ID), // Konversi Product.ID ke int
		Quantity:    input.Quantity,
		TotalAmount: totalPrice,
	}
	if err := config.DB.Create(&transaction).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to create transaction")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to create transaction"})
	}

	// Mengurangkan saldo pengguna
	user.DepositAmount -= totalPrice

	// Mengurangkan stok produk
	product.Stock -= input.Quantity
	if err := config.DB.Save(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update user balance")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update user balance"})
	}

	// Update stok produk
	if err := config.DB.Save(&product).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update product stock")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update product stock"})
	}

	log.WithFields(logrus.Fields{"userID": userID}).Info("Transaction successful")

	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Transaction successful"})
}

// @Summary Mendapatkan daftar toko
// @Description Mengembalikan daftar toko dengan nama dan alamat.
// @Produce json
// @Success 200 {array} StoreResponse
// @Header 200 {string} Authorization "Bearer <token>"
// @Failure 401 {object} map[string]interface{} "Missing token"
// @Failure 403 {object} map[string]interface{} "Invalid token"
// @Failure 500 {object} map[string]interface{} "Failed to fetch stores"
// @Router /stores [get]
func GetStores(c echo.Context) error {
	// Mendapatkan token dari permintaan
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Missing token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Missing token"})
	}

	// Memeriksa dan mendapatkan ID pengguna dari token JWT
	_, err := verifyToken(token)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid token"})
	}

	// Query toko dari database
	var stores []entity.Store
	if err := config.DB.Select("nama_store", "alamat").Find(&stores).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to fetch stores")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to fetch stores"})
	}

	// Konversi ke dalam respons yang hanya mencakup "nama_store" dan "alamat"
	var storeResponses []StoreResponse
	for _, store := range stores {
		storeResponse := StoreResponse{
			NamaStore: store.NamaStore,
			Alamat:    store.Alamat,
		}
		storeResponses = append(storeResponses, storeResponse)
	}

	return c.JSON(http.StatusOK, storeResponses)
}

// Fungsi untuk memeriksa dan mendapatkan ID pengguna dari token JWT
func verifyToken(tokenString string) (int, error) {
	// Mendeklarasikan struktur untuk menyimpan klaim token
	type TokenClaims struct {
		UserID int `json:"sub"`
		jwt.StandardClaims
	}

	// Mendeklarasikan kunci rahasia yang digunakan untuk menandatangani token
	secretKey := []byte("your-secret-key")

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return 0, err
	}

	// Cek apakah token valid
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims.UserID, nil
	}

	return 0, err
}

func getWeatherData(latitude, longitude float64) (entity.Weather, error) {
	url := "https://weather-by-api-ninjas.p.rapidapi.com/v1/weather?lat=40.7128&lon=-74.006" // Use the provided latitude and longitude

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return entity.Weather{}, err
	}

	req.Header.Add("X-RapidAPI-Key", "416e127650msh3296db5803d04afp1b752cjsn47a3d4d55a61")
	req.Header.Add("X-RapidAPI-Host", "weather-by-api-ninjas.p.rapidapi.com")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return entity.Weather{}, err
	}
	defer res.Body.Close()

	var cuaca entity.Weather
	if err := json.NewDecoder(res.Body).Decode(&cuaca); err != nil {
		return entity.Weather{}, err
	}

	return cuaca, nil
}

// @Summary Mendapatkan detail toko
// @Description Mengembalikan detail toko beserta data cuaca dan total penjualan.
// @Param id path int true "ID toko"
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Header 200 {string} Authorization "Bearer <token>"
// @Failure 400 {object} map[string]interface{} "Invalid store ID"
// @Failure 401 {object} map[string]interface{} "Missing token"
// @Failure 403 {object} map[string]interface{} "Invalid token"
// @Failure 404 {object} map[string]interface{} "Store not found"
// @Failure 500 {object} map[string]interface{} "Failed to get weather data"
// @Router /stores/{id} [get]
func GetStoreDetail(c echo.Context) error {
	// Mendapatkan token dari permintaan
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Missing token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Missing token"})
	}

	// Memeriksa dan mendapatkan ID pengguna dari token JWT
	_, err := verifyToken(token)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid token"})
	}

	storeID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid store ID")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid store ID"})
	}

	// Query store details from the database
	var store entity.Store
	if err := config.DB.First(&store, storeID).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Store not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "Store not found"})
	}

	// Make an HTTP request to get weather data for the current store
	weatherData, err := getWeatherData(store.Longitude, store.Latitude)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to get weather data")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to get weather data"})
	}

	// Calculate total sales (You need to implement this logic based on your data model)
	totalSales := calculateTotalSales(storeID)

	// Buat tipe data respons untuk toko
	storeDetail := StoreDetailResponse{
		NamaStore:  store.NamaStore,
		Alamat:     store.Alamat,
		Koordinat:  fmt.Sprintf("Longitude: %f, Latitude: %f", store.Longitude, store.Latitude),
		TotalSales: totalSales,
		Rating:     store.Rating,
	}

	// Buat tipe data respons untuk cuaca
	weatherResponse := entity.Weather{
		CloudPct:    weatherData.CloudPct,
		Temp:        weatherData.Temp,
		FeelsLike:   weatherData.FeelsLike,
		Humidity:    weatherData.Humidity,
		MinTemp:     weatherData.MinTemp,
		MaxTemp:     weatherData.MaxTemp,
		WindSpeed:   weatherData.WindSpeed,
		WindDegrees: weatherData.WindDegrees,
		Sunrise:     weatherData.Sunrise,
		Sunset:      weatherData.Sunset,
	}

	// Menggabungkan dua objek respons dalam satu respons
	response := map[string]interface{}{
		"store":   storeDetail,
		"weather": weatherResponse,
	}

	return c.JSON(http.StatusOK, response)
}

// Helper function to calculate total sales
func calculateTotalSales(storeID int) float64 {
	// Inisialisasi total penjualan dengan nilai awal 0
	totalPenjualan := 0.0

	// Query transaksi dari database berdasarkan storeID
	var transaksis []entity.Transaction
	if err := config.DB.Where("store_id = ?", storeID).Find(&transaksis).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Gagal mengambil transaksi")
		return totalPenjualan
	}

	// Iterasi melalui transaksi dan tambahkan total penjualan
	for _, transaksi := range transaksis {
		totalPenjualan += transaksi.TotalAmount
	}

	return totalPenjualan
}
