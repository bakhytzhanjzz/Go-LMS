package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"type:varchar(100)"`
	Email     string    `gorm:"type:varchar(100);unique"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

var db *gorm.DB

func initDatabase() {
	dsn := "host=localhost user=postgres password=1234 dbname=golms port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	// Auto-migrate User model
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatal("Error during migration:", err)
	}
	fmt.Println("Database connected and migrated!")
}

func main() {
	initDatabase()

	// Serve static files (HTML, CSS, JS)
	http.Handle("/", http.FileServer(http.Dir("./static"))) // Ensure 'index.html' is in the 'static' folder

	// API endpoints
	http.HandleFunc("/api/users", usersHandler)

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		var users []User
		result := db.Find(&users)
		if result.Error != nil {
			http.Error(w, `{"status":"fail","message":"Failed to fetch users"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		usersJSON, _ := json.Marshal(users)
		fmt.Fprintf(w, `{"status":"success","users":%s}`, usersJSON)

	case http.MethodPost:
		name := r.FormValue("name")
		email := r.FormValue("email")
		if name == "" || email == "" {
			http.Error(w, `{"status":"fail","message":"Name and email are required"}`, http.StatusBadRequest)
			return
		}
		user := User{Name: name, Email: email}
		result := db.Create(&user)
		if result.Error != nil {
			http.Error(w, `{"status":"fail","message":"Failed to create user"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","message":"User created","user_id":%d}`, user.ID)

	default:
		http.Error(w, `{"status":"fail","message":"Invalid HTTP method"}`, http.StatusMethodNotAllowed)
	}
}
