package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type User struct {
	ID    uint   `json:"id" gorm:"primaryKey"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var db *gorm.DB

// Initialize database connection
func initDB() {
	dsn := "user=postgres password=1234 dbname=go_lms sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Error connecting to the database: ", err)
	}

	// Auto migrate the User model
	db.AutoMigrate(&User{})
	fmt.Println("Successfully connected to the database")
}

// CRUD operations for User
// Create User
func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if user.Name == "" || user.Email == "" {
		http.Error(w, `{"status":"fail","message":"Name and Email are required"}`, http.StatusBadRequest)
		return
	}

	// Save user to the database
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, `{"status":"fail","message":"Error saving user"}`, http.StatusInternalServerError)
		return
	}

	// Log the created user for debugging
	fmt.Printf("Created User ID: %d, Name: %s, Email: %s\n", user.ID, user.Name, user.Email)

	response := ResponseData{
		Status:  "success",
		Message: "User successfully created",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	if err := db.Find(&users).Error; err != nil {
		http.Error(w, `{"status":"fail","message":"Error retrieving users"}`, http.StatusInternalServerError)
		return
	}
	// Respond with the list of users
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func getUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, `{"status":"fail","message":"User not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	// Ensure Name and Email are provided
	if user.Name == "" || user.Email == "" {
		http.Error(w, `{"status":"fail","message":"Name and Email are required"}`, http.StatusBadRequest)
		return
	}

	var existingUser User
	if err := db.First(&existingUser, user.ID).Error; err != nil {
		http.Error(w, `{"status":"fail","message":"User not found"}`, http.StatusNotFound)
		return
	}

	// Update user fields
	if user.Name != "" {
		existingUser.Name = user.Name
	}
	if user.Email != "" {
		existingUser.Email = user.Email
	}

	// Save the updated user to the database
	db.Save(&existingUser)

	// Respond with success
	response := ResponseData{
		Status:  "success",
		Message: "User successfully updated",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, `{"status":"fail","message":"User not found"}`, http.StatusNotFound)
		return
	}

	db.Delete(&user)
	response := ResponseData{
		Status:  "success",
		Message: "User successfully deleted",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleJSON processes JSON requests and sends appropriate responses
func handleJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"status":"fail","message":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	var reqData map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	// Check if the key "message" exists
	if _, ok := reqData["message"]; !ok {
		response := ResponseData{
			Status:  "fail",
			Message: `"message" key is required`,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// If the key is "message", but its value is empty, it should still be success
	if reqData["message"] == "" {
		response := ResponseData{
			Status:  "success",
			Message: "Received an empty message",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// If the key is "message" and has a valid value, respond success
	fmt.Printf("Received message: %s\n", reqData["message"])

	response := ResponseData{
		Status:  "success",
		Message: "Data successfully received",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Initialize database connection
	initDB()

	// Serve static files (HTML, CSS, JS)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Handle JSON API endpoint
	http.HandleFunc("/api/json", handleJSON)

	// CRUD API endpoints for users
	http.HandleFunc("/api/user/create", createUser)
	http.HandleFunc("/api/users", getUsers) // Endpoint for retrieving all users
	http.HandleFunc("/api/user/get", getUserByID)
	http.HandleFunc("/api/user/update", updateUser)
	http.HandleFunc("/api/user/delete", deleteUser)

	port := ":8080"
	fmt.Printf("Server running at http://localhost%s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
