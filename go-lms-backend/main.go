package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/gomail.v2"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type RateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiterConfig struct {
	RequestsPerSecond float64
	BurstSize         int
	ExpirationTime    time.Duration
}

type RateLimitManager struct {
	limiters    map[string]*RateLimiter
	mu          sync.RWMutex
	config      RateLimiterConfig
	cleanupTick time.Duration
}

type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

type EmailRequest struct {
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	IsHTML      bool     `json:"is_html"`
	Attachments []string `json:"attachments,omitempty"`
}

type EmailService struct {
	config EmailConfig
	dialer *gomail.Dialer
}

func NewEmailService(config EmailConfig) *EmailService {
	dialer := gomail.NewDialer(config.Host, config.Port, config.Username, config.Password)
	return &EmailService{
		config: config,
		dialer: dialer,
	}
}

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name     string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
	Password string             `json:"password,omitempty" bson:"password"`
}

type Course struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Title       string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	ImageURL    string             `json:"image_url" bson:"image_url"`
	Price       float64            `json:"price" bson:"price"`
	IsAdmin     bool               `json:"is_admin" bson:"is_admin"`
}

var mongoCli *mongo.Client
var db *mongo.Collection
var coursesCollection *mongo.Collection
var disconnectFunc = func() error { return nil }
var log = logrus.New()

var (
	publicAPIConfig = RateLimiterConfig{
		RequestsPerSecond: 10,        // 10 requests per second
		BurstSize:         20,        // Allow bursts up to 20 requests
		ExpirationTime:    time.Hour, // Clean up after 1 hour of inactivity
	}

	adminAPIConfig = RateLimiterConfig{
		RequestsPerSecond: 30,            // 30 requests per second
		BurstSize:         50,            // Allow bursts up to 50 requests
		ExpirationTime:    time.Hour * 2, // Clean up after 2 hours of inactivity
	}

	emailAPIConfig = RateLimiterConfig{
		RequestsPerSecond: 2,         // 2 emails per second
		BurstSize:         5,         // Allow bursts up to 5 emails
		ExpirationTime:    time.Hour, // Clean up after 1 hour of inactivity
	}
)

func initLogger() {
	log.SetFormatter(&logrus.JSONFormatter{}) // Use JSON format for structured logging
	log.SetLevel(logrus.InfoLevel)            // Set default log level
}

func initDB() {
	uri := "mongodb+srv://Dima:OuRLSz6NWvWsvlbM@cluster0.sfsqz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "init_db",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Error creating MongoDB client")
	}
	mongoCli = client
	disconnectFunc = func() error {
		return mongoCli.Disconnect(context.Background())
	}

	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		log.WithFields(logrus.Fields{
			"action": "ping_mongodb",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Error pinging MongoDB")
	}
	fmt.Println("Successfully connected to MongoDB!")

	db = client.Database("Go-LMS").Collection("users")
	coursesCollection = client.Database("Go-LMS").Collection("courses") // Новая коллекция
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager(config RateLimiterConfig) *RateLimitManager {
	manager := &RateLimitManager{
		limiters:    make(map[string]*RateLimiter),
		config:      config,
		cleanupTick: 5 * time.Minute,
	}

	// Start cleanup routine
	go manager.cleanup()
	return manager
}

// cleanup removes expired limiters periodically
func (m *RateLimitManager) cleanup() {
	ticker := time.NewTicker(m.cleanupTick)
	for range ticker.C {
		m.mu.Lock()
		for clientID, limiter := range m.limiters {
			if time.Since(limiter.lastSeen) > m.config.ExpirationTime {
				delete(m.limiters, clientID)
			}
		}
		m.mu.Unlock()
	}
}

// GetLimiter returns a rate limiter for a specific client
func (m *RateLimitManager) GetLimiter(clientID string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	limiter, exists := m.limiters[clientID]
	if !exists {
		limiter = &RateLimiter{
			limiter:  rate.NewLimiter(rate.Limit(m.config.RequestsPerSecond), m.config.BurstSize),
			lastSeen: time.Now(),
		}
		m.limiters[clientID] = limiter
	}
	limiter.lastSeen = time.Now()
	return limiter.limiter
}

// RateLimitMiddleware creates a middleware for rate limiting
func (m *RateLimitManager) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get client identifier (IP address or user ID)
		clientID := r.RemoteAddr
		if userID := r.Header.Get("X-User-ID"); userID != "" {
			clientID = userID
		}

		limiter := m.GetLimiter(clientID)

		// Try to get token from bucket
		ctx := r.Context()
		if err := limiter.Wait(ctx); err != nil {
			if err == context.Canceled {
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60") // Suggest retry after 60 seconds
			w.WriteHeader(http.StatusTooManyRequests)

			json.NewEncoder(w).Encode(ResponseData{
				Status:  "error",
				Message: "Rate limit exceeded. Please try again later.",
			})
			return
		}

		// Add rate limit headers
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.2f", m.config.RequestsPerSecond))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%.2f", limiter.Tokens()))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))

		next.ServeHTTP(w, r)
	}
}

func (s *EmailService) SendEmail(req EmailRequest) error {
	// Validate request
	if len(req.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}
	if req.Subject == "" {
		return fmt.Errorf("subject cannot be empty")
	}
	if req.Body == "" {
		return fmt.Errorf("body cannot be empty")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", s.config.Username)
	m.SetHeader("To", req.To...)
	m.SetHeader("Subject", req.Subject)

	if req.IsHTML {
		m.SetBody("text/html", req.Body)
	} else {
		m.SetBody("text/plain", req.Body)
	}

	// Add attachments if any
	for _, attachment := range req.Attachments {
		m.Attach(attachment)
	}

	err := s.dialer.DialAndSend(m)
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "send_email",
			"status": "failure",
			"error":  err.Error(),
			"to":     req.To,
			"host":   s.config.Host,
			"port":   s.config.Port,
		}).Error("Failed to send email")
		return fmt.Errorf("failed to send email: %v", err)
	}

	log.WithFields(logrus.Fields{
		"action": "send_email",
		"status": "success",
		"to":     req.To,
	}).Info("Email sent successfully")

	return nil
}

// EmailHandler handles email-related HTTP requests
func (s *EmailService) EmailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithFields(logrus.Fields{
			"action": "decode_request",
			"status": "failure",
			"error":  err.Error(),
		}).Error("Failed to decode email request")
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Log the request details (excluding sensitive information)
	log.WithFields(logrus.Fields{
		"action":  "email_request",
		"to":      req.To,
		"subject": req.Subject,
		"is_html": req.IsHTML,
	}).Info("Processing email request")

	if err := s.SendEmail(req); err != nil {
		log.WithFields(logrus.Fields{
			"action": "send_email",
			"status": "failure",
			"error":  err.Error(),
		}).Error("Failed to send email")

		errResponse := ResponseData{
			Status:  "error",
			Message: fmt.Sprintf("Failed to send email: %v", err),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errResponse)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "Email sent successfully",
	})
}

func (s *EmailService) BulkEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var users []User
	cursor, err := db.Find(r.Context(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(r.Context())

	if err = cursor.All(r.Context(), &users); err != nil {
		http.Error(w, "Failed to parse users", http.StatusInternalServerError)
		return
	}

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Send emails to all users
	for _, user := range users {
		req.To = []string{user.Email}
		if err := s.SendEmail(req); err != nil {
			log.WithFields(logrus.Fields{
				"action": "send_bulk_email",
				"status": "failure",
				"error":  err.Error(),
				"email":  user.Email,
			}).Error("Failed to send email")
			continue
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "Bulk emails sent successfully",
	})
}

func signupUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Invalid JSON format",
		})
		return
	}

	if user.Name == "" || user.Email == "" || user.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "All fields are required",
		})
		return
	}

	// Check if user already exists
	count, err := db.CountDocuments(r.Context(), bson.M{"email": user.Email})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Error checking user",
		})
		return
	}
	if count > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Email already registered",
		})
		return
	}
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Error hashing password",
		})
		return
	}
	user.Password = string(hashedPassword)

	// Insert user
	_, err = db.InsertOne(r.Context(), user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Error saving user",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "Signup successful",
	})
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var creds User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Invalid JSON format",
		})
		return
	}

	var user User
	err = db.FindOne(r.Context(), bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Invalid email or password",
		})
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "fail",
			Message: "Invalid email or password",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "Login successful",
	})
}

func GetAllCoursesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Параметр для сортировки из запроса
	sortOrder := r.URL.Query().Get("sort")

	var courses []bson.M
	cursor, err := coursesCollection.Find(context.Background(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	if err = cursor.All(context.Background(), &courses); err != nil {
		http.Error(w, "Failed to parse courses", http.StatusInternalServerError)
		return
	}

	// Сортировка курсов по цене
	if sortOrder == "asc" {
		sort.SliceStable(courses, func(i, j int) bool {
			// Преобразуем курс в структуру для доступа к цене
			priceI := courses[i]["price"].(float64)
			priceJ := courses[j]["price"].(float64)
			return priceI < priceJ
		})
	} else if sortOrder == "desc" {
		sort.SliceStable(courses, func(i, j int) bool {
			// Преобразуем курс в структуру для доступа к цене
			priceI := courses[i]["price"].(float64)
			priceJ := courses[j]["price"].(float64)
			return priceI > priceJ
		})
	}

	// Отправка отсортированных курсов
	json.NewEncoder(w).Encode(courses)
}

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

	result, err := db.InsertOne(r.Context(), user)
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "insert_user",
			"status": "failure",
			"error":  err.Error(),
		}).Error("Failed to insert document into MongoDB")
		http.Error(w, `{"status":"fail","message":"Error saving user"}`, http.StatusInternalServerError)
		return
	}

	log.WithFields(logrus.Fields{
		"action":  "insert_user",
		"status":  "success",
		"user_id": result.InsertedID,
	}).Info("User successfully created")

	response := ResponseData{
		Status:  "success",
		Message: "User successfully created",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	cursor, err := db.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Error retrieving users"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		err := cursor.Decode(&user)
		if err != nil {
			http.Error(w, `{"status":"fail","message":"Error decoding user"}`, http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func getUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
	var user User
	err = db.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"User not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"status":"fail","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Получение ID из параметров URL
	id := r.URL.Query().Get("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid ID format"}`, http.StatusBadRequest)
		return
	}

	// Декодирование JSON из тела запроса
	var user User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	// Проверка обязательных полей
	if user.Name == "" || user.Email == "" {
		http.Error(w, `{"status":"fail","message":"Name and Email are required"}`, http.StatusBadRequest)
		return
	}

	// Обновление записи в базе данных
	update := bson.M{
		"$set": bson.M{
			"name":  user.Name,
			"email": user.Email,
		},
	}

	_, err = db.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		update,
	)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Error updating user"}`, http.StatusInternalServerError)
		return
	}

	// Формирование успешного ответа
	response := map[string]string{
		"status":  "success",
		"message": "User successfully updated",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"status":"fail","message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	deletedObjectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Invalid ID format"}`, http.StatusBadRequest)
		return
	}
	_, err = db.DeleteOne(context.Background(), bson.D{{Key: "_id", Value: deletedObjectID}})
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Error deleting user"}`, http.StatusInternalServerError)
		return
	}

	response := ResponseData{
		Status:  "success",
		Message: "User successfully deleted",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

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

	if _, ok := reqData["message"]; !ok {
		response := ResponseData{
			Status:  "fail",
			Message: `"message" key is required`,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	if reqData["message"] == "" {
		response := ResponseData{
			Status:  "success",
			Message: "Received an empty message",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Printf("Received message: %s\n", reqData["message"])

	response := ResponseData{
		Status:  "success",
		Message: "Data successfully received",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func adminPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/admin.html")
	if err != nil {
		http.Error(w, "Error loading admin page", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var users []User
	cursor, err := db.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Failed to fetch users",
		})
		return
	}
	defer cursor.Close(context.Background())

	if err = cursor.All(context.Background(), &users); err != nil {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Failed to parse users",
		})
		return
	}

	// Remove password field from response
	for i := range users {
		users[i].Password = ""
	}

	json.NewEncoder(w).Encode(users)
}

func adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract user ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	userID := parts[len(parts)-1]

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	update := bson.M{
		"$set": updateData,
	}

	result, err := db.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		update,
	)

	if err != nil {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Failed to update user",
		})
		return
	}

	if result.ModifiedCount == 0 {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "No user found with this ID",
		})
		return
	}

	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User updated successfully",
	})
}

func adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	userID := parts[len(parts)-1]

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	result, err := db.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Failed to delete user",
		})
		return
	}

	if result.DeletedCount == 0 {
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "No user found with this ID",
		})
		return
	}

	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User deleted successfully",
	})
}

func GetPaginatedCoursesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Получение параметров пагинации
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 2 // Лимит курсов на страницу
	skip := (page - 1) * limit

	// Подсчитываем общее количество курсов
	totalCount, err := coursesCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to count courses", http.StatusInternalServerError)
		return
	}

	// Выборка курсов с учетом пагинации
	var courses []bson.M
	cursor, err := coursesCollection.Find(
		context.Background(),
		bson.M{},
		options.Find().SetSkip(int64(skip)).SetLimit(int64(limit)),
	)
	if err != nil {
		http.Error(w, "Failed to fetch courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	if err := cursor.All(context.Background(), &courses); err != nil {
		http.Error(w, "Failed to parse courses", http.StatusInternalServerError)
		return
	}

	// Формируем ответ с данными и количеством страниц
	response := map[string]interface{}{
		"courses":     courses,
		"totalPages":  int((totalCount + int64(limit) - 1) / int64(limit)), // Округление вверх
		"currentPage": page,
	}

	json.NewEncoder(w).Encode(response)
}

func testEmailConfig(config EmailConfig) error {
	dialer := gomail.NewDialer(config.Host, config.Port, config.Username, config.Password)

	// Try to create a connection to the SMTP server
	s, err := dialer.Dial()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %v", err)
	}
	s.Close()
	return nil
}

func main() {
	initDB() // Инициализация базы данных
	defer func() {
		_ = disconnectFunc() // Закрытие соединения с базой данных
	}()

	publicLimiter := NewRateLimitManager(publicAPIConfig)
	adminLimiter := NewRateLimitManager(adminAPIConfig)
	emailLimiter := NewRateLimitManager(emailAPIConfig)

	http.HandleFunc("/api/json", publicLimiter.RateLimitMiddleware(handleJSON))
	http.HandleFunc("/api/users", publicLimiter.RateLimitMiddleware(getUsers))
	http.HandleFunc("/api/user/get", publicLimiter.RateLimitMiddleware(getUserByID))
	http.HandleFunc("/all-courses", publicLimiter.RateLimitMiddleware(GetAllCoursesHandler))

	http.HandleFunc("/api/admin/users", adminLimiter.RateLimitMiddleware(getAllUsers))
	http.HandleFunc("/api/admin/users/", adminLimiter.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			adminUpdateUser(w, r)
		case http.MethodDelete:
			adminDeleteUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	emailConfig := EmailConfig{
		Host:     "smtp.gmail.com", // or your SMTP server
		Port:     587,
		Username: "bakhytzhanabdilmazhit@gmail.com",
		Password: "ufoe qtgl zikj eowb",
	}

	if err := testEmailConfig(emailConfig); err != nil {
		log.WithFields(logrus.Fields{
			"action": "test_email_config",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Failed to connect to email server")
	}
	emailService := NewEmailService(emailConfig)

	http.HandleFunc("/api/admin/send-email", emailLimiter.RateLimitMiddleware(emailService.EmailHandler))
	http.HandleFunc("/api/admin/bulk-email", emailLimiter.RateLimitMiddleware(emailService.BulkEmailHandler))

	http.HandleFunc("/api/admin/send-email", emailService.EmailHandler)
	http.HandleFunc("/api/admin/bulk-email", emailService.BulkEmailHandler)

	// Статические файлы (например, CSS, JS, изображения)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Обработчики для HTML страниц
	http.HandleFunc("/", homePage)              // Главная страница
	http.HandleFunc("/about", aboutPage)        // Страница "О нас"
	http.HandleFunc("/allcourses", CoursesPage) // Страница "курсы"

	// Страница администратора
	http.HandleFunc("/admin", adminPage)
	http.HandleFunc("/api/admin/users", getAllUsers)
	http.HandleFunc("/api/admin/users/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			adminUpdateUser(w, r)
		case http.MethodDelete:
			adminDeleteUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Обработчики для API
	http.HandleFunc("/api/json", handleJSON)
	http.HandleFunc("/api/user/create", createUser)
	http.HandleFunc("/api/users", getUsers)
	http.HandleFunc("/api/user/get", getUserByID)
	http.HandleFunc("/api/user/update", updateUser)
	http.HandleFunc("/api/user/delete", deleteUser)
	http.HandleFunc("/all-courses", GetAllCoursesHandler) // для курсов
	http.HandleFunc("/signup", signupUser)
	http.HandleFunc("/login", loginUser)

	port := ":8080"
	fmt.Printf("Server running at http://localhost%s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "start_server",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Server failed to start")
	}
}

// Обработчик для главной страницы
func homePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/index.html") // Загружаем файл index.html
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "render_template",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Failed to render template")

	}
	tmpl.Execute(w, nil)
}

// Обработчик для страницы "О нас"
func aboutPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/about.html") // Загружаем файл about.html
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "render_template",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Failed to render template")

	}
	tmpl.Execute(w, nil)
}

// Обработчик для страницы "О курсах"
func CoursesPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/allcourses.html") // Загружаем файл about.html
	if err != nil {
		log.WithFields(logrus.Fields{
			"action": "render_template",
			"status": "failure",
			"error":  err.Error(),
		}).Fatal("Failed to render template")

	}
	tmpl.Execute(w, nil)
}
