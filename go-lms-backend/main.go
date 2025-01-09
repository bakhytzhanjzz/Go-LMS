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

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
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

func main() {
	initDB() // Инициализация базы данных
	defer func() {
		_ = disconnectFunc() // Закрытие соединения с базой данных
	}()

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
