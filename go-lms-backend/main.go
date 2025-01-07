package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type User struct {
	ID    string `json:"id" bson:"_id,omitempty"`
	Name  string `json:"name" bson:"name"`
	Email string `json:"email" bson:"email"`
}

type Course struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Title       string             `bson:"title"`
	Description string             `bson:"description"`
	ImageURL    string             `bson:"image_url"`
}

var mongoCli *mongo.Client
var db *mongo.Collection
var coursesCollection *mongo.Collection
var disconnectFunc = func() error { return nil }

func initDB() {
	uri := "mongodb+srv://Dima:OuRLSz6NWvWsvlbM@cluster0.sfsqz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal("Error creating MongoDB client: ", err)
	}
	mongoCli = client
	disconnectFunc = func() error {
		return mongoCli.Disconnect(context.Background())
	}

	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		log.Fatal("Error pinging MongoDB: ", err)
	}
	fmt.Println("Successfully connected to MongoDB!")

	db = client.Database("Go-LMS").Collection("users")
	coursesCollection = client.Database("Go-LMS").Collection("courses") // Новая коллекция
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
		log.Println("Error inserting document into MongoDB:", err)
		http.Error(w, `{"status":"fail","message":"Error saving user"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("Inserted user with ID: %v\n", result.InsertedID)

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

	// Обработчики для API
	http.HandleFunc("/api/json", handleJSON)
	http.HandleFunc("/api/user/create", createUser)
	http.HandleFunc("/api/users", getUsers)
	http.HandleFunc("/api/user/get", getUserByID)
	http.HandleFunc("/api/user/update", updateUser)
	http.HandleFunc("/api/user/delete", deleteUser)
	http.HandleFunc("/all-courses", GetAllCoursesHandler) // для курсов

	port := ":8080"
	fmt.Printf("Server running at http://localhost%s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// Обработчик для главной страницы
func homePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/index.html") // Загружаем файл index.html
	if err != nil {
		log.Fatal(err)
	}
	tmpl.Execute(w, nil)
}

// Обработчик для страницы "О нас"
func aboutPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/about.html") // Загружаем файл about.html
	if err != nil {
		log.Fatal(err)
	}
	tmpl.Execute(w, nil)
}

// Обработчик для страницы "О курсах"
func CoursesPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./static/allcourses.html") // Загружаем файл about.html
	if err != nil {
		log.Fatal(err)
	}
	tmpl.Execute(w, nil)
}
