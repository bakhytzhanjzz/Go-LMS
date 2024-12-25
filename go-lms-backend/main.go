package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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

var mongoCli *mongo.Client
var db *mongo.Collection
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
	var user User
	err := db.FindOne(context.Background(), bson.M{"_id": id}).Decode(&user)
	if err != nil {
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

	if user.Name == "" || user.Email == "" {
		http.Error(w, `{"status":"fail","message":"Name and Email are required"}`, http.StatusBadRequest)
		return
	}

	_, err = db.UpdateOne(context.Background(), bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"name": user.Name, "email": user.Email}})
	if err != nil {
		http.Error(w, `{"status":"fail","message":"Error updating user"}`, http.StatusInternalServerError)
		return
	}

	response := ResponseData{
		Status:  "success",
		Message: "User successfully updated",
	}
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
	initDB()
	defer func() {
		_ = disconnectFunc()
	}()

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	http.HandleFunc("/api/json", handleJSON)
	http.HandleFunc("/api/user/create", createUser)
	http.HandleFunc("/api/users", getUsers)
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
