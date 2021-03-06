package db

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
)

func GetDBCollectionAndBase(ctx context.Context) (*mongo.Collection, *mongo.Database, error) {

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://herokuapp:simplepass@mongocluster.kd0gh.mongodb.net/users?retryWrites=true&w=majority"))
	if err != nil {
		log.Fatal(err.Error())
	}

	db := client.Database("test")
	col := db.Collection("users")

	fmt.Println("Connected to MongoDB!")
	return col, db, nil
}
