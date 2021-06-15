package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                primitive.ObjectID `bson:"_id" json:"id"`
	Email             string             `bson:"email" json:"email"`
	Password          string             `bosn:"_" json:"password,omitempty"`
	EncryptedPassword string             `bson:"encripted_password" json:"-"`
	FantacyCoins      int                `bson:"fantasy_coins" json:"fantacy_coins"`
	Packs             PacksCount
	CardsCollection   [][]PlayerCard `bson:"card_collection"`
	Teams             []FantacyTeam
}

type PacksCount struct {
	Common  int `bson:"common" json:"common"`
	Special int `bson:"special" json:"special"`
}

type FantacyTeam struct {
	ID   primitive.ObjectID `bson:"_id" json:"id"`
	Date time.Time          `bson:"date" json:"date"`
	Team []PlayerCard       `bosn:"team" json:"team"`
}
