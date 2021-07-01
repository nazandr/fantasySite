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
	Teams             []FantasyTeam
}

type PacksCount struct {
	Common  int `bson:"common" json:"common"`
	Special int `bson:"special" json:"special"`
}

type FantasyTeam struct {
	ID    primitive.ObjectID `bson:"_id" json:"id"`
	Date  time.Time          `bson:"date" json:"date"`
	Team  []Player           `bosn:"team" json:"team"`
	Total float32            `bson:"total" json:"total"`
}

type Player struct {
	PlayerCard PlayerCard
	Points     float32
}
