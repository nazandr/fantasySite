package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type PlayerCard struct {
	Id          primitive.ObjectID `bson:"_id" json:"id"`
	AccountId   int                `bson:"account_id" json:"account_id"`
	Name        string             `bson:"name" json:"name"`
	FantacyRole int                `bson:"fantasy_role" json:"fantasy_role"`
	Team        string             `bson:"team" json:"team_name"`
	Rarity      int                `json:"rarity"`

	Buffs []Buff `json:"buffs"`
}

type Buff struct {
	ID            primitive.ObjectID `bson:"_id" json:"_id"`
	NameOfFild    string             `bson:"name_of_fild" json:"name_of_fild"`
	DisplayedName string             `bson:"displayed_name" json:"displayed_name"`
	Multiplier    int                `bson:"multiplier" json:"multiplier"`
}
