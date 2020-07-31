package model

type User struct {
	GUID         string `json:"guid"`
	RefreshToken string `json:"refreshtoken"`
	TokenID      string `json:"tokenid"`
}
