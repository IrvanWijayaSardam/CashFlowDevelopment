package dto

type RegisterGoogle struct {
	Name     string `json:"name" form:"name" binding:"required"`
	Email    string `json:"email" form:"email" binding:"required,email"`
	Profile  string `json:"profile" form:"profile"` // Changed type to string
	IsGoogle bool   `json:"isGoogle" form:"isGoogle"`
}
