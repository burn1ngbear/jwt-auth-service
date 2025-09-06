package user

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// Function to retrieve user information by username
func GetUserByUsername(username string) (*User, bool) {
	if user, exists := Users[username]; exists {
		return &user, true
	}
	return nil, false
}

// Временное хранилище пользователей
var Users = map[string]User{
	"testuser": {
		ID:       1,
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
		Role:     "user",
	},
	"admin": {
		ID:       2,
		Username: "admin",
		Password: "adminpass",
		Email:    "admin@example.com",
		Role:     "admin",
	},
}
