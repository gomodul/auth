package auth

// User represents an authenticated user
type User struct {
	UserID    string
	Email     string
	FullName  string
	FirstName string
	LastName  string
	NickName  string
	AvatarURL string

	Provider string

	Token Token

	RawData map[string]interface{}
}

// SetName ...
func (u *User) SetName(name string) {
	u.FullName = name
	u.FirstName = name
}
