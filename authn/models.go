package authn

//Account is an AuthN user account
type Account struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Locked   bool   `json:"locked"`
	Deleted  bool   `json:"deleted"`
}
