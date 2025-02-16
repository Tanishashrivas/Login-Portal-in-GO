package utils

import (
	"errors"
	"net/http"
)

var ErrAuth = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")

	user, ok := Users[username]

	if !ok {
		return ErrAuth
	}

	sessionToken, err := r.Cookie("session_token")

	if err != nil || sessionToken.Value == "" || sessionToken.Value != user.SessionToken {
		return ErrAuth
	}

	csrfToken := r.Header.Get("X-CSRF-Token")

	if csrfToken == "" || csrfToken != user.CsrfToken {
		return ErrAuth
	}

	return nil
}
