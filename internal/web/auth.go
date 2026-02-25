package web

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
)

var (
	sessions = make(map[string]time.Time)
	mu       sync.Mutex
)

const sessionDuration = 24 * time.Hour

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func LoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, loginPageHTML)
			return
		}

		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == cfg.WebPanelUser && password == cfg.WebPanelPass {
				sessionID, err := generateSessionID()
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				mu.Lock()
				sessions[sessionID] = time.Now().Add(sessionDuration)
				mu.Unlock()

				http.SetCookie(w, &http.Cookie{
					Name:     "session_token",
					Value:    sessionID,
					Expires:  time.Now().Add(sessionDuration),
					HttpOnly: true,
					Path:     "/",
				})

				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, loginPageErrorHTML) // Show login page with error
			return
		}
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		mu.Lock()
		expiry, exists := sessions[c.Value]
		mu.Unlock()

		if !exists || time.Now().After(expiry) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

const loginPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Elahe Tunnel</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; margin: 0; }
        .login-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { text-align: center; color: #333; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #666; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 1rem; }
        button { width: 100%; padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #0056b3; }
        .error { color: #dc3545; text-align: center; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Elahe Tunnel Login</h2>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
`

const loginPageErrorHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Elahe Tunnel</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; margin: 0; }
        .login-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { text-align: center; color: #333; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #666; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 1rem; }
        button { width: 100%; padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #0056b3; }
        .error { color: #dc3545; text-align: center; margin-bottom: 1rem; font-size: 0.9rem; background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 0.5rem; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Elahe Tunnel Login</h2>
        <div class="error">Invalid username or password</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
`
