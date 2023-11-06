package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/justinas/nosurf"
	"github.com/omeid/uconfig"
)

type config struct {
	HttpPort int `default:"8080"`
}

var sessionManager *scs.SessionManager

func GetCSRFToken(ctx context.Context) string {
	// We don't have access to request in the templ component so we create a new
	// empty request and use that to get the CSRF token.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		panic(err)
	}
	return nosurf.Token(req)
}

func CheckUserPassword(ctx context.Context, email, password string) (bool, error) {
	// We hardcode the users credentials here initially.
	usersDb := map[string]string{
		"user1@example.com": "user1pass",
		"user2@example.com": "user2pass",
	}
	return usersDb[email] == password, nil
}

func LoggedInUser(ctx context.Context) string {
	return sessionManager.GetString(ctx, "user")
}

func main() {
	conf := config{}
	confFiles := uconfig.Files{
		{"config.json", json.Unmarshal, true},
	}
	if _, err := uconfig.Classic(&conf, confFiles); err != nil {
		log.Fatalf("parsing config failed %v+", err)
		os.Exit(1)
	}

	sessionManager = scs.New()
	sessionManager.Lifetime = 24 * time.Hour

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(nosurf.NewPure)
	r.Use(sessionManager.LoadAndSave)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		component := index()
		component.Render(r.Context(), w)
	})

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		// If the user is already logged in, redirect to the home page.
		if sessionManager.GetString(r.Context(), "user") != "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if err := login( /*failed=*/ false).Render(r.Context(), w) != nil; err {
			log.Printf("rendering login failed %v+", err)
			return
		}
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		// Verify the user's credentials.
		ok, err := CheckUserPassword(r.Context(), r.Form.Get("email"), r.Form.Get("password"))
		if err != nil {
			log.Printf("checking user password failed %v+", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !ok {
			if err := login( /*failed=*/ true).Render(r.Context(), w) != nil; err {
				log.Printf("rendering login failed %v+", err)
			}
			return
		}

		// Renew the session token.
		if err := sessionManager.RenewToken(r.Context()); err != nil {
			log.Printf("renewing session token failed %v+", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Add user to session.
		sessionManager.Put(r.Context(), "user", r.Form.Get("email"))

		// Redirect to the home page.
		http.Redirect(w, r, "/", http.StatusFound)
	})

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		sessionManager.Destroy(r.Context())
		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Printf("Started HTTP listening on %d", conf.HttpPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", conf.HttpPort), r); err != nil {
		log.Printf("Serving http failed %v+", err)
		os.Exit(2)
	}
}
