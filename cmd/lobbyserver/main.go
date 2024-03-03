package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/justinas/nosurf"
	"github.com/omeid/uconfig"
)

type config struct {
	Host      string `default:"localhost"`
	HttpPort  int    `default:"8080"`
	ForcePKCE bool   `default:"true"`
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

type MyClient struct {
	models.Client
	PrettyName string
}

func main() {
	conf := config{}
	confFiles := uconfig.Files{
		{"config.json", json.Unmarshal, true},
	}
	if _, err := uconfig.Classic(&conf, confFiles); err != nil {
		log.Fatalf("parsing config failed %v", err)
		os.Exit(1)
	}
	var baseUrl string
	if conf.Host == "localhost" {
		baseUrl = fmt.Sprintf("http://%s:%d", conf.Host, conf.HttpPort)
	} else {
		baseUrl = fmt.Sprintf("https://%s", conf.Host)
	}

	sessionManager = scs.New()
	sessionManager.Lifetime = 24 * time.Hour

	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	clientStore.Set("lobby", &MyClient{
		Client: models.Client{
			ID:     "lobby",
			Public: true,
			Domain: "http://localhost/oauth2callback",
		},
		PrettyName: "Generic Lobby",
	})
	manager.MapClientStorage(clientStore)
	manager.SetValidateURIHandler(validateRedirectUri)

	oauthSrv := server.NewDefaultServer(manager)
	// https://tools.ietf.org/html/rfc8252#section-8.1
	oauthSrv.Config.ForcePKCE = conf.ForcePKCE
	oauthSrv.SetAllowedGrantType("authorization_code", "refresh_token")
	oauthSrv.SetAllowedResponseType("code")
	oauthSrv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		// If the user is already logged in, allow the request.
		user := sessionManager.GetString(r.Context(), "user")
		if user != "" {
			log.Printf("user is %s", user)
			return user, nil
		}

		// Otherwise, redirect to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return "", nil
	})

	oauthSrv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	oauthSrv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(h http.Handler) http.Handler {
		csrfHandler := nosurf.New(h)
		csrfHandler.ExemptPaths("/oauth2/token", "/oauth2/revoke")
		return csrfHandler
	})
	r.Use(sessionManager.LoadAndSave)
	// https://tools.ietf.org/html/rfc6749#section-10.13
	r.Use(middleware.SetHeader("X-Frame-Options", "DENY"))
	r.Use(middleware.GetHead)

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
			log.Printf("rendering login failed %+v", err)
			return
		}
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		} else if next[0] != '/' {
			// Prevent open redirects.
			http.Error(w, "Invalid next URL", http.StatusBadRequest)
			return
		}

		// Verify the user's credentials.
		ok, err := CheckUserPassword(r.Context(), r.FormValue("email"), r.FormValue("password"))
		if err != nil {
			log.Printf("checking user password failed %+v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !ok {
			if err := login( /*failed=*/ true).Render(r.Context(), w) != nil; err {
				log.Printf("rendering login failed %+v", err)
			}
			return
		}

		// Renew the session token.
		if err := sessionManager.RenewToken(r.Context()); err != nil {
			log.Printf("renewing session token failed %+v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Add user to session.
		sessionManager.Put(r.Context(), "user", r.FormValue("email"))

		// Redirect to the next page.
		http.Redirect(w, r, next, http.StatusFound)
	})

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		sessionManager.Destroy(r.Context())
		http.Redirect(w, r, "/", http.StatusFound)
	})

	r.Get("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Extract and verify the client.
		clientId := r.FormValue("client_id")
		client, err := oauthSrv.Manager.GetClient(r.Context(), clientId)
		if err != nil {
			respondJson(w, *oauthSrv, err)
			return
		}
		myClient := client.(*MyClient)

		// Verify the redirect URI per https://tools.ietf.org/html/rfc6749#section-4.1.2.1
		redirectUri := r.FormValue("redirect_uri")
		if err := validateRedirectUri(myClient.Domain, redirectUri); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user := sessionManager.GetString(r.Context(), "user")
		if user == "" {
			next := url.QueryEscape("/oauth2/authorize?" + r.URL.RawQuery)
			http.Redirect(w, r, "/login?next="+next, http.StatusFound)
			return
		}

		if err := consent(myClient.PrettyName, []string{}).Render(r.Context(), w) != nil; err {
			log.Printf("rendering consent failed %+v", err)
			return
		}
	})

	r.Post("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := oauthSrv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	r.Get("/oauth2/test", func(w http.ResponseWriter, r *http.Request) {
		token, err := oauthSrv.ValidationBearerToken(r)
		if err == errors.ErrInvalidAccessToken {
			http.Header.Add(w.Header(), "WWW-Authenticate", `Bearer realm="oauth2-test"`)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Header.Add(w.Header(), "Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello, %s!", token.GetUserID())
	})

	r.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		err := oauthSrv.HandleTokenRequest(w, r)
		if err != nil {
			log.Printf("handling token request failed %+v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	r.Post("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		clientId, _, err := oauthSrv.ClientInfoHandler(r)
		if err != nil {
			respondJson(w, *oauthSrv, err)
			return
		}
		client, err := oauthSrv.Manager.GetClient(r.Context(), clientId)
		if err != nil {
			respondJson(w, *oauthSrv, err)
			return
		}

		token := r.FormValue("token")
		if token == "" {
			respondJson(w, *oauthSrv, errors.ErrInvalidRequest)
			return
		}

		checkToken := func(ti oauth2.TokenInfo, error) (bool, error) {

		}

		ti, err := oauthSrv.Manager.LoadAccessToken(r.Context(), token)
		if err != nil &&
			err != errors.ErrInvalidAccessToken &&
			err != errors.ErrExpiredAccessToken &&
			err != errors.ErrExpiredRefreshToken {
			respondJson(w, *oauthSrv, errors.ErrServerError)
			return
		} else if err == nil {
			if ti.GetClientID() != client.GetID() {
				respondJson(w, *oauthSrv, errors.ErrInvalidRequest)
				return
			}
			if err := oauthSrv.Manager.RemoveAccessToken(r.Context(), token); err != nil {
				respondJson(w, *oauthSrv, errors.ErrServerError)
				return
			}
		}

		if err == errors.ErrInvalidAccessToken {
			ti, err = oauthSrv.Manager.LoadRefreshToken(r.Context(), token)
			if err != nil &&
				err != errors.ErrInvalidRefreshToken &&
				err != errors.ErrExpiredRefreshToken {
				respondJson(w, *oauthSrv, errors.ErrServerError)
				return
			} else if err == nil {
				if ti.GetClientID() != client.GetID() {
					respondJson(w, *oauthSrv, errors.ErrInvalidRequest)
					return
				}
				if err := oauthSrv.Manager.RemoveRefreshToken(r.Context(), token); err != nil {
					respondJson(w, *oauthSrv, errors.ErrServerError)
					return
				}
			}
		}

		w.WriteHeader(http.StatusOK)
	})

	r.Get("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": "%s",
			"authorization_endpoint": "%s/oauth2/authorize",
			"token_endpoint": "%s/oauth2/token",
			"scopes_supported": [
				"lobby"
			],
			"response_types_supported": [
				"code"
			],
			"grant_types_supported": [
				"authorization_code",
				"refresh_token"
			],
			"code_challenge_methods_supported": [
				"plain",
				"S256"
			]
		}`, baseUrl, baseUrl, baseUrl)
	})

	log.Printf("Started HTTP listening on %d", conf.HttpPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", conf.HttpPort), r); err != nil {
		log.Printf("Serving http failed %+v", err)
		os.Exit(2)
	}
}

func respondJson(w http.ResponseWriter, srv server.Server, err error) error {
	data, status, header := srv.GetErrorData(err)

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	for key := range header {
		w.Header().Set(key, header.Get(key))
	}
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// validateRedirectUri validates that the redirect URI is a valid one according to RFC 8252.
func validateRedirectUri(baseURI, redirectURI string) error {
	base, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}

	if base.Scheme != redirect.Scheme ||
		base.Path != redirect.Path ||
		redirect.Fragment != "" ||
		redirect.User != nil {
		return errors.ErrInvalidRedirectURI
	}
	// Following https://tools.ietf.org/html/rfc8252#section-7.3 we allow localhost as a redirect URI ignoring port.
	if base.Host == redirect.Host ||
		(base.Host == "localhost" && (redirect.Hostname() == "127.0.0.1" || redirect.Hostname() == "[::1]")) {
		return nil
	}
	return errors.ErrInvalidRedirectURI
}
