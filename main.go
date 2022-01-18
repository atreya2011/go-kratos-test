package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/atreya2011/kratos-test/generated/go/service"
	"github.com/go-openapi/strfmt"
	ory "github.com/ory/client-go"
	"github.com/gorilla/sessions"
	hydra "github.com/ory/hydra-client-go/client"
	hydra_admin "github.com/ory/hydra-client-go/client/admin"
	hydra_models "github.com/ory/hydra-client-go/models"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

var store = sessions.NewCookieStore([]byte("secret-key"))

var appSession *sessions.Session

//go:embed templates
var templates embed.FS

//go:embed config/idp.yml
var idpConfYAML []byte

// templateData contains data for template
type templateData struct {
	Title    string
	UI       *ory.UiContainer
	Details  string
	Metadata Metadata
}

type idpConfig struct {
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	ClientMetadata string `yaml:"client_metadata"`
	Port           int    `yaml:"port"`
}

type Metadata struct {
	Registration bool `json:"registration"`
	Verification bool `json:"verification"`
}

// server contains server information
type server struct {
	KratosAPIClient      *ory.APIClient
	KratosPublicEndpoint string
	HydraAPIClient       *hydra.OryHydra
	Port                 string
	OAuth2Config         *oauth2.Config
	IDPConfig            *idpConfig
}

func initSession(r *http.Request) *sessions.Session {
	log.Println("session before get", appSession)

	if appSession != nil {
		return appSession
	}

	session, err := store.Get(r, "idp")
	appSession = session

	log.Println("session after get", session)
	if err != nil {
		panic(err)
	}
	return session
}

func setSessionValue(w http.ResponseWriter, r *http.Request, key string, value interface{}) {
	session := initSession(r)
	session.Values[key] = value
	log.Printf("set session with key %s and value %s\n", key, value)
	session.Save(r, w)
}

func getSessionValue(w http.ResponseWriter, r *http.Request, key string) interface{} {
	session := initSession(r)
	value := session.Values[key]
	log.Printf("valWithOutType: %s\n", value)
	return value
}

func main() {
	// create server
	s, err := NewServer(4433, 4444, 4445)
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	/**
		create an OAuth2 client using the following command:
			curl -X POST 'http://localhost:4445/clients' \
			-H 'Content-Type: application/json' \
			--data-raw '{
					"client_id": "auth-code-client",
					"client_name": "Test OAuth2 Client",
					"client_secret": "secret",
					"grant_types": ["authorization_code", "refresh_token"],
					"redirect_uris": ["http://localhost:4455/dashboard"],
					"response_types": ["code", "id_token"],
					"scope": "openid offline",
					"token_endpoint_auth_method": "client_secret_post",
					"metadata": "{\"registration\": true}"
			}'
		(or)
		run the compiled binary setting the "-withoauthclient" flag to true to
		automatically create an oauth2 client on startup (not recommended for production)
	**/
	// create an OAuth2 client if none exists

	withOAuthClient := flag.Bool("withoauthclient", false, "Creates an OAuth2 client on startup")
	flag.Parse()

	if *withOAuthClient {
		_, err = s.HydraAPIClient.Admin.GetOAuth2Client(&hydra_admin.GetOAuth2ClientParams{
			Context: ctx,
			ID:      s.IDPConfig.ClientID,
		})
		if err != nil {
			_, err = s.HydraAPIClient.Admin.CreateOAuth2Client(
				&hydra_admin.CreateOAuth2ClientParams{
					Context: ctx,
					Body: &hydra_models.OAuth2Client{
						ClientID:                s.IDPConfig.ClientID,
						ClientName:              "Test OAuth2 Client",
						ClientSecret:            s.IDPConfig.ClientSecret,
						GrantTypes:              []string{"authorization_code", "refresh_token"},
						RedirectUris:            []string{fmt.Sprintf("http://localhost%s/dashboard", s.Port)},
						ResponseTypes:           []string{"code", "id_token"},
						Scope:                   "openid offline",
						TokenEndpointAuthMethod: "client_secret_post",
						Metadata:                s.IDPConfig.ClientMetadata,
					},
				})
			if err != nil {
				log.Fatalln("unable to create OAuth2 client: ", err)
			}
			log.Info("Successfully created OAuth2 client!")
		}
	} else {
		log.Info("Skipping OAuth2 client creation...")
	}

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   216000, // = 1h,
		HttpOnly: true,   // no websocket or any protocol else
	}

	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/logout", s.handleLogout)
	http.HandleFunc("/error", s.handleError)
	http.HandleFunc("/registration", s.ensureCookieFlowID("registration", s.handleRegister))
	http.HandleFunc("/verification", s.ensureCookieFlowID("verification", s.handleVerification))
	http.HandleFunc("/registered", ensureCookieReferer(s.handleRegistered))
	http.HandleFunc("/dashboard", s.handleDashboard)
	http.HandleFunc("/recovery", s.ensureCookieFlowID("recovery", s.handleRecovery))
	http.HandleFunc("/settings", s.ensureCookieFlowID("settings", s.handleSettings))
	http.HandleFunc("/", s.handleIndex)

	http.HandleFunc("/auth/consent", s.handleHydraConsent)

	// start server
	log.Println("Auth Server listening on port 4455")
	log.Fatalln(http.ListenAndServe(s.Port, http.DefaultServeMux))
}

// handleLogin handles login request from hydra and kratos login flow
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// get login challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")
	flowID := r.URL.Query().Get("flow")
	// redirect to login page if there is no login challenge or flow id in url query parameters
	if challenge == "" && flowID == "" {
		log.Println("No login challenge found or flow ID found in URL Query Parameters")

		// create oauth2 state and store in session
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			log.Errorf("generate state failed: %v", err)
			return
		}
		state := base64.StdEncoding.EncodeToString(b)
		setSessionValue(w, r, "oauth2State", state)

		// start oauth2 authorization code flow
		redirectTo := s.OAuth2Config.AuthCodeURL(state)
		log.Infof("redirect to hydra, url: %s", redirectTo)
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	var metadata Metadata

	// get login request from hydra only if there is no flow id in the url query parameters
	if flowID == "" {
		loginRes, err := s.HydraAPIClient.Admin.GetLoginRequest(&hydra_admin.GetLoginRequestParams{
			Context:        r.Context(),
			LoginChallenge: challenge,
		})
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}
		log.Println("got client id: ", loginRes.Payload.Client.ClientID)
		// get client details from hydra
		clientRes, err := s.HydraAPIClient.Admin.GetOAuth2Client(&hydra_admin.GetOAuth2ClientParams{
			Context: r.Context(),
			ID:      loginRes.Payload.Client.ClientID,
		})
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}

		log.Println("got client metadata: ", clientRes.Payload.Metadata)
		// unmarshal client metadata
		md, ok := clientRes.Payload.Metadata.(string)
		if !ok {
			writeError(w, http.StatusInternalServerError, errors.New("Internal Server Error"))
			return
		}
		if err = json.Unmarshal([]byte(md), &metadata); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, errors.New("Internal Server Error"))
			return
		}
	}

	// store metadata value in session
	v := getSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if ok {
		metadata.Registration = reg
	} else {
		setSessionValue(w, r, "canRegister", metadata.Registration)
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")

	// check for kratos session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()

	// if there is no session, redirect to login page with login challenge
	if err != nil {
		// build return_to url with hydra login challenge as url query parameter
		returnToParams := url.Values{
			"login_challenge": []string{challenge},
		}
		returnTo := "/login?" + returnToParams.Encode()
		// build redirect url with return_to as url query parameter
		// refresh=true forces a new login from kratos regardless of browser sessions
		// this is important because we are letting Hydra handle sessions
		redirectToParam := url.Values{
			"return_to": []string{returnTo},
			"refresh":   []string{"true"},
		}
		redirectTo := fmt.Sprintf("%s/self-service/login/browser?", s.KratosPublicEndpoint) + redirectToParam.Encode()

		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")

		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// get the login flow
		flow, _, err := s.KratosAPIClient.FrontendApi.GetLoginFlow(ctx).Id(flowID).Cookie(cookie).Execute()
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		templateData := templateData{
			Title:    "Login",
			UI:       &flow.Ui,
			Metadata: metadata,
		}

		// render template index.html
		templateData.Render(w)
		return
	}

	// if there is a valid session, marshal session.identity.traits to json to be stored in subject
	traitsJSON, err := json.Marshal(session.Identity.Traits)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	subject := string(traitsJSON)

	// accept hydra login request
	res, err := s.HydraAPIClient.Admin.AcceptLoginRequest(&hydra_admin.AcceptLoginRequestParams{
		Context:        r.Context(),
		LoginChallenge: challenge,
		Body: &hydra_models.AcceptLoginRequest{
			Remember:    true,
			RememberFor: 3600,
			Subject:     &subject,
		},
	})
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	http.Redirect(w, r, *res.GetPayload().RedirectTo, http.StatusFound)
}

// handleLogout handles kratos logout flow
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// create self-service logout flow for browser
	flow, _, err := s.KratosAPIClient.FrontendApi.CreateBrowserLogoutFlow(ctx).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// redirect to logout url if session is valid
	if flow != nil {
		http.Redirect(w, r, flow.LogoutUrl, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleError handles login/registration error
func (s *server) handleError(w http.ResponseWriter, r *http.Request) {
	// get url query parameters
	errorID := r.URL.Query().Get("id")
	// get error details
	errorDetails, _, err := s.KratosAPIClient.FrontendApi.GetFlowError(ctx).Id(errorID).Execute()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// marshal errorDetails to json
	errorDetailsJSON, err := json.MarshalIndent(errorDetails, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	templateData := templateData{
		Title:   "Error",
		Details: string(errorDetailsJSON),
	}
	// render template index.html
	templateData.Render(w)
}

// handleRegister handles kratos registration flow
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get the registration flow
	flow, _, err := s.KratosAPIClient.FrontendApi.GetRegistrationFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// check metadata value in session
	v := getSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if !ok || !reg {
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	templateData := templateData{
		Title: "Registration",
		UI:    &flow.Ui,
	}
	// render template index.html
	templateData.Render(w)
}

// handleVerification handles kratos verification flow
func (s *server) handleVerification(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service verification flow for browser
	flow, _, err := s.KratosAPIClient.FrontendApi.GetVerificationFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	title := "Verify your Email address"
	ui := &flow.Ui
	if flow.Ui.Messages != nil {
		for _, message := range flow.Ui.Messages {
			if strings.ToLower(message.GetText()) == "you successfully verified your email address." {
				title = "Verification Complete"
				ui = nil
			}
		}
	}
	templateData := templateData{
		Title: title,
		UI:    ui,
	}
	// render template index.html
	templateData.Render(w)
}

// handleRegistered displays registration complete message to user
func (s *server) handleRegistered(w http.ResponseWriter, r *http.Request) {
	templateData := templateData{
		Title: "Registration Complete",
	}
	// render template index.html
	templateData.Render(w)
}

// handleRecovery handles kratos recovery flow
func (s *server) handleRecovery(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.FrontendApi.GetRecoveryFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title: "Password Recovery Form",
		UI:    &flow.Ui,
	}
	// render template index.html
	templateData.Render(w)
}

// handleSettings handles kratos settings flow
func (s *server) handleSettings(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.FrontendApi.GetSettingsFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title: "Settings",
		UI:    &flow.Ui,
	}
	// render template index.html
	templateData.Render(w)
}

// handleDashboard shows dashboard
func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.FrontendApi.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// marshal session to json
	sessionJSON, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// get oauth2 state from session
	v := getSessionValue(w, r, "oauth2State")
	state, ok := v.(string)
	if !ok || state == "" {
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	// compare oauth2 state with state from url query
	if r.URL.Query().Get("state") != string(state) {
		log.Printf("states do not match, expected %s, got %s\n", string(state), r.URL.Query().Get("state"))
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	// get authorization code from url query and exchange it for access token
	code := r.URL.Query().Get("code")
	token, err := s.OAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("unable to exchange code for token: %s\n", err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	idt := token.Extra("id_token")
	log.Printf("Access Token:\n\t%s\n", token.AccessToken)
	log.Printf("Refresh Token:\n\t%s\n", token.RefreshToken)
	log.Printf("Expires in:\n\t%s\n", token.Expiry.Format(time.RFC1123))
	log.Printf("ID Token:\n\t%v\n\n", idt)

	templateData := templateData{
		Title:   "Session Details",
		Details: string(sessionJSON),
	}
	// render template index.html
	templateData.Render(w)
}

// handleHydraConsent shows hydra consent screen
func (s *server) handleHydraConsent(w http.ResponseWriter, r *http.Request) {
	// get consent challenge from url query parameters
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		log.Println("Missing consent challenge")
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// get consent request
	getConsentRes, err := s.HydraAPIClient.Admin.GetConsentRequest(&hydra_admin.GetConsentRequestParams{
		Context:          r.Context(),
		ConsentChallenge: challenge,
	})
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.FrontendApi.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// accept consent request and add verifiable address to id_token in session
	acceptConsentRes, err := s.HydraAPIClient.Admin.AcceptConsentRequest(&hydra_admin.AcceptConsentRequestParams{
		Context:          r.Context(),
		ConsentChallenge: challenge,
		Body: &hydra_models.AcceptConsentRequest{
			GrantScope:  getConsentRes.Payload.RequestedScope,
			Remember:    true,
			RememberFor: 3600,
			Session: &hydra_models.ConsentRequestSession{
				IDToken: service.PersonSchemaJsonTraits{Email: session.Identity.VerifiableAddresses[0].Value},
			},
		},
	})

	if err != nil {
		log.Println(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	http.Redirect(w, r, *acceptConsentRes.GetPayload().RedirectTo, http.StatusFound)
}

func NewServer(kratosPublicEndpointPort, hydraPublicEndpointPort, hydraAdminEndpointPort int) (*server, error) {
	// create a new kratos client for self hosted server
	conf := ory.NewConfiguration()
	conf.Servers = ory.ServerConfigurations{{URL: fmt.Sprintf("http://kratos:%d", kratosPublicEndpointPort)}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}

	idpConf := idpConfig{}

	if err := yaml.Unmarshal(idpConfYAML, &idpConf); err != nil {
		return nil, err
	}

	oauth2Conf := &oauth2.Config{
		ClientID:     idpConf.ClientID,
		ClientSecret: idpConf.ClientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/dashboard", idpConf.Port),
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/oauth2/auth", hydraPublicEndpointPort), // access from browser
			TokenURL: fmt.Sprintf("http://hydra:%d/oauth2/token", hydraPublicEndpointPort),    // access from server
		},
		Scopes: []string{"openid", "offline"},
	}

	log.Println("OAuth2 Config: ", oauth2Conf)

	return &server{
		KratosAPIClient:      ory.NewAPIClient(conf),
		KratosPublicEndpoint: fmt.Sprintf("http://localhost:%d", kratosPublicEndpointPort),
		HydraAPIClient: hydra.NewHTTPClientWithConfig(strfmt.Default, &hydra.TransportConfig{
			BasePath: "/",
			Host:     fmt.Sprintf("hydra:%d", hydraAdminEndpointPort),
			Schemes:  []string{"http"},
		}),
		Port:         fmt.Sprintf(":%d", idpConf.Port),
		OAuth2Config: oauth2Conf,
		IDPConfig:    &idpConf,
	}, nil
}

// writeError writes error to the response
func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	if _, e := w.Write([]byte(err.Error())); e != nil {
		log.Fatal(err)
	}
}

// ensureCookieFlowID is a middleware function that ensures that a request contains
// flow ID in url query parameters and cookie in header
func (s *server) ensureCookieFlowID(flowType string, next func(w http.ResponseWriter, r *http.Request, cookie, flowID string)) http.HandlerFunc {
	// create redirect url based on flow type
	redirectURL := fmt.Sprintf("%s/self-service/%s/browser", s.KratosPublicEndpoint, flowType)

	return func(w http.ResponseWriter, r *http.Request) {
		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")
		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// if there is no cookie in header, return error
		if cookie == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing cookie"))
			return
		}

		// call next handler
		next(w, r, cookie, flowID)
	}
}

// ensureCookieReferer is a middleware function that ensures that cookie in header contains csrf_token and referer is not empty
func ensureCookieReferer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// if there is no csrf_token in cookie, return error
		if !strings.Contains(cookie, "csrf_token") {
			writeError(w, http.StatusUnauthorized, errors.New(http.StatusText(int(http.StatusUnauthorized))))
			return
		}

		// get referer from headers
		referer := r.Header.Get("referer")
		// if there is no referer in header, return error
		if referer == "" {
			writeError(w, http.StatusBadRequest, errors.New(http.StatusText(int(http.StatusUnauthorized))))
			return
		}

		// call next handler
		next(w, r)
	}
}

// Render renders template with provided data
func (td *templateData) Render(w http.ResponseWriter) {
	// render template index.html
	tmpl := template.Must(template.ParseFS(templates, "templates/index.html"))
	if err := tmpl.Execute(w, td); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, _ := httputil.DumpRequest(r, true)
	log.Println(string(b))
	w.WriteHeader(200)
}
