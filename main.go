package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/atreya2011/kratos-test/generated/go/service"
	"github.com/gorilla/sessions"
	ory "github.com/ory/client-go"
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
	Title   string
	UI      *ory.UiContainer
	Details string
}

type idpConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Port         int    `yaml:"port"`
}

// server contains server information
type server struct {
	KratosAPIClient      *ory.APIClient
	KratosPublicEndpoint string
	HydraAPIClient       *ory.APIClient
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

func deleteSessionValues(w http.ResponseWriter, r *http.Request) {
	session := initSession(r)
	session.Options.MaxAge = -1
	log.Print("deleted session")
	session.Save(r, w)
}

func main() {
	// create server
	s, err := NewServer(4433, 4444, 4445)
	if err != nil {
		log.Fatalln(err)
	}

	// set global cookie store options
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
	// get login challenge and flow id from url query parameters
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

	// if there is no flow id in url query parameters, create a new flow
	if flowID == "" {
		// build url with hydra login challenge as url query parameter
		// it will be automatically passed to hydra upon redirect
		params := url.Values{
			"login_challenge": []string{challenge},
		}
		redirectTo := fmt.Sprintf("%s/self-service/login/browser?", s.KratosPublicEndpoint) + params.Encode()
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get the login flow
	flow, _, err := s.KratosAPIClient.FrontendApi.GetLoginFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	templateData := templateData{
		Title: "Login",
		UI:    &flow.Ui,
	}

	// render template index.html
	templateData.Render(w)
	return
}

// handleLogout handles kratos logout flow
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get logout challenge from url query parameters
	challenge := r.URL.Query().Get("logout_challenge")
	// create self-service logout flow for browser
	flow, _, err := s.KratosAPIClient.FrontendApi.CreateBrowserLogoutFlow(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		if challenge == "" {
			v := getSessionValue(w, r, "idToken")
			idToken, ok := v.(string)
			if !ok {
				idToken = ""
			}
			http.Redirect(w, r, fmt.Sprintf("http://localhost:4444/oauth2/sessions/logout?id_token_hint=%s", idToken), http.StatusSeeOther)
			return
		}
		// get logout request
		getLogoutRequestRes, _, err := s.HydraAPIClient.OAuth2Api.GetOAuth2LogoutRequest(r.Context()).LogoutChallenge(challenge).Execute()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, err)
		}
		// accept logout request
		acceptLogoutRequestRes, _, err := s.HydraAPIClient.OAuth2Api.AcceptOAuth2LogoutRequest(r.Context()).LogoutChallenge(challenge).Execute()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, err)
		}
		// revoke hydra sessions
		_, err = s.HydraAPIClient.OAuth2Api.RevokeOAuth2LoginSessions(r.Context()).Subject(*getLogoutRequestRes.Subject).Execute()
		if err != nil {
			log.Errorf("unable to revoke login sessions %s", err.Error())
			writeError(w, http.StatusInternalServerError, err)
		}
		_, err = s.HydraAPIClient.OAuth2Api.RevokeOAuth2ConsentSessions(r.Context()).Subject(*getLogoutRequestRes.Subject).All(true).Execute()
		if err != nil {
			log.Errorf("unable to revoke consent sessions %s", err.Error())
			writeError(w, http.StatusInternalServerError, err)
		}
		log.Info("hydra logout completed")
		// set the redirect url
		redirectURL := acceptLogoutRequestRes.RedirectTo
		if getLogoutRequestRes.Client != nil {
			redirectURL = getLogoutRequestRes.Client.PostLogoutRedirectUris[0]
		}
		log.Println("logout redirect", redirectURL)
		deleteSessionValues(w, r)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
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
	errorDetails, _, err := s.KratosAPIClient.FrontendApi.GetFlowError(r.Context()).Id(errorID).Execute()
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
	flow, _, err := s.KratosAPIClient.FrontendApi.GetRegistrationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
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
	flow, _, err := s.KratosAPIClient.FrontendApi.GetVerificationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
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
	flow, _, err := s.KratosAPIClient.FrontendApi.GetRecoveryFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
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
	flow, _, err := s.KratosAPIClient.FrontendApi.GetSettingsFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
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
	session, _, err := s.KratosAPIClient.FrontendApi.ToSession(r.Context()).Cookie(cookie).Execute()
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

	// store idToken value in session
	setSessionValue(w, r, "idToken", idt)

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
	getConsentRes, _, err := s.HydraAPIClient.OAuth2Api.GetOAuth2ConsentRequest(r.Context()).ConsentChallenge(challenge).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.FrontendApi.ToSession(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// if user has submitted consent form, process it and get granted scopes
	var grantedScopes []string
	var submittedConsentForm bool
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			log.Error(err)
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		for key, values := range r.PostForm {
			if key == "scopes" {
				for _, value := range values {
					grantedScopes = append(grantedScopes, value)
				}
			}
		}
		submittedConsentForm = true
	}

	switch {
	// show the consent form only if user has not already granted scopes
	case !submittedConsentForm && len(grantedScopes) == 0:
		var consentUiNodes []ory.UiNode
		for _, requestedScope := range getConsentRes.RequestedScope {
			log.Println("requested scope", requestedScope)
			consentUiNodes = append(consentUiNodes, ory.UiNode{
				Attributes: ory.UiNodeAttributes{
					UiNodeInputAttributes: &ory.UiNodeInputAttributes{
						NodeType: "input",
						Name:     "scopes",
						Type:     "checkbox",
						Value:    requestedScope,
						Label: &ory.UiText{
							Text: requestedScope,
						},
					},
				},
				Meta: ory.UiNodeMeta{
					Label: &ory.UiText{
						Text: requestedScope,
					},
				},
				Type: "input",
			})
		}
		consentUiNodes = append(consentUiNodes, ory.UiNode{
			Attributes: ory.UiNodeAttributes{
				UiNodeInputAttributes: &ory.UiNodeInputAttributes{
					Name:     "method",
					NodeType: "input",
					Type:     "submit",
				},
			},
			Meta: ory.UiNodeMeta{
				Label: &ory.UiText{
					Text: "Submit",
				},
			},
			Type: "input",
		})

		consentUI := &ory.UiContainer{
			Action: fmt.Sprintf("/auth/consent?consent_challenge=%s", getConsentRes.Challenge),
			Method: http.MethodPost,
			Messages: []ory.UiText{
				{
					Text: "Please confirm that you want to grant access to the following scopes:",
					Type: "info",
				},
			},
			Nodes: consentUiNodes,
		}
		// render template index.html
		templateData := templateData{
			Title: "Consent",
			UI:    consentUI,
		}
		templateData.Render(w)
		return

	// reject the consent request if user has not granted scopes
	case submittedConsentForm && len(grantedScopes) == 0:
		rejectConsentRes, _, err := s.HydraAPIClient.OAuth2Api.RejectOAuth2ConsentRequest(r.Context()).
			ConsentChallenge(challenge).
			RejectOAuth2Request(ory.RejectOAuth2Request{
				Error:            pointer.ToString("access denied"),
				ErrorDescription: pointer.ToString("You must grant access to atleast one scope to continue"),
				StatusCode:       pointer.ToInt64(http.StatusForbidden),
			}).Execute()

		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}

		http.Redirect(w, r, rejectConsentRes.RedirectTo, http.StatusFound)
	// accept consent request and add verifiable address to id_token in session
	// only if the user has granted scopes
	default:
		acceptConsentRes, _, err := s.HydraAPIClient.OAuth2Api.AcceptOAuth2ConsentRequest(r.Context()).
			ConsentChallenge(challenge).
			AcceptOAuth2ConsentRequest(ory.AcceptOAuth2ConsentRequest{
				GrantScope:  grantedScopes,
				Remember:    pointer.ToBool(true),
				RememberFor: pointer.ToInt64(3600),
				Session: &ory.AcceptOAuth2ConsentRequestSession{
					IdToken: service.PersonSchemaJsonTraits{Email: session.Identity.VerifiableAddresses[0].Value},
				},
			}).Execute()

		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}

		http.Redirect(w, r, acceptConsentRes.RedirectTo, http.StatusFound)
	}
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

	hydraConf := ory.NewConfiguration()
	hydraConf.Servers = ory.ServerConfigurations{{URL: fmt.Sprintf("http://hydra:%d", hydraAdminEndpointPort)}}

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
		HydraAPIClient:       ory.NewAPIClient(hydraConf),
		Port:                 fmt.Sprintf(":%d", idpConf.Port),
		OAuth2Config:         oauth2Conf,
		IDPConfig:            &idpConf,
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
