package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"strings"

	ory "github.com/ory/client-go"
)

var ctx = context.Background()

//go:embed templates
var templates embed.FS

// templateData contains data for template
type templateData struct {
	Title   string
	UI      *ory.UiContainer
	Details string
}

// server contains server information
type server struct {
	KratosAPIClient      *ory.APIClient
	KratosPublicEndpoint string
	Port                 string
}

func main() {
	// create server
	s, err := NewServer(4433)
	if err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/login", s.ensureCookieFlowID("login", s.handleLogin))
	http.HandleFunc("/logout", s.handleLogout)
	http.HandleFunc("/error", s.handleError)
	http.HandleFunc("/registration", s.ensureCookieFlowID("registration", s.handleRegister))
	http.HandleFunc("/verification", s.ensureCookieFlowID("verification", s.handleVerification))
	http.HandleFunc("/registered", ensureCookieReferer(s.handleRegistered))
	http.HandleFunc("/dashboard", s.handleDashboard)
	http.HandleFunc("/recovery", s.ensureCookieFlowID("recovery", s.handleRecovery))
	http.HandleFunc("/settings", s.ensureCookieFlowID("settings", s.handleSettings))
	http.HandleFunc("/", s.handleIndex)

	// start server
	log.Println("Auth Server listening on port 4455")
	log.Fatalln(http.ListenAndServe(s.Port, http.DefaultServeMux))
}

// handleLogin handles kratos login flow
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get the login flow
	flow, _, err := s.KratosAPIClient.FrontendApi.GetLoginFlow(ctx).Id(flowID).Cookie(cookie).Execute()
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

	templateData := templateData{
		Title:   "Session Details",
		Details: string(sessionJSON),
	}
	// render template index.html
	templateData.Render(w)
}

func NewServer(kratosPublicEndpointPort int) (*server, error) {
	// create a new kratos client for self hosted server
	conf := ory.NewConfiguration()
	conf.Servers = ory.ServerConfigurations{{URL: fmt.Sprintf("http://kratos:%d", kratosPublicEndpointPort)}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}
	return &server{
		KratosAPIClient:      ory.NewAPIClient(conf),
		KratosPublicEndpoint: fmt.Sprintf("http://localhost:%d", kratosPublicEndpointPort),
		Port:                 ":4455",
	}, nil
}

// writeError writes error to the response
func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	_, e := w.Write([]byte(err.Error()))
	if e != nil {
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
