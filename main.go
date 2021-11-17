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
	"net/url"
	"strings"

	"github.com/atreya2011/kratos-test/generated/go/service"
	"github.com/go-openapi/strfmt"
	hydra "github.com/ory/hydra-client-go/client"
	hydra_admin "github.com/ory/hydra-client-go/client/admin"
	hydra_models "github.com/ory/hydra-client-go/models"
	kratos "github.com/ory/kratos-client-go"
)

var ctx = context.Background()

//go:embed templates
var templates embed.FS

// templateData contains data for template
type templateData struct {
	Title   string
	UI      *kratos.UiContainer
	Details string
}

// server contains server information
type server struct {
	KratosAPIClient      *kratos.APIClient
	KratosPublicEndpoint string
	HydraAPIClient       *hydra.OryHydra
	HydraPublicEndpoint  string
	Port                 string
}

func main() {
	// create server
	s, err := NewServer(4433, 4445)
	if err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/logout", s.handleLogout)
	http.HandleFunc("/error", s.handleError)
	http.HandleFunc("/registration", s.ensureCookieFlowID("registration", s.handleRegister))
	http.HandleFunc("/verification", s.ensureCookieFlowID("verification", s.handleVerification))
	http.HandleFunc("/registered", ensureCookieReferer(s.handleRegistered))
	http.HandleFunc("/dashboard", s.handleDashboard)
	http.HandleFunc("/verified", ensureCookieReferer(s.handleVerified))
	http.HandleFunc("/recovery", s.ensureCookieFlowID("recovery", s.handleRecovery))
	http.HandleFunc("/settings", s.ensureCookieFlowID("settings", s.handleSettings))

	http.HandleFunc("/auth/login", s.handleHydraLogin)
	http.HandleFunc("/auth/consent", s.handleHydraConsent)
	http.HandleFunc("/acceptLogin", s.handleAcceptLogin)

	// start server
	log.Println("Auth Server listening on port 4455")
	log.Fatalln(http.ListenAndServe(s.Port, http.DefaultServeMux))
}

// handleAcceptLogin handles accepts login request from hydra
func (s *server) handleAcceptLogin(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// marshal session.identity.traits to json
	traitsJSON, err := json.Marshal(session.Identity.Traits)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// get login challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")
	subject := string(traitsJSON)
	// accept hydra login request
	res, err := s.HydraAPIClient.Admin.AcceptLoginRequest(&hydra_admin.AcceptLoginRequestParams{
		Context:        ctx,
		LoginChallenge: challenge,
		Body: &hydra_models.AcceptLoginRequest{
			Remember:    true,
			RememberFor: 3600,
			Subject:     &subject,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, *res.GetPayload().RedirectTo, http.StatusFound)
}

// handleLogin handles kratos login flow
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// get login challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")

	// build return_to url with hydra login challenge as url query parameter
	returnToParams := url.Values{
		"login_challenge": []string{challenge},
	}
	returnTo := "/acceptLogin?" + returnToParams.Encode()
	// build redirect url with return_to as url query parameter
	redirectToParam := url.Values{
		"return_to": []string{returnTo},
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
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceLoginFlow(ctx).Id(flowID).Cookie(cookie).Execute()
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
	flow, _, err := s.KratosAPIClient.V0alpha2Api.CreateSelfServiceLogoutFlowUrlForBrowsers(ctx).Cookie(cookie).Execute()
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
	errorDetails, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceError(ctx).Id(errorID).Execute()
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
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRegistrationFlow(ctx).Id(flowID).Cookie(cookie).Execute()
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
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceVerificationFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title: "Verify your Email address",
		UI:    &flow.Ui,
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

// handleVerified displays verfification complete message to user
func (s *server) handleVerified(w http.ResponseWriter, r *http.Request) {
	templateData := templateData{
		Title: "Verification Complete",
	}
	// render template index.html
	templateData.Render(w)
}

// handleRecovery handles kratos recovery flow
func (s *server) handleRecovery(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRecoveryFlow(ctx).Id(flowID).Cookie(cookie).Execute()
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
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceSettingsFlow(ctx).Id(flowID).Cookie(cookie).Execute()
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
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(ctx).Cookie(cookie).Execute()
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

// handleHydraLogin handles login request from hydra
func (s *server) handleHydraLogin(w http.ResponseWriter, r *http.Request) {
	// get challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")
	_, err := s.HydraAPIClient.Admin.GetLoginRequest(&hydra_admin.GetLoginRequestParams{
		Context:        ctx,
		LoginChallenge: challenge,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// build login url with challenge as url query parameter
	params := url.Values{
		"login_challenge": []string{challenge},
	}
	loginURL := "/login?" + params.Encode()
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// handleHydraConsent shows hydra consent screen
func (s *server) handleHydraConsent(w http.ResponseWriter, r *http.Request) {
	// get consent challenge from url query parameters
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		w.WriteHeader(http.StatusBadRequest)
		if _, e := w.Write([]byte("Missing consent challenge")); e != nil {
			log.Println(e)
		}
		return
	}

	// get consent request
	_, err := s.HydraAPIClient.Admin.GetConsentRequest(&hydra_admin.GetConsentRequestParams{
		Context:          ctx,
		ConsentChallenge: challenge,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// accept consent request and add verifiable address to id_token in session
	acceptConsentRes, err := s.HydraAPIClient.Admin.AcceptConsentRequest(&hydra_admin.AcceptConsentRequestParams{
		Context:          ctx,
		ConsentChallenge: challenge,
		Body: &hydra_models.AcceptConsentRequest{
			GrantScope:  []string{"openid"},
			Remember:    true,
			RememberFor: 3600,
			Session: &hydra_models.ConsentRequestSession{
				IDToken: service.PersonSchemaJsonTraits{Email: session.Identity.VerifiableAddresses[0].Value},
			},
		},
	})

	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.Redirect(w, r, *acceptConsentRes.GetPayload().RedirectTo, http.StatusFound)
}

func NewServer(kratosPublicEndpointPort, hydraPublicEndpointPort int) (*server, error) {
	// create a new kratos client for self hosted server
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: fmt.Sprintf("http://kratos:%d", kratosPublicEndpointPort)}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}
	return &server{
		KratosAPIClient:      kratos.NewAPIClient(conf),
		KratosPublicEndpoint: fmt.Sprintf("http://localhost:%d", kratosPublicEndpointPort),
		HydraAPIClient: hydra.NewHTTPClientWithConfig(strfmt.Default, &hydra.TransportConfig{
			BasePath: "/",
			Host:     fmt.Sprintf("hydra:%d", hydraPublicEndpointPort),
			Schemes:  []string{"http"},
		}),
		HydraPublicEndpoint: fmt.Sprintf("http://localhost:%d", hydraPublicEndpointPort),
		Port:                ":4455",
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
