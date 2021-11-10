package main

import (
	"context"
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/http/cookiejar"

	kratos "github.com/ory/kratos-client-go"
)

var kratosClient = NewKratosSDKForSelfHosted("http://127.0.0.1:4433")
var ctx = context.Background()

//go:embed templates
var templates embed.FS

func main() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/registration", handleRegister)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/error", handleError)
	log.Fatalln(http.ListenAndServe(":4455", http.DefaultServeMux))
}

// handleLogin handles kratos login flow
func handleLogin(w http.ResponseWriter, r *http.Request) {
	redirectTo := "http://127.0.0.1:4433/self-service/login/browser"

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
	loginFlow, _, err := kratosClient.V0alpha2Api.GetSelfServiceLoginFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
	}
	// render template index.html
	tmpl := template.Must(template.ParseFS(templates, "templates/index.html"))
	if err := tmpl.Execute(w, loginFlow.Ui); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}

// handleRegister handles kratos registration flow
func handleRegister(w http.ResponseWriter, r *http.Request) {
	// get flowID from url query parameters
	flowID := r.URL.Query().Get("flow")
	if flowID == "" {
		http.Redirect(w, r, "http://127.0.0.1:4433/self-service/registration/browser", http.StatusFound)
		return
	}
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get the registration flow
	registrationFlow, _, err := kratosClient.V0alpha2Api.GetSelfServiceRegistrationFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
	}
	// render template index.html
	tmpl := template.Must(template.ParseFS(templates, "templates/index.html"))
	if err := tmpl.Execute(w, registrationFlow.Ui); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}

// handleError handles login/registration error
func handleError(w http.ResponseWriter, r *http.Request) {
	// get url query parameters
	errorID := r.URL.Query().Get("id")
	// get error details
	errorDetails, _, err := kratosClient.V0alpha2Api.GetSelfServiceError(ctx).Id(errorID).Execute()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
	// render template error.html
	tmpl := template.Must(template.ParseFS(templates, "templates/error.html"))
	if err := tmpl.Execute(w, errorDetails); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}

// handleLogout handles kratos logout flow
func handleLogout(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// create self-service logout flow for browser
	flow, _, err := kratosClient.V0alpha2Api.CreateSelfServiceLogoutFlowUrlForBrowsers(ctx).Cookie(cookie).Execute()
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

// NewKratosSDKForSelfHosted creates a new kratos client for self hosted server
func NewKratosSDKForSelfHosted(endpoint string) *kratos.APIClient {
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: endpoint}}
	cj, _ := cookiejar.New(nil)
	conf.HTTPClient = &http.Client{Jar: cj}
	return kratos.NewAPIClient(conf)
}

// writeError writes error to the response
func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	_, e := w.Write([]byte(err.Error()))
	if e != nil {
		log.Fatal(err)
	}
}
