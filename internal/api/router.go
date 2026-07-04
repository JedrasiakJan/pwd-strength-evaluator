package api

import "net/http"

// NewRouter konfiguruje i zwraca główny ruter dla aplikacji
func NewRouter(handler *Handler) http.Handler {
	mux := http.NewServeMux()

	// Definicja punktu końcowego w wersji v1 (zgodnie z wymaganiami projektowymi)
	mux.HandleFunc("POST /api/v1/password/evaluate", handler.HandleEvaluate)

	return mux
}
