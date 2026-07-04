package main

import (
	"log"
	"net/http"
	"pwd-strength-evaluator/internal/api"
	"pwd-strength-evaluator/internal/eval"
	"pwd-strength-evaluator/internal/pwned"
)

func main() {
	// 1. Inicjalizacja komponentów (Dependency Injection)
	pwnedClient := pwned.NewClient()
	evalService := eval.NewService(pwnedClient)
	handler := api.NewHandler(evalService)

	// 2. Konfiguracja routera
	router := api.NewRouter(handler)

	// 3. Uruchomienie serwera HTTP
	log.Println("Server starting on port :8080...")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Server failed to start: %s", err)
	}
}
