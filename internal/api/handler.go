package api

import (
	"encoding/json"
	"net/http"
	"pwd-strength-evaluator/internal/eval"
)

// Evaluator definiuje kontrakt dla silnika oceny haseł
type Evaluator interface {
	Evaluate(password, username, email string) eval.Result
}

type Request struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Handler struct {
	evaluator Evaluator
}

func NewHandler(e Evaluator) *Handler {
	return &Handler{evaluator: e}
}

func (h *Handler) HandleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON request body"}`, http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(eval.Result{
			Verdict:  "PASSWORD_REQUIRED",
			Feedback: []string{"Password field cannot be empty."},
		})
		return
	}

	// Wywołanie zoptymalizowanego silnika oceny
	result := h.evaluator.Evaluate(req.Password, req.Username, req.Email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
