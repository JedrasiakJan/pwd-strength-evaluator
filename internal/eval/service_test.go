package eval

import (
	"errors"
	"testing"
)

// mockPwnedClient to sztuczna implementacja interfejsu PwnedClient na potrzeby testów
type mockPwnedClient struct {
	isLeaked bool
	count    int
	err      error
}

func (m *mockPwnedClient) CheckPassword(password string) (bool, int, error) {
	return m.isLeaked, m.count, m.err
}

func TestEvaluate_PasswordTooShort(t *testing.T) {
	mock := &mockPwnedClient{isLeaked: false, count: 0, err: nil}
	service := NewService(mock)

	result := service.Evaluate("123", "user", "user@test.com")

	if result.Verdict != "TOO_SHORT" {
		t.Errorf("Expected verdict TOO_SHORT, got %s", result.Verdict)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0, got %d", result.Score)
	}
}

func TestEvaluate_CompromisedPassword(t *testing.T) {
	// Symulujemy, że hasło znajduje się w bazie wycieków
	mock := &mockPwnedClient{isLeaked: true, count: 1500, err: nil}
	service := NewService(mock)

	result := service.Evaluate("super_secret_password", "user", "user@test.com")

	if result.Verdict != "COMPROMISED" {
		t.Errorf("Expected verdict COMPROMISED, got %s", result.Verdict)
	}
	if !result.IsCompromised {
		t.Errorf("Expected IsCompromised to be true")
	}
}

func TestEvaluate_ContextAwareFiltering(t *testing.T) {
	mock := &mockPwnedClient{isLeaked: false, count: 0, err: nil}
	service := NewService(mock)

	// Hasło ma ponad 8 znaków, ale zawiera w sobie pełny login "okenobi"
	result := service.Evaluate("okenobi_jedi_master", "okenobi", "o.kenobi@jedi.com")

	if result.Verdict != "WEAK" {
		t.Errorf("Expected verdict WEAK due to personal data usage, got %s", result.Verdict)
	}
}

func TestEvaluate_NetworkErrorFallback_FailOpen(t *testing.T) {
	// Symulujemy awarię zewnętrznego API (błąd sieci)
	mock := &mockPwnedClient{isLeaked: false, count: 0, err: errors.New("network timeout")}
	service := NewService(mock)

	// Silne hasło, które powinno przejść pomyślnie mimo awarii API (zasada Fail-Open)
	result := service.Evaluate("CorrectHorseBatteryStaple2026!", "user", "user@test.com")

	if result.Verdict != "STRONG" {
		t.Errorf("Expected Fail-Open to allow strong password during network error, got verdict: %s", result.Verdict)
	}
}

/*
================================================================================
DOKUMENTACJA TECHNICZNA: TESTY JEDNOSTKOWE SILNIKA OCENY (EVAL SERVICE TEST)
================================================================================

1. METODOLOGIA TESTOWANIA I ZGODNOŚĆ Z AUDYTEM:

   * Izolacja Warstwy Biznesowej (Mocking):
     Zgodnie z najlepszymi praktykami inżynierii oprogramowania, testy jednostkowe
     silnika oceny haseł nie mogą polegać na zewnętrznych połączeniach sieciowych.
     Wykorzystano wzorzec projektowy Mock (struktura mockPwnedClient), która
     implementuje interfejs PwnedClient. Pozwala to na pełną deterministyczną
     kontrolę nad zachowaniem warstwy sprawdzania wycieków (symulacja hasła
     bezpiecznego, skompromitowanego oraz awarii sieci).

   * Walidacja Przypadków Brzegowych (Edge Cases):
     - TestEvaluate_PasswordTooShort: Weryfikuje natychmiastowe odrzucenie hasła
       krótszego niż 8 znaków (wymóg NIST SP 800-63B), zapobiegając dalszemu
       procesowaniu i marnowaniu zasobów CPU.
     - TestEvaluate_CompromisedPassword: Potwierdza, że hasło jawnie figurujące
       w rejestrach wycieków zostanie oznaczone jako COMPROMISED, niezależnie
       od jego długości czy złożoności znakowej.
     - TestEvaluate_ContextAwareFiltering: Testuje krytyczny wymóg NIST dotyczący
       odrzucania haseł zawierających dane powiązane z tożsamością aplikanta.
       Weryfikuje, czy wstrzyknięcie loginu lub e-maila (nawet jako fragmentu
       dłuższego hasła) poprawnie obniża werdykt do statusu WEAK.
     - TestEvaluate_NetworkErrorFallback_FailOpen: Testuje odporność systemu
       na awarie (Resilience). Udowadnia, że w przypadku awarii sieci (timeout API),
       mikrousługa nie paraliżuje systemu rejestracji klienta, lecz przechodzi
       do oceny lokalnej za pomocą zxcvbn (zasada Fail-Open).
================================================================================
*/
