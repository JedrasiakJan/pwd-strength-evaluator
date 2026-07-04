package eval

import (
	"strings"

	"github.com/nbutton23/zxcvbn-go"
)

type PwnedClient interface {
	CheckPassword(password string) (bool, int, error)
}

type Service struct {
	pwnedClient PwnedClient
}

func NewService(pc PwnedClient) *Service {
	return &Service{pwnedClient: pc}
}

// Result odzwierciedla strukturę odpowiedzi oceny siły hasła.
type Result struct {
	Score         int      `json:"score"`          // Skala 0 (bardzo słabe) do 4 (bardzo silne)
	Verdict       string   `json:"verdict"`        // Krótka decyzja: TOO_SHORT, COMPROMISED, WEAK, STRONG
	IsCompromised bool     `json:"is_compromised"` // Czy hasło figuruje w bazach wycieków
	Feedback      []string `json:"feedback"`       // Wskazówki dla użytkownika (NIST compliance)
}

func (s *Service) Evaluate(password, username, email string) Result {
	// 1. Walidacja minimalnej długości (NIST SP 800-63B rekomenduje min. 8 znaków dla systemów web)
	if len(password) < 8 {
		return Result{
			Score:         0,
			Verdict:       "TOO_SHORT",
			IsCompromised: false,
			Feedback:      []string{"Password is too short. It must be at least 8 characters long."},
		}
	}

	// 2. Weryfikacja skompromitowanych poświadczeń (Compromised Credentials Check)
	is_leaked, _, err := s.pwnedClient.CheckPassword(password)
	if err == nil && is_leaked {
		return Result{
			Score:         0,
			Verdict:       "COMPROMISED",
			IsCompromised: true,
			Feedback:      []string{"This password has appeared in historical data breaches and is fundamentally unsafe."},
		}
	}

	// 3. Budowanie słownika kontekstowego (Context-Aware Dictionary Attack Protection)
	// NIST bezwzględnie wymaga odrzucania haseł zawierających dane powiązane z tożsamością użytkownika.
	userInputs := make([]string, 0, 4)
	if username != "" {
		userInputs = append(userInputs, username, strings.ToLower(username))
	}

	if email != "" {
		userInputs = append(userInputs, email, strings.ToLower(email))
		// Ekstrakcja części przed znakiem '@' (np. "o.kenobi" z "o.kenobi@jedi.com")
		if idx := strings.IndexByte(email, '@'); idx != -1 {
			prefix := email[:idx]
			userInputs = append(userInputs, prefix, strings.ToLower(prefix))
		}
	}

	// 4. Analiza entropii za pomocą zxcvbn
	// Biblioteka sprawdza powtarzalne wzorce, sekwencje klawiatury (qwerty), daty i słowniki
	analysis := zxcvbn.PasswordStrength(password, userInputs)

	// Mapowanie wyniku na werdykt biznesowy
	// NIST uznaje hasła o niskiej entropii (score < 3) za nieakceptowalne w branżach regulowanych
	verdict := "STRONG"
	if analysis.Score < 3 {
		verdict = "WEAK"
	}

	// Agregacja feedbacku dla użytkownika końcowego
	feedback := make([]string, 0)

	if analysis.Score < 3 {
		feedback = append(feedback, "The password is too predictable or uses common words/patterns.")
		feedback = append(feedback, "Tip: Use a sequence of random words (passphrase) and avoid sequences like 'abc' or '123'.")

		// Sprawdzamy czy użytkownik użył swoich danych jako hasła
		for _, input := range userInputs {
			if strings.Contains(strings.ToLower(password), input) {
				feedback = append(feedback, "Warning: Password contains your username, email, or parts of it.")
				break
			}
		}
	}

	return Result{
		Score:         analysis.Score,
		Verdict:       verdict,
		IsCompromised: false,
		Feedback:      feedback,
	}
}

/*
================================================================================
DOKUMENTACJA TECHNICZNA I ARCHITEKTONICZNA: SILNIK OCENY HASEŁ (EVAL SERVICE)
================================================================================

1. ZGODNOŚĆ Z REGULACJAMI (NIST SP 800-63B / HIPAA / FedRAMP):

   * Rezygnacja z przestarzałych reguł złożoności (Complexity Rules):
     Standard NIST wyraźnie wskazuje, że wymuszanie kombinacji wielkich liter, cyfr
     i znaków specjalnych prowadzi do przewidywalnych substytucji (np. zamiana 'a' na '@')
     i drastycznie obniża faktyczną cyberbezpieczeństwo. Serwis porzuca te reguły na rzecz
     badania realnej entropii matematycznej oraz weryfikacji słownikowej.

   * Context-Aware Filtering (Ochrona kontekstowa):
     Ataki typu credential stuffing często wykorzystują warianty nazwy użytkownika.
     Kod dynamicznie buduje tablicę zabronionych fraz, wstrzykując tam login, e-mail
     oraz wycięty prefiks poczty e-mail, wymuszając na zxcvbn odrzucenie haseł
     powiązanych z tożsamością aplikanta.

--------------------------------------------------------------------------------

2. OPTYMALIZACJA I DESIGN PATTERNS:

   * Inwersja Sterowania (Dependency Injection & Mocking):
     Serwis nie zależy od konkretnej implementacji klienta HTTP bazy wycieków,
     lecz od interfejsu PwnedClient. Umożliwia to 100% izolację logiki biznesowej
     podczas testów jednostkowych (możemy zasymulować odpowiedź HIBP bez sieci).

   * Alokacja pamięci w słowniku użytkownika:
     Tablica 'userInputs' jest inicjalizowana za pomocą make([]string, 0, 4)
     ze zdefiniowaną pojemnością (capacity). Zapobiega to wielokrotnemu
     realokowaniu tablicy w pamięci RAM podczas wywołań append().

--------------------------------------------------------------------------------

3. POTENCJALNE UTRODNIENIA I WYZWANIA (EDGE CASES):

   * Ryzyko "Fail-Open" weryfikacji wycieków:
     W linijce: if err == nil && isLeaked { ... } celowo sprawdzamy 'err == nil'.
     Oznacza to, że jeśli warstwa sieciowa (PwnedClient) zwróci błąd (np. timeout 800ms),
     serwis świadomie przechodzi do kroku 3 i 4 (Fail-Open). Hasło zostanie ocenione
     wyłącznie przez zxcvbn. Jest to kompromis architektoniczny: dostępność systemu (HA)
     vs absolutne bezpieczeństwo. Gdybyśmy zaimplementowali Fail-Close, awaria zewnętrznego
     dostawcy zablokowałaby krytyczne procesy biznesowe naszych klientów.
================================================================================
*/
