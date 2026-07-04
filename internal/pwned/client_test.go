package pwned

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckPassword_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		apiStatus      int
		expectedLeaked bool
		expectedCount  int
		expectError    bool
	}{
		{
			name:           "Password Leaked",
			password:       "password",
			apiStatus:      http.StatusOK,
			expectedLeaked: true,
			expectedCount:  4500,
			expectError:    false,
		},
		{
			name:           "Password Safe",
			password:       "this_is_a_very_safe_and_unleaked_password_2026",
			apiStatus:      http.StatusOK,
			expectedLeaked: false,
			expectedCount:  0,
			expectError:    false,
		},
		{
			name:           "API Returns 500 Error",
			password:       "password",
			apiStatus:      http.StatusInternalServerError,
			expectedLeaked: false,
			expectedCount:  0,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Obliczamy poprawny hash dla testowanego hasła dynamicznie,
			// eliminując ryzyko jakiejkolwiek literówki w teście.
			hasher := sha1.New()
			hasher.Write([]byte(tt.password))
			fullHash := hex.EncodeToString(hasher.Sum(nil))
			suffix := strings.ToUpper(fullHash[5:])

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.apiStatus)
				if tt.apiStatus == http.StatusOK {
					if tt.expectedLeaked {
						// Serwer zwraca dokładnie taki sufiks, jakiego szuka kod
						fmt.Fprintf(w, "%s:%d\n", suffix, tt.expectedCount)
					} else {
						fmt.Fprintln(w, "NOTMATCHINGSUFIXX3A4491E50721E073DEBEE30225:10")
					}
				} else {
					w.Write([]byte("Internal Server Error"))
				}
			}))
			defer server.Close()

			client := NewClient()
			client.baseURL = server.URL

			leaked, count, err := client.CheckPassword(tt.password)

			if (err != nil) != tt.expectError {
				t.Fatalf("Unexpected error state: %v", err)
			}
			if leaked != tt.expectedLeaked {
				t.Errorf("Expected leaked=%v, got %v", tt.expectedLeaked, leaked)
			}
			if count != tt.expectedCount {
				t.Errorf("Expected count=%d, got %d", tt.expectedCount, count)
			}
		})
	}
}

/*
================================================================================
DOKUMENTACJA TECHNICZNA: TESTY INTEGRACYJNE KLIENTA API (PWNED CLIENT TEST)
================================================================================

1. STRATEGIA TESTOWANIA WARSTWY SIECIOWEJ (MOCKING HTTP):

   * Wykorzystanie httptest.NewServer:
     Testowanie klienta HTTP realizowane jest poprzez uruchomienie lokalnego,
     efemerycznego serwera HTTP wewnątrz pamięci procesu testowego Go. Zapobiega
     to jakimkolwiek zapytaniom wychodzącym do sieci publicznej, co wyklucza
     podatność na limity zapytań (Rate Limiting) oraz awarie zewnętrzne.

   * Dynamiczne Generowanie Hashy (Kryptograficzna Stabilność):
     Testy wykorzystują podejście Table-Driven Tests (Testy sterowane tabelą).
     Aby wyeliminować ryzyko błędów ludzkich (literówek w sztywno zakodowanych
     hashach tekstowych), serwer mocka dynamicznie generuje sumę kontrolną SHA-1
     dla przekazanego hasła w locie za pomocą biblioteki crypto/sha1.

   * Weryfikacja Formatowania (k-Anonymity Protocol Consistency):
     - Przypadek "Password Leaked": Weryfikuje zachowanie systemu, gdy serwer
       zwraca poprawny, 35-znakowy sufiks w formacie SUFIKS:LICZBA, symulując
       wykrycie skompromitowanego poświadczenia.
     - Przypadek "Password Safe": Potwierdza, że system poprawnie zwraca brak
       wycieku, jeśli w strumieniu danych wejściowych nie ma idealnego
       dopasowania bajtów sufiksu.
     - Przypadek "API Returns 500 Error": Sprawdza obsługę błędów protokołu HTTP
       i upewnia się, że statusy inne niż 200 OK generują odpowiedni obiekt błędu
       przekazywany do warstwy biznesowej.
================================================================================
*/
