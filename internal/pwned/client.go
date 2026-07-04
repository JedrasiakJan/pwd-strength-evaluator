package pwned

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 800 * time.Millisecond,
		},
	}
}

func (c *Client) Checkpassword(password string) (bool, int, error) {
	// 1. Obliczanie SHA-1 na potrzeby integracji z zewnętrznym rejestrem wycieków (np. Have I Been Pwned).
	//
	// [ZGODNOŚĆ Z NIST SP 800-63B / FedRAMP]: Standardy te bezwzględnie wymagają weryfikacji, czy hasło
	// nie znajduje się na liście haseł skompromitowanych (compromised credentials check).
	//
	// [NOTKA DOT. BEZPIECZEŃSTWA]: SHA-1 jest algorytmem kryptograficznie złamanym i NIE JEST
	// wykorzystywany tutaj do bezpiecznego przechowywania haseł w bazie danych (do tego celu
	// mikrousługa wdroży Argon2id lub bcrypt zgodnie z HIPAA). SHA-1 jest użyty wyłącznie dlatego,
	// że jest to standard komunikacji z API 'Have I Been Pwned' przy użyciu zasady k-Anonymity.
	h := sha1.New()
	h.Write([]byte(password))
	hash := fmt.Sprintf("%X", h.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	// 2. Zapytanie do API Pwned Passwords
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Inicjalizacja skanera do strumieniowego przetwarzania odpowiedzi linia po linii.
	// [WYDAJNOŚĆ]: Zapobiega to alokacji dużej ilości pamięci RAM przy parsowaniu odpowiedzi z API.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// API 'Have I Been Pwned' zwraca dane w formacie: SUFIX_HASHA:LICZBA_WYCIEKOW
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			// Sprawdzenie, czy przesłany z zewnątrz sufiks hasła pasuje do rekordu z bazy wycieków
			if parts[0] == suffix {
				// Konwersja liczby wycieków z formatu string na integer
				count, _ := strconv.Atoi((parts[1]))

				// [ZGODNOŚĆ Z NIST SP 800-63B]: Hasło zostaje jednoznacznie uznane za skompromitowane.
				// Mikrousługa natychmiast zwraca fakt znalezienia hasła (true) oraz skalę ryzyka (count).
				return true, count, nil
			}
		}
	}

	// Bezwzględnie sprawdzamy, czy pętla skanera nie zakończyła się przedwcześnie z powodu błędu sieciowego
	// lub przerwanego strumienia danych. Ignorowanie tego błędu mogłoby dopuścić skompromitowane hasło.
	if err := scanner.Err(); err != nil {
		return false, 0, fmt.Errorf("error reading API response stream: %w", err)
	}

	return false, 0, nil
}
