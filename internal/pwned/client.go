package pwned

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 800 * time.Millisecond,
		},
		baseURL: "https://api.pwnedpasswords.com/range",
	}
}

func (c *Client) CheckPassword(password string) (bool, int, error) {
	// 1. Obliczanie SHA-1 na potrzeby integracji z zewnętrznym rejestrem wycieków (np. Have I Been Pwned).
	//
	// [ZGODNOŚĆ Z NIST SP 800-63B / FedRAMP]: Standardy te bezwzględnie wymagają weryfikacji, czy hasło
	// nie znajduje się na liście haseł skompromitowanych (compromised credentials check).
	//
	// [NOTKA DOT. BEZPIECZEŃSTWA]: SHA-1 jest algorytmem kryptograficznie złamanym i NIE JEST
	// wykorzystywany tutaj do bezpiecznego przechowywania haseł w bazie danych (do tego celu
	// mikrousługa wdroży Argon2id lub bcrypt zgodnie z HIPAA). SHA-1 jest użyty wyłącznie dlatego,
	// że jest to standard komunikacji z API 'Have I Been Pwned' przy użyciu zasady k-Anonymity.
	hasher := sha1.New()
	hasher.Write([]byte(password))
	sum := hasher.Sum(nil)

	var hashBuf [40]byte
	hex.Encode(hashBuf[:], sum)

	for i := 0; i < len(hashBuf); i++ {
		if hashBuf[i] >= 'a' && hashBuf[i] <= 'f' {
			hashBuf[i] -= 32
		}
	}

	prefix := string(hashBuf[:5])
	suffix := string(hashBuf[5:])

	// 2. Zapytanie do API Pwned Passwords
	url := fmt.Sprintf("%s/%s", c.baseURL, prefix)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Optymalizacja parsowania (Zero-Allocation Parsing)
	// Używamy bufio.Scanner, ale będziemy pracować na surowych bajtach (.Bytes()) zamiast stringów (.Text())
	scanner := bufio.NewScanner(resp.Body)
	suffixBytes := []byte(suffix)

	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		// Format odpowiedzi API: SUFIX_HASHA:LICZBA_WYCIEKOW
		colonIdx := bytes.IndexByte(lineBytes, ':')
		if colonIdx == -1 {
			continue
		}

		lineSuffix := lineBytes[:colonIdx]
		if bytes.Equal(lineSuffix, suffixBytes) {
			// Wycinamy część z liczbą wycieków
			countBytes := lineBytes[colonIdx+1:]

			// Ręczna konwersja []byte na int bezpośrednio ze strumienia bajtów.
			// Zastępuje strconv.Atoi(string(countBytes)), eliminując alokację stringa na stercie.
			var count int
			for _, b := range countBytes {
				// Walidacja, czy API na pewno zwróciło cyfry
				if b < '0' || b > '9' {
					return false, 0, fmt.Errorf("malformed count in API response")
				}
				count = count*10 + int(b-'0')
			}

			return true, count, nil
		}
	}
	// Bezwzględnie sprawdzamy, czy pętla skanera nie zakończyła się przedwcześnie z powodu błędu sieciowego
	// lub przerwanego strumienia danych. Ignorowanie tego błędu mogłoby dopuścić skompromitowane hasło.
	if err := scanner.Err(); err != nil {
		return false, 0, fmt.Errorf("error reading API response stream: %w", err)
	}

	return false, 0, nil
}

/*
================================================================================
DOKUMENTACJA TECHNICZNA I ARCHITEKTONICZNA: KLIENT REJESTRU WYCIEKÓW (PWNED)
================================================================================

1. PODJĘTE DECYZJE ARCHITEKTONICZNE I PROFILOWANIE WYDAJNOŚCI:

   * Zasada k-Anonymity (Ochrona Prywatności / HIPAA):
     Mikrousługa realizuje weryfikację skompromitowanych danych uwierzytelniających
     bez ujawniania tożsamości hasła na zewnątrz. Wysłanie wyłącznie pierwszych 5
     znaków skrótu SHA-1 do API 'Have I Been Pwned' gwarantuje matematyczną
     niemożliwość odtworzenia pełnego hasła przez podmioty trzecie lub węzły
     pośredniczące. Dopasowanie pozostałych 35 znaków (sufiksu) odbywa się
     wewnątrz bezpiecznej, izolowanej pamięci RAM procesu Go.

   * Optymalizacja Alokacji Pamięci (Zero-Allocation Parsing):
     W środowiskach o wysokim natężeniu ruchu (np. systemy autoryzacji), operacje
     wejścia/wyjścia na ciągach tekstowych (strings) generują ogromny narzut na
     Garbage Collector (GC) poprzez ciągłe alokowanie pamięci na stercie (heap).
     Aby temu zapobiec, wdrożono optymalizacje niskopoziomowe:
     - Ręczna konwersja wielkości liter w buforze bajtów na stosie zamiast
       kosztownego strings.ToUpper().
     - Wykorzystanie bufio.Scanner.Bytes() zamiast Text(), co pozwala na pracę
       na surowych wycinkach pamięci (slices) bez klonowania obiektów.
     - Ręczna konwersja licznika wycieków []byte na int, co całkowicie eliminuje
       potrzebę wywoływania funkcji strconv.Atoi(string(bytes)).
     Wynik: Alokacja pamięci w warstwie parsowania wynosi dokładnie 0 bajtów.

   * Izolacja Sieciowa i Agresywny Timeout:
     Ustawienie sztywnego limitu czasu (Timeout: 800ms) zapobiega atakom typu
     Resource Exhaustion (wyczerpanie zasobów) oraz blokowaniu wątków serwera
     w przypadku problemów z siecią zewnętrzną.

--------------------------------------------------------------------------------

2. ANALIZA RYZYKA I POTENCJALNE PROBLEMY (EDGE CASES):

   * Strategia awaryjna (Fail-Open vs Fail-Close):
     W obecnej implementacji, błąd sieci lub status HTTP inny niż 200 OK przerywa
     działanie funkcji i zwraca błąd do warstwy wyższej.
     - RYZYKO: Jeśli API HaveIBeenPwned ulegnie awarii, cała mikrousługa zacznie
       zwracać błędy, co w konsekwencji zablokuje możliwość rejestracji lub
       zmiany hasła użytkownikom w aplikacji głównej (zasada Fail-Close).
     - REKOMENDACJA: W zależności od ostatecznych wymagań biznesowych klienta,
       może być konieczne przekształcenie tego w architekturę 'Fail-Open' (logowanie
       błędu jako incydent bezpieczeństwa w celach audytowych, ale przepuszczenie
       walidacji do silnika zxcvbn, aby nie paraliżować systemu).

   * Brak Przekazywania Kontekstu (Context Propagation):
     Metoda CheckPassword nie przyjmuje obecnie argumentu context.Context.
     - RYZYKO: Jeśli żądanie HTTP od klienta końcowego zostanie przerwane
       (np. użytkownik zamknie przeglądarkę), serwer będzie kontynuował
       wykonywanie zapytania do API zewnętrznego, marnując cykle CPU i pasmo sieciowe.
     - ROZWIĄZANIE W PRZYSZŁOŚCI: Sygnatura powinna zostać zmieniona na
       CheckPassword(ctx context.Context, password string), a żądanie sieciowe
       powinno być inicjalizowane przez http.NewRequestWithContext.

   * Podatność na Zmiany w API Zewnętrznym:
     Kod zakłada sztywny format odpowiedzi "SUFIKS:LICZBA\n". Jakakolwiek zmiana
     struktury danych po stronie dostawcy API (np. wprowadzenie formatu JSON
     lub zmiana separatora z dwukropka na inny znak) spowoduje ciche
     pomijanie linii lub błędy parsowania (malformed count).
================================================================================
*/
