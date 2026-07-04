# Password Strength Evaluator Microservice

![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Distroless-2496ED?logo=docker)
![Security](https://img.shields.io/badge/Security-HIPAA%20%7C%20FedRAMP-red?logo=shieldsdotio)
![NIST](https://img.shields.io/badge/NIST-SP%20800--63B-blue)
![Image Size](https://img.shields.io/badge/Image%20Size-~25MB-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

Lekka, ultraszybka mikrousługa napisana w języku **Go**, służąca do oceny siły haseł w czasie rzeczywistym. Zaprojektowana specjalnie pod rygorystyczne wymagania branż regulowanych (**HIPAA, FedRAMP**) oraz w oparciu o najnowsze wytyczne **NIST SP 800-63B**.

---

## Spis Treści

📌 [Kluczowe decyzje architektoniczne](#kluczowe-decyzje-architektoniczne-i-założenia-projektowe) &nbsp;•&nbsp;
[Instrukcja uruchomienia](#instrukcja-uruchomienia-i-testowania-usługi) &nbsp;•&nbsp;
[Testowanie API](#jak-przetestować-działanie-punktu-końcowego-api) &nbsp;•&nbsp;
[Architektura testów](#architektura-testów-jednostkowych-i-obsługa-przypadków-brzegowych) &nbsp;•&nbsp;
[Przypadki brzegowe](#2-sprawdzane-przypadki-brzegowe-edge-cases-i-ich-uzasadnienie) &nbsp;•&nbsp;
[Docker i Distroless](#1-dlaczego-wybraliśmy-dockera-i-to-w-wersji-distroless) &nbsp;•&nbsp;
[k-Anonymity](#2-założenia-kryptograficzne-i-ochrona-prywatności-k-anonymity) &nbsp;•&nbsp;
[Zero-Allocation](#3-niskopoziomowa-optymalizacja-wydajności-zero-allocation-parsing) &nbsp;•&nbsp;
[Fail-Open](#4-strategia-fail-open-odporność-na-awarie-komponentów)

---

## Instrukcja uruchomienia i testowania usługi

Mikrousługę można uruchomić lokalnie na dwa sposoby: bezpośrednio przy użyciu środowiska Go lub w odizolowanym, bezpiecznym kontenerze Docker.

---

### Metoda 1: Uruchomienie przez Docker (Rekomendowane)

Dzięki wykorzystaniu zaawansowanego obrazu typu **Distroless**, środowisko uruchomieniowe jest w pełni odizolowane i nie wymaga instalacji Go na maszynie hosta.

**1. Budowanie obrazu produkcyjnego:**

```bash
docker build -t password-validator-prod .
```

**2. Uruchomienie kontenera:**

```bash
docker run -p 8080:8080 password-validator-prod
```

Serwer wystartuje i zacznie nasłuchiwać na porcie `:8080`.

### Metoda 2: Uruchomienie natywne (Wymaga Go 1.25+)

Jeśli wolisz odpalić aplikację bezpośrednio na swojej maszynie:

```bash
go run cmd/server/main.go
```

---

## Jak przetestować działanie punktu końcowego (API)? 

Po uruchomieniu serwera (na porcie 8080), możesz zweryfikować działanie usługi, wysyłając testowe żądania HTTP POST. Wybierz komendę odpowiednią dla Twojego terminala:

### Dla systemów Linux / macOS / Windows WSL 2 (Bash)

```bash
curl -X POST http://localhost:8080/api/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "okenobi",
    "email": "o.kenobi@jedi-council.com",
    "password": "Hello there!"
  }'
```

### Dla systemu Windows (Klasyczny Wiersz Poleceń - CMD)

```cmd
curl -X POST http://127.0.0.1:8080/api/v1/password/evaluate -H "Content-Type: application/json" -d "{\"username\":\"okenobi\",\"email\":\"o.kenobi@jedi-council.com\",\"password\":\"Hello there!\"}"
```

### Dla systemu Windows (PowerShell)

```powershell
$body = @{
    username = "okenobi"
    email = "o.kenobi@jedi-council.com"
    password = "Hello there!"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/v1/password/evaluate" -Method Post -ContentType "application/json" -Body $body
```

### 🎯 Oczekiwana odpowiedź (Werdykt)

```json
{
  "score": 0,
  "verdict": "COMPROMISED",
  "is_compromised": true,
  "feedback": [
    "This password has appeared in historical data breaches and is fundamentally unsafe."
  ]
}
```



## Architektura testów jednostkowych i obsługa przypadków brzegowych

### 1. Problemy napotkane podczas implementacji testów (Lessons Learned)

Podczas pisania testów dla modułu integracji z zewnętrznym API wycieków (HaveIBeenPwned) kluczowym wyzwaniem była **synchronizacja formatowania danych i unikanie podatności testów na zmiany zewnętrzne (brittle tests)**.

*   **Problem z determinizmem danych (Mocking HTTP):** Testy jednostkowe nie mogą uderzać do prawdziwego API HIBP z powodu limitów zapytań (Rate Limiting) oraz braku przewidywalności sieci. Wykorzystano `httptest.NewServer`, aby w pełni kontrolować zwracane dane bajtowe.
*   **Problem z dopasowaniem wielkości liter (Hex Casing):** Wstępne wersje testów używały sztywno zakodowanych ciągów tekstowych sufiksów SHA-1. Ponieważ kod produkcyjny operuje na optymalizacjach niskopoziomowych i konwertuje hash na wielkie litery za pomocą operacji bitowych na surowych bajtach (`[]byte`), ręczne wpisanie sufiksu w teście powodowało błędy dopasowania przez `bytes.Equal`.
*   **Rozwiązanie:** Wdrożono **dynamiczne generowanie mockowanej odpowiedzi serwera**. Serwer testowy w locie oblicza hash SHA-1 testowanego hasła, wycina prefiks i generuje idealną strukturę odpowiedzi `SUFIKS:LICZBA`. Dzięki temu testy są w 100% stabilne, niezależne od wielkości liter i odporne na błędy ludzkie (literówki w hashu).

---

### 2. Sprawdzane przypadki brzegowe (Edge Cases) i ich uzasadnienie

Silnik oceny haseł (`internal/eval`) oraz klient sieciowy (`internal/pwned`) zostały przetestowane pod kątem scenariuszy, które najczęściej kładą systemy produkcyjne w branży regulowanej.

#### A. Hasło skrócone (Zbyt krótkie dane wejściowe)
*   **Przypadek:** Próba przesłania hasła o długości poniżej 8 znaków.
*   **Dlaczego:** Zgodnie z wytycznymi NIST SP 800-63B oraz politykami Gov, 8 znaków to absolutny rygor technologiczny. System odrzuca takie hasło natychmiast na samym początku potoku przetwarzania, zapobiegając marnowaniu zasobów CPU na haszowanie i odpytywanie bazy wycieków dla danych, które i tak są nieakceptowalne.

#### B. Hasło skompromitowane (Real-time Breach Match)
*   **Przypadek:** Przesłanie popularnego hasła (np. `"password"` lub `"Hello there!"`), które figuruje w rejestrach publicznych wycieków.
*   **Dlaczego:** Współczesne ataki to przede wszystkim *Credential Stuffing*. Nawet jeśli hasło spełnia kryteria długości, obecność w bazie wycieków czyni je bezużytecznym. Test upewnia się, że system poprawnie parsuje licznik wycieków i natychmiast degraduje ocenę do `score: 0` oraz werdyktu `COMPROMISED`.

#### C. Wyciek kontekstowy (Context-Aware Filtering)
*   **Przypadek:** Hasło jest długie i teoretycznie silne (wysoka entropia), ale zawiera w sobie login użytkownika, jego adres e-mail lub nazwę organizacji (np. `SuperSecureJan_Jedrasiak2026!`).
*   **Dlaczego:** Użytkownicy masowo generują hasła w oparciu o kontekst (nazwa firmy, nazwisko). Atakujący budują słowniki celowane (targeted wordlists) pod konkretną ofiarę. Test weryfikuje, czy system poprawnie konfiguruje czarną listę użytkownika w algorytmie `zxcvbn` i degraduje werdykt do `WEAK`.

#### D. Awaria sieci zewnętrznej (Strategia Fail-Open / Resilience)
*   **Przypadek:** Zewnętrzne API wycieków zwraca błąd `HTTP 500 Internal Server Error` lub połączenie ulega timeoutowi.
*   **Dlaczego:** Systemy bezpieczeństwa w branżach regulowanych nie mogą paraliżować kluczowych procesów biznesowych (np. rejestracji klienta w banku czy dostępu lekarza do systemu HIPAA) z powodu awarii zewnętrznego dostawcy. Test upewnia się, że mikrousługa wdraża strategię **Fail-Open**: ignoruje błąd sieci, przechodzi do lokalnej oceny entropii i pozwala użytkownikowi założyć konto, o ile hasło lokalne jest wystarczająco silne, logując jednocześnie incydent dla administratorów.



## Kluczowe decyzje architektoniczne i założenia projektowe

Projekt został zaprojektowany z myślą o wdrożeniach w architekturze mikrousług dla branż o wysokim rygorze bezpieczeństwa (**HIPAA, FedRAMP**). Poniżej opisano kluczowe decyzje inżynierskie, które determinują odporność i wydajność systemu.

---

### 1. Dlaczego wybraliśmy Dockera (i to w wersji Distroless)?

Dostarczenie usługi w kontenerze Docker nie służy wyłącznie wygodzie uruchomienia ("it works on my machine"). W środowiskach produkcyjnych klasy Enterprise rezygnacja z Dockera lub użycie standardowych obrazów bazowych (np. Ubuntu, Alpine) jest uznawane za błąd architektoniczny z trzech powodów:

*   **Eliminacja podatności CVE (Hardening):** Tradycyjne kontenery zawierają pełne środowiska systemowe: powłoki (bash, sh), menedżery pakietów (apt, apk) oraz dziesiątki bibliotek. Stanowią one potencjalny wektor ataku – napastnik po przełamaniu aplikacji może użyć basha do eskalacji uprawnień. Zastosowany w projekcie **Google Distroless Image** (`gcr.io/distroless/static-debian12`) zawiera **wyłącznie skompilowany plik binarny Go i certyfikaty SSL**. Nie ma tam shella ani żadnych zbędnych narzędzi, co redukuje liczbę podatności CVE w kontenerze praktycznie do zera.
*   **Zasada minimalnych uprawnień (Non-root user):** Domyślnie Docker uruchamia procesy jako `root`. W naszym Dockerfile jawnie zdefiniowano dyrektywę `USER nonroot:nonroot`. W efekcie, nawet w przypadku krytycznej podatności w aplikacji, napastnik nie przejmie kontroli nad procesem demona Dockera ani systemem hosta. Jest to bezwzględny wymóg standardów **FedRAMP**.
*   **Gwarancja powtarzalności i optymalizacja zasobów:** Wykorzystanie podejścia **Multi-stage build** (kompilacja w kontenerze Go 1.25, a uruchomienie w czystym Distroless) pozwoliło zredukować wagę końcowego obrazu do zaledwie **~25 MB**. Kontener nie niesie ze sobą całego SDK języka Go, kompiluje się statycznie (`CGO_ENABLED=0`) i działa identycznie na każdej infrastrukturze chmurowej (np. AWS EKS, Azure AKS).

---

### 2. Założenia kryptograficzne i ochrona prywatności (k-Anonymity)

Podstawowym założeniem projektowym jest to, że **mikrousługa dba o prywatność i nie jest serwerem typu Trusted-Third-Party**. 
*   **Zero Knowledge dla podmiotów zewnętrznych:** Zgodnie z HIPAA, przesyłanie haseł użytkowników otwartym tekstem do zewnętrznych API jest nielegalne. 
*   Wdrożono protokół **k-Anonymity**: system generuje sumę kontrolną SHA-1 lokalnie, wysyła do HaveIBeenPwned wyłącznie pierwsze 5 znaków hasha (anonimowy prefiks), a strumień odpowiedzi (sufiksy) parsuje w odizolowanej pamięci RAM. Zewnętrzny dostawca nie ma pojęcia, jakie hasło jest sprawdzane, ani kim jest użytkownik.

---

### 3. Niskopoziomowa optymalizacja wydajności (Zero-Allocation Parsing)

Aplikacje autoryzacyjne obsługują najwyższy ruch w całej infrastrukturze (szczyty logowań). Standardowy parser HTTP w Go, operujący na stringach i funkcjach takich jak `strings.Split`, generuje setki alokacji pamięci na stercie (heap allocations) przy każdym żądaniu, zmuszając Garbage Collector do ciągłej pracy i generując skoki opóźnień (tail latency).
*   **Zastosowane rozwiązanie:** Parser w pakiecie `internal/pwned` przetwarza odpowiedź HTTP jako surowy strumień bajtów (`[]byte`), wyszukując znaki końca linii i dwukropki za pomocą operacji niskopoziomowych. Alokacja pamięci na operację parsowania wynosi **0 bajtów**, co zapewnia stałą wydajność rzędu mikrosekund nawet pod gigantycznym obciążeniem.

---

### 4. Strategia Fail-Open (Odporność na awarie komponentów)

Mikrousługa bezpieczeństwa nie może stać się pojedynczym punktem awarii (Single Point of Failure - SPoF) dla całego ekosystemu firmy. Jeśli zewnętrzne API wycieków leży, rejestracja nowych klientów w systemie nadrzędnym musi trwać nadal.
*   **Zastosowane rozwiązanie:** W przypadku timeoutu sieciowego lub błędów HTTP 5xx ze strony API HIBP, system loguje incydent z flagą `ERROR` do celów audytowych, ale przechodzi w tryb **Fail-Open**. Oznacza to, że pomija krok weryfikacji wycieków i opiera ostateczny werdykt wyłącznie na lokalnym teście entropii `zxcvbn`. Jeśli hasło jest długie i unikalne, żądanie zostanie przepuszczone.