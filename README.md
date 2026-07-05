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

### Dokumentacja projektu

- [Kluczowe decyzje architektoniczne](#kluczowe-decyzje-architektoniczne-i-założenia-projektowe)
- [Instrukcja uruchomienia](#instrukcja-uruchomienia-i-testowania-usługi)
- [Testowanie API](#jak-przetestować-działanie-punktu-końcowego-api)
- [Architektura testów](#architektura-testów-jednostkowych-i-obsługa-przypadków-brzegowych)
- [Przypadki brzegowe](#2-sprawdzane-przypadki-brzegowe-edge-cases-i-ich-uzasadnienie)
- [Docker i Distroless](#1-dlaczego-wybraliśmy-dockera-i-to-w-wersji-distroless)
- [k-Anonymity](#2-założenia-kryptograficzne-i-ochrona-prywatności-k-anonymity)
- [Zero-Allocation](#3-niskopoziomowa-optymalizacja-wydajności-zero-allocation-parsing)
- [Fail-Open](#4-strategia-fail-open-odporność-na-awarie-komponentów)

### Polityka haseł 2026 — przewodnik

- [Dlaczego polityka haseł w 2026 wygląda inaczej](#1-dlaczego-polityka-haseł-w-2026-wygląda-inaczej)
- [Minimalna długość zamiast złożoności: passphrases i praktyczne zasady tworzenia haseł](#2-minimalna-długość-zamiast-złożoności-passphrases-i-praktyczne-zasady-tworzenia-haseł)
- [Menedżery haseł w organizacji: wymagania, wdrożenie i dobre praktyki użytkowników](#3-menedżery-haseł-w-organizacji-wymagania-wdrożenie-i-dobre-praktyki-użytkowników)
- [MFA i passkeys jako kierunek docelowy: gdzie hasła nadal są potrzebne, a gdzie nie](#4-mfa-i-passkeys-jako-kierunek-docelowy-gdzie-hasła-nadal-są-potrzebne-a-gdzie-nie)
- [Ochrona przed atakami: blokady po próbach, rate limiting, credential stuffing i monitoring logowań](#5-ochrona-przed-atakami-blokady-po-próbach-rate-limiting-credential-stuffing-i-monitoring-logowań)

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



## 📖 Nowoczesna polityka uwierzytelniania w 2026 roku

---

### 1. Dlaczego polityka haseł w 2026 wygląda inaczej

W 2026 hasło coraz rzadziej jest jedyną linią obrony, a coraz częściej jednym z elementów większego układu: aplikacje i usługi wspierają logowanie bezhasłowe, a organizacje częściej wymagają dodatkowej weryfikacji tożsamości. Jednocześnie hasła nie zniknęły — nadal są powszechne w wielu systemach, integracjach i procesach awaryjnych. Dlatego nowoczesna polityka haseł musi być realistyczna, spójna i przyjazna użytkownikom, bo tylko wtedy będzie faktycznie stosowana.

Najważniejsza zmiana polega na odejściu od „haseł-łamigłówek” (częste wymuszanie znaków specjalnych, cykliczne zmiany, arbitralne reguły) na rzecz podejścia opartego na aktualnych standardach, analizie ryzyka i ochronie przed realnymi atakami. Polityka ma minimalizować przejęcia kont, ale bez generowania kosztów i obejść typu zapisywanie haseł na kartkach czy tworzenie przewidywalnych wariantów.

#### Co wymusiło zmianę: standardy i praktyka
W ostatnich latach podejście do haseł zostało mocno ujednolicone przez rekomendacje branżowe (np. NIST SP 800-63) oraz praktyki dostawców usług i audytów. Wspólny mianownik jest prosty: użytkownicy nie powinni być zmuszani do zachowań, które obniżają bezpieczeństwo, nawet jeśli „na papierze” wyglądają na rygorystyczne.

W praktyce oznacza to, że polityka haseł w 2026 powinna kłaść nacisk na:
* **odporność na typowe ataki** (próby przejęcia konta oparte o znane wycieki, automatyzację i socjotechnikę),
* **użyteczność** (żeby użytkownik nie musiał obchodzić zasad),
* **spójność między systemami** (żeby nie powstawał chaos reguł w zależności od aplikacji),
* **zgodność z kierunkiem bezhasłowym** (tak, by hasła nie blokowały wdrożeń MFA i passkeys).

#### Najważniejsze zagrożenia w 2026: inne niż „zgadnięcie hasła”
Klasyczne „brute force” wciąż istnieje, ale w środowiskach produkcyjnych częściej wygrywają ataki, które omijają „siłę” hasła:
* **Credential stuffing** — automatyczne testowanie par login/hasło z wcześniejszych wycieków na wielu usługach, licząc na ponowne użycie hasła.
* **Phishing i przejęcia sesji** — użytkownik może podać hasło na fałszywej stronie, a napastnik wykorzysta je od razu lub przejmie tokeny sesyjne.
* **Ataki na procesy odzyskiwania dostępu** — słabe linki resetu, łatwe pytania bezpieczeństwa, zbyt proste procedury wsparcia.
* **Automatyzacja na dużą skalę** — boty testujące logowania, rejestracje, API i punkty integracyjne, gdzie polityka bywa niespójna.
* **Ryzyko wewnętrzne i udostępnianie kont** — hasła krążą w mailach, komunikatorach lub wśród zespołów, jeśli polityka i narzędzia tego nie adresują.

> **Wniosek:** Samo „wymyślenie trudniejszego hasła” nie rozwiązuje problemu, jeśli organizacja nie ma mechanizmów ograniczających nadużycia i wykrywających podejrzane logowania.

#### Czego unikać: „absurdy”, które psują bezpieczeństwo
W 2026 wiele starszych praktyk jest uznawanych za kontrproduktywne, bo prowadzą do przewidywalnych zachowań użytkowników i wzrostu obciążeń operacyjnych. Najczęstsze pułapki to:
* Wymuszanie cyklicznej zmiany hasła bez powodu — sprzyja tworzeniu wariantów typu „Haslo!2026”, a nie realnie lepszych haseł.
* Sztywne reguły złożoności (np. „musi być wielka litera, cyfra i znak specjalny”) jako główny filar polityki — użytkownicy wybierają wtedy schematy łatwe do odgadnięcia.
* Ograniczanie długości lub blokowanie spacji i znaków z innych alfabetów — to utrudnia tworzenie dobrych, długich haseł i fraz.
* Zbyt agresywne blokady kont bez kontroli nadużyć — mogą stać się narzędziem do łatwego wywołania niedostępności (atak typu lockout).
* Ujednolicenie haseł „dla wygody” (wiele systemów, to samo hasło) — zwiększa skutki pojedynczego wycieku.
* Przerzucanie odpowiedzialności na użytkownika bez wsparcia narzędziami — jeśli organizacja nie daje bezpiecznych mechanizmów, ludzie i tak znajdą drogę na skróty.

#### Co to oznacza dla polityki: kierunek zamiast szczegółów
Nowoczesna polityka haseł w 2026 ma wspierać trzy cele: ograniczyć przejęcia kont, zmniejszyć tarcie dla użytkownika i ułatwić egzekwowanie oraz audyt. Dlatego powinna być budowana w powiązaniu z zasadami dostępu, sposobami logowania i ochroną procesu resetu, a nie jako oderwana lista zakazów i nakazów.

W praktyce oznacza to odejście od „hasło ma wyglądać skomplikowanie” na rzecz „hasło ma być trudne do przejęcia w realnych warunkach”, a resztę mają domknąć mechanizmy organizacyjne i techniczne.

---

### 2. Minimalna długość zamiast złożoności: passphrases i praktyczne zasady tworzenia haseł

W 2026 coraz więcej organizacji odchodzi od polityk typu „musi zawierać wielką literę, cyfrę i znak specjalny” na rzecz prostszej, skuteczniejszej zasady: liczy się długość i unikalność. Wymuszanie skomplikowanych kompozycji często kończy się przewidywalnymi wzorcami (np. zamiana „a” na „@”, dopisywanie „1!” na końcu), które nie dają realnej przewagi wobec współczesnych ataków, a jednocześnie zwiększają frustrację i liczbę resetów. 

Najbardziej praktyczną formą „długiego hasła” jest **passphrase**, czyli fraza-hasło: kilka zwykłych słów ułożonych w łatwe do zapamiętania zdanie lub sekwencję. Taka konstrukcja ma wysoką entropię dzięki długości, a jednocześnie jest przyjazna użytkownikowi, bo nie wymaga żonglowania znakami.

#### Co zastępuje „złożoność” i dlaczego to działa
* **Długość:** dłuższe hasła są trudniejsze do złamania metodami offline, a w praktyce dają więcej niż wymuszanie znaków specjalnych.
* **Unikalność:** każde konto powinno mieć inne hasło; ponowne użycie jest jedną z najczęstszych przyczyn przejęć po wyciekach.
* **Brak przewidywalnych schematów:** polityki „złożoności” prowadzą do schematów, które atakujący zakładają w słownikach i regułach.

#### Passphrases w praktyce: jak tworzyć dobre frazy
Dobra passphrase jest długa, naturalna do zapamiętania i nieoczywista. Warto myśleć o niej jak o mini-historii lub obrazie w głowie. Nie musi zawierać znaków specjalnych, jeśli jest wystarczająco długa, ale może je zawierać, jeśli pomagają w zapamiętaniu.
* Łącz kilka słów, które nie tworzą popularnego cytatu ani znanego zwrotu.
* Unikaj danych osobistych i firmowych, które można zgadnąć lub znaleźć (imiona bliskich, nazwa organizacji, projekt, rok).
* Jeśli dodajesz separator (spacja, myślnik), rób to dla czytelności; nie traktuj tego jako „wymogu bezpieczeństwa”.
* W miarę możliwości unikaj krótkich haseł „ulepszonych” przez dopisanie cyfry lub „!” — to zwykle przewidywalne.

#### Ile znaków wymagać: praktyczne minimum
Minimalna długość powinna odzwierciedlać ryzyko i typ konta. W większości przypadków rozsądny standard to co najmniej 14–16 znaków, a dla kont uprzywilejowanych (administracyjnych) więcej. Najważniejsze jest, by minimalna długość nie wymuszała kompromisów w użyteczności, bo to prowadzi do obchodzenia zasad.

Równolegle warto ustalić maksymalną dopuszczalną długość na sensownie wysokim poziomie, aby nie blokować użycia passphrases i menedżerów haseł. Zbyt niski limit maksymalny bywa cichym „psuciem” bezpieczeństwa, bo zmusza do skracania mocnych haseł.

#### Czego unikać w zasadach tworzenia haseł
* Wymuszonej rotacji „co 30/60/90 dni” bez powodu — często kończy się dopisywaniem kolejnych numerów i spadkiem jakości haseł.
* Zbyt agresywnych reguł składu, które utrudniają tworzenie długich haseł i zwiększają liczbę resetów.
* Blokowania wklejania w polu hasła — to zniechęca do korzystania z menedżerów i sprzyja słabszym hasłom.
* „Wskazówek do hasła”, które ujawniają informacje pomocne w odgadnięciu.
* Ograniczania do krótkich zestawów znaków lub niskich limitów długości, które niepotrzebnie redukują przestrzeń haseł.

> 💡 **Pro tip:** Stawiaj na passphrase: 4–6 niepowiązanych słów ułożonych w zapamiętywalną frazę (zwykle 14–16+ znaków) daje więcej niż „@1!” i inne przewidywalne sztuczki. Każde konto ma mieć inne hasło, a polityka nie może ucinać maksymalnej długości ani blokować wklejania — to sabotuje menedżery haseł.

---

### 3. Menedżery haseł w organizacji: wymagania, wdrożenie i dobre praktyki użytkowników

W 2026 menedżer haseł jest praktycznym „systemem operacyjnym” dla logowania: porządkuje dostęp do setek kont, zmniejsza powtórzenia haseł i ogranicza ryzyko wynikające z ręcznego przechowywania sekretów. W polityce haseł menedżer nie jest dodatkiem, tylko mechanizmem egzekwującym dobre nawyki (unikalne, długie hasła) bez obciążania użytkowników.

#### Do czego menedżer haseł ma służyć w firmie (i do czego nie)
* Przechowywanie i generowanie unikalnych haseł dla usług firmowych i zewnętrznych.
* Bezpieczne współdzielenie dostępów w zespole (z kontrolą uprawnień), zamiast przekazywania haseł na czacie lub w mailu.
* Onboarding/offboarding: szybkie nadawanie i odbieranie dostępu do współdzielonych zasobów.
* Porządkowanie „shadow IT”: centralny, audytowalny sposób przechowywania sekretów używanych do narzędzi SaaS.
* **Nie:** przechowywanie sekretów infrastrukturalnych w stylu kluczy API/sekretów aplikacyjnych jako jedynego magazynu (do tego zwykle służą wyspecjalizowane sejfy sekretów). Menedżer haseł ma przede wszystkim rozwiązywać problem kont użytkowników i kont współdzielonych.

#### Wymagania dla menedżera haseł w organizacji
Wybór narzędzia powinien wynikać z potrzeb zarządczych i bezpieczeństwa, a nie tylko z wygody. Minimalny zestaw wymagań w środowisku firmowym:
* **Model organizacyjny:** zespoły/vaulty, role i uprawnienia (kto może widzieć, edytować, udostępniać).
* **Udostępnianie z kontrolą:** współdzielone elementy bez „przekazywania hasła”, możliwość odebrania dostępu bez zmiany hasła (gdy narzędzie to wspiera) lub przynajmniej szybka rotacja w obrębie współdzielonego vaultu.
* **Audyt i logi:** zdarzenia administracyjne i użytkownika (logowania, udostępnienia, eksporty), integracja z SIEM/centralnym logowaniem.
* **Integracja z tożsamością:** SSO (SAML/OIDC) oraz SCIM do automatycznego tworzenia/wyłączania kont; wsparcie dla polityk dostępu warunkowego, jeśli organizacja je stosuje.
* **MFA dla sejfu:** możliwość wymuszenia silnego uwierzytelnienia do samego menedżera (nie mylić z MFA do usług docelowych).
* **Bezpieczne odzyskiwanie:** procedury i mechanizmy dla utraty urządzenia/dostępu (w tym scenariusze dla administratorów), bez obchodzenia zabezpieczeń.
* **Obsługa urządzeń i przeglądarek:** aplikacje desktop/mobile, rozszerzenia przeglądarek, wsparcie dla polityk MDM (jeśli firma zarządza urządzeniami).
* **Separacja prywatne/służbowe:** jasny model, czy dopuszczasz prywatny sejf użytkownika obok służbowego, oraz jak wygląda przenoszenie danych przy odejściu pracownika.
* **Kontrola eksportu:** możliwość ograniczenia/monitorowania eksportu haseł i pracy „offline” (w zależności od ryzyka).

#### Modele wdrożenia: co wybrać i kiedy

| Model | Najlepszy gdy… | Ryzyka/uwagi |
| :--- | :--- | :--- |
| **Cloud (SaaS)** | chcesz szybkiego startu, łatwych integracji z SSO/SCIM i niskiego kosztu utrzymania | wymaga oceny dostawcy, umów, lokalizacji danych i logowania zdarzeń |
| **Self-hosted** | masz wymagania regulacyjne/techniczne lub potrzebujesz pełnej kontroli nad środowiskiem | utrzymanie, aktualizacje, kopie zapasowe i bezpieczeństwo spoczywają na tobie |
| **Hybrydowy** | część zespołów pracuje w środowiskach o podwyższonych wymaganiach | większa złożoność, kluczowe jest spójne zarządzanie tożsamością i audyt |

#### Plan wdrożenia (bez „wielkiej rewolucji”)
1. **Inwentaryzacja:** gdzie dziś są hasła (przeglądarki, pliki, notatniki, czaty), jakie są konta współdzielone i które narzędzia SaaS są krytyczne.
2. **Projekt struktury:** vaulty per zespół/projekt, zasady nadawania ról, właściciele vaultów, proces proszenia o dostęp.
3. **Integracja z tożsamością:** SSO jako domyślny sposób logowania do menedżera, SCIM do automatyzacji cyklu życia kont.
4. **Pilotaż:** mała grupa (np. IT/Finanse/Sprzedaż) i typowe scenariusze: generowanie haseł, współdzielenie, onboarding, odzyskiwanie.
5. **Migracja:** przeniesienie haseł z przeglądarek i „nieformalnych” miejsc do sejfu; priorytet dla kont administracyjnych i współdzielonych.
6. **Polityki i egzekwowanie:** wymuszenie MFA do sejfu, blokada niebezpiecznych praktyk (np. zakaz wysyłania haseł w mailu), oraz jasne reguły dla kont współdzielonych.
7. **Szkolenie krótkie i praktyczne:** 30–45 minut z naciskiem na codzienne nawyki (autouzupełnianie, generowanie, udostępnianie) + checklisty.

#### Dobre praktyki dla użytkowników (proste reguły, które działają)
* **Trzymaj hasła w jednym miejscu:** firmowy menedżer jest domyślnym magazynem; nie duplikuj w notatkach, plikach ani w przeglądarce „dla wygody”.
* **Generuj, nie wymyślaj:** dla kont w menedżerze używaj generatora (unikalne, długie hasła); ręczne hasła zostaw tylko tam, gdzie naprawdę musisz coś wpisać ręcznie.
* **Nie udostępniaj hasła – udostępniaj wpis:** jeśli ktoś potrzebuje dostępu, dodaj go do współdzielonego vaultu/elementu zgodnie z rolą, zamiast przesyłać sekret.
* **Oznaczaj i porządkuj:** tagi/zespoły/projekty, opis „do czego jest konto”, właściciel biznesowy, link do systemu.
* **Minimalizuj konta współdzielone:** jeśli już muszą istnieć, to tylko w vaultach zespołowych z właścicielem i jasno przydzielonymi uprawnieniami.
* **Uważaj na phishing:** autouzupełnianie pomaga wykrywać fałszywe domeny (brak dopasowania), ale nie zastępuje czujności; zawsze sprawdzaj adres usługi.
* **Chroń „hasło główne”/dostęp do sejfu:** nie zapisuj go obok urządzenia; traktuj menedżer jak klucz do wszystkich drzwi.
* **Oddziel prywatne od służbowego:** nie mieszaj kont osobistych z firmowymi, jeśli polityka tego zabrania; jeśli dopuszcza — trzymaj je w rozdzielonych sejfach.

#### Krótka lista kontrolna dla IT/bezpieczeństwa
* SSO + SCIM włączone, role administracyjne minimalne.
* Wymuszone MFA do menedżera, polityka urządzeń (MDM) tam, gdzie ma to sens.
* Zdefiniowane vaulty zespołowe i proces udostępniania (kto zatwierdza).
* Włączone logowanie zdarzeń i przegląd najważniejszych alertów (np. masowe eksporty, nietypowe logowania).
* Procedura odzyskiwania dostępu i scenariusz awaryjny dla kont krytycznych.

> Największą wartością menedżera haseł w organizacji jest to, że zamienia „politykę na papierze” w codzienną praktykę: użytkownicy mogą mieć unikalne sekrety bez wysiłku, a firma zyskuje kontrolę nad współdzieleniem, audytem i cyklem życia dostępów.

---

### 4. MFA i passkeys jako kierunek docelowy: gdzie hasła nadal są potrzebne, a gdzie nie

W 2026 hasło coraz rzadziej jest „główną linią obrony”. Coraz częściej pełni rolę mechanizmu awaryjnego albo elementu kompatybilności w starszych systemach, a ciężar bezpieczeństwa przejmują MFA (uwierzytelnianie wieloskładnikowe) i passkeys (logowanie oparte o klucze kryptograficzne). Dobrze zaprojektowana polityka haseł powinna więc zakładać, że: tam, gdzie to możliwe, ograniczamy użycie haseł, a tam, gdzie muszą pozostać — wzmacniamy je dodatkowymi warstwami.

#### Passkeys: „bezhasłowe” logowanie, które eliminuje klasyczne ryzyka
Passkeys to metoda logowania oparta o kryptografię klucza publicznego (standardy w ekosystemie FIDO2/WebAuthn). Użytkownik nie wpisuje sekretu, tylko potwierdza tożsamość na urządzeniu (np. PIN/biometria do odblokowania klucza). Klucz prywatny nie opuszcza urządzenia, a serwis dostaje jedynie dowód posiadania.
* **Odporność na phishing** (w typowym scenariuszu) — passkey jest powiązany z konkretną domeną/usługą, więc „podrobiona strona” zwykle nie zadziała.
* **Brak „hasła do wycieku”** — w razie incydentu po stronie serwisu napastnik nie dostaje materiału do łamania offline.
* **Mniej tarcia dla użytkownika** — nie ma resetów haseł z powodu zapomnienia, jeśli organizacja zadba o sensowny proces odzyskiwania dostępu.

W praktyce passkeys są kierunkiem docelowym dla aplikacji i usług, które mają nowoczesny front (web/mobile) i mogą wdrożyć WebAuthn/FIDO2. W polityce warto rozdzielić obszary ich wdrażania.

#### MFA: dodatkowy składnik, gdy hasło nadal istnieje
MFA oznacza użycie co najmniej dwóch niezależnych składników (coś, co użytkownik zna + coś, co ma lub czym jest). W kontekście polityki haseł MFA jest kluczowe tam, gdzie hasło nadal jest wymagane: znacząco ogranicza skutki wycieku lub przejęcia hasła.

Nie wszystkie metody MFA są równie odporne. W polityce warto jasno rozróżnić mechanizmy:
* **Najsilniejsze (zalecane):** klucze sprzętowe FIDO2/WebAuthn, aplikacje uwierzytelniające generujące kody jednorazowe (TOTP), powiadomienia push z „number matching”.
* **Słabsze (tylko awaryjnie lub w wyjątkach):** SMS/połączenie głosowe — ze względu na ryzyka związane z przejęciem numeru (SIM swapping) i socjotechniką.

#### Gdzie hasła nadal są potrzebne (realistycznie)
Nawet przy ambitnym przejściu na passkeys, hasła często pozostają w kilku obszarach. Polityka powinna je nazwać i ograniczyć do minimum:
1. **Systemy legacy** i urządzenia, które nie wspierają nowoczesnych metod (część VPN/VDI, starsze aplikacje biznesowe, urządzenia sieciowe, niektóre drukarki/IoT).
2. **Kontener „fallback”** — awaryjne logowanie, gdy użytkownik nie ma dostępu do urządzenia z passkey (tu kluczowe są procedury odzyskiwania i kontrola ryzyka).
3. **Konta serwisowe / integracje** — tam, gdzie wciąż używa się sekretów aplikacyjnych (choć docelowo lepiej zastępować je tokenami, certyfikatami lub tożsamością maszynową).
4. **Środowiska o ograniczonej łączności** lub specyficznych wymaganiach (np. stacje kioskowe, segmenty OT) — zależnie od możliwości technicznych.

#### Gdzie hasła nie powinny być pierwszym wyborem
Jeśli usługa może wspierać passkeys lub silne MFA, to hasło jako jedyny mechanizm uwierzytelnienia powinno być traktowane jako rozwiązanie tymczasowe:
* **SSO do aplikacji firmowych** — preferowane centralne logowanie z MFA/passkeys zamiast wielu lokalnych haseł.
* **Dostęp administracyjny** — konta uprzywilejowane powinny mieć silniejsze wymagania (sprzętowy klucz lub passkey, dodatkowe kontrole dostępu).
* **Aplikacje wystawione do Internetu** — logowanie tylko hasłem znacząco zwiększa podatność na credential stuffing.

#### Porównanie: hasło + MFA vs passkeys

| Obszar | Hasło + MFA | Passkeys |
| :--- | :--- | :--- |
| **Odporność na phishing** | Średnia–wysoka (zależy od metody MFA) | Wysoka (zwykle powiązanie z domeną) |
| **Ryzyko wycieku z serwisu** | Hasła mogą wyciec (nawet jako hashe) | Brak hasła do wycieku (klucz prywatny u użytkownika) |
| **Wygoda użytkownika** | Umiarkowana (pamiętanie/zmiany, kody) | Wysoka (potwierdzenie na urządzeniu) |
| **Kompatybilność z legacy** | Zwykle dobra | Ograniczona (wymaga wsparcia aplikacji i OS) |
| **Odzyskiwanie dostępu** | Znane, ale często nadużywane kanały | Wwymaga dobrego procesu i procedur IT |

#### Jak ująć to w polityce: proste zasady decyzyjne
* Preferuj passkeys dla nowych aplikacji i systemów, które można dostosować — jako domyślny sposób logowania użytkowników.
* Jeśli hasło pozostaje, to MFA jest obowiązkowe dla dostępu z Internetu, dla kont uprzywilejowanych i dla zasobów wrażliwych.
* Ogranicz wyjątki: jeśli gdzieś nie da się wdrożyć MFA/passkeys, wymagaj formalnej akceptacji ryzyka i planu modernizacji.
* Oddziel „logowanie człowieka” od „tożsamości aplikacji”: dla integracji i automatyzacji dąż do mechanizmów innych niż hasła (np. klucze/poświadczenia krótkotrwałe).

---

### 5. Ochrona przed atakami: blokady po próbach, rate limiting, credential stuffing i monitoring logowań

W 2026 „polityka haseł” nie kończy się na wymaganiach dla użytkownika. Największą różnicę robi ochrona mechanizmu logowania: to ona ogranicza skuteczność ataków online (zgadywanie haseł, automaty, botnety, credential stuffing). Dobre zasady są proste: spowalniaj atakującego, nie karz legalnych użytkowników i zbieraj sygnały o nadużyciach.

#### Blokady konta po próbach: ostrożnie, bo to też wektor ataku
Klasyczna blokada konta po X błędnych próbach bywa ryzykowna, bo pozwala na Denial of Service: ktoś może celowo blokować konta pracowników (zwłaszcza gdy zna ich loginy). Dlatego w nowoczesnych podejściach częściej stosuje się blokady „inteligentne” lub blokady czasowe zamiast trwałego zablokowania.
* **Blokada czasowa (cooldown)** – po serii nieudanych prób wymagaj odczekania (np. rosnąco: 30 s, 2 min, 10 min), zamiast trwałej blokady.
* **Blokada zależna od ryzyka** – ostrzejsza, gdy widać automatyzację (wiele prób, wiele kont, nietypowa lokalizacja/IP/ASN, brak cookies), łagodniejsza przy zachowaniu typowych wzorców użytkownika.
* **Blokada na „kombinację”** – np. na parę konto + adres IP lub konto + fingerprint sesji, żeby nie blokować całego konta przez ruch z jednego źródła.

> W praktyce często lepsze jest spowalnianie i filtrowanie (rate limiting, wykrywanie botów) niż twarda blokada konta.

#### Rate limiting: podstawowe narzędzie przeciw automatom
Rate limiting ogranicza tempo prób logowania. Jest skuteczny, bo ataki online wygrywa się skalą i szybkością. Kluczowe jest ograniczanie na kilku wymiarach jednocześnie:
* **Per IP** – redukuje najprostsze ataki z jednego źródła.
* **Per konto (username/email)** – chroni konkretne konto, gdy IP się zmienia (np. botnet).
* **Per urządzenie/sesję** – np. cookie, token urządzenia; pomaga odróżnić człowieka od automatu.
* **Per podsieć / ASN / region** – przydaje się, gdy widać nadużycia z określonych zakresów.

Warto łączyć rate limiting z krótkim opóźnieniem odpowiedzi (np. stałe 200–500 ms) oraz progresywnym backoff przy kolejnych błędach. To podnosi koszt ataku bez drastycznego pogorszenia UX.

#### Porównanie mechanizmów ochrony

| Mechanizm | Co ogranicza | Typowy efekt uboczny | Kiedy ma sens |
| :--- | :--- | :--- | :--- |
| **Blokada konta (twarda)** | Próby na jedno konto | DoS na użytkownika | Rzadko; głównie w systemach o wysokim ryzyku |
| **Cooldown / backoff** | Szybkość prób | Chwilowe opóźnienia przy pomyłkach | Domyślnie w większości aplikacji |
| **Rate limiting** | Masowe ataki automatyczne | Wymaga stałego strojenia progów | Wszędzie, szczególnie publiczne punkty logowania |
| **Weryfikacja CAPTCHA** | Boty i skrypty | Utrudnienie UX / dostępności | Warunkowo: dopiero po wykryciu anomalii ryzyka |

#### Credential stuffing: najczęstszy realny scenariusz
Credential stuffing to masowe próby logowania skradzionymi parami login/hasło z wycieków. W odróżnieniu od „zgadywania”, tutaj hasła często są poprawne — więc same wymagania dotyczące złożoności niewiele dają. Obrona opiera się na wykrywaniu wzorców i redukcji automatyzacji:
* **Wykrywanie anomalii:** wiele kont z jednego IP, wiele IP na jedno konto, szybkie przełączanie kont, nietypowe nagłówki klienta.
* **Warunkowe zaostrzenie logowania:** po sygnale ryzyka wymagaj dodatkowego kroku (np. ponowne potwierdzenie), zamiast utrudniać wszystkim zawsze.
* **Ujednolicone komunikaty błędu:** nie ujawniaj, czy to login czy hasło jest błędne (ogranicza enumerację kont).
* **Ochrona endpointów pomocniczych:** limity i monitorowanie także na „reset hasła”, „sprawdź czy konto istnieje”, bo tam często zaczyna się automatyzacja.

#### Monitoring logowań: sygnały, które powinny trafić do alertów
* **Zdarzenia do logowania:** udane/nieudane logowania, użycie mechanizmów odzyskiwania dostępu, zmiany w konfiguracji konta, zmiany urządzenia/przeglądarki, zmiany adresu email/telefonu.
* **Kontekst:** czas, identyfikator konta, IP/ASN (lub przybliżona geolokalizacja), identyfikator aplikacji/klienta, wynik polityki (np. „rate-limited”, „cooldown applied”).
* **Alerty wysokiego priorytetu:** wiele nieudanych prób na jedno konto, skokowy wzrost nieudanych logowań w skali systemu, udane logowanie po serii błędów, logowanie z nietypowej lokalizacji po krótkim czasie (twz. „impossible travel”), nadużycia na endpointach resetu.
* **Wskaźniki operacyjne:** odsetek logowań zablokowanych przez limity, liczba kont „atakowanych”, top źródeł ruchu automatycznego.

> Jednocześnie należy uważać na prywatność: loguj minimum potrzebne do bezpieczeństwa, ogranicz dostęp do logów i stosuj retencję zgodną z wymaganiami organizacji.

#### Krótki wzorzec konfiguracji (przykład)
Poniższy szkic pokazuje ideę: limity na IP i konto, rosnący cooldown oraz warunkowe „human check” dopiero po przekroczeniu progów. To nie jest gotowa polityka — raczej punkt startowy do strojenia pod własny ruch.

```yaml
# Pseudokonfiguracja ochrony punktu logowania
login_protection:
  rate_limits:
    per_ip:
      window: 10m
      max_attempts: 30
    per_account:
      window: 15m
      max_attempts: 10
  cooldown_backoff:
    after_failed_attempts: [5, 8, 10]
    cooldowns: [30s, 2m, 10m]
  risk_steps:
    if_suspected_automation:
      require_human_check: true
    if_credential_stuffing_pattern:
      tighten_limits_factor: 0.5
  errors:
    message: "Nieprawidłowe dane logowania"
