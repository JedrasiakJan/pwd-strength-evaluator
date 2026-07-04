# --- Etap 1: Budowanie aplikacji (Build Stage) ---
FROM golang:1.25-alpine AS builder

# Instalacja certyfikatów CA niezbędnych do bezpiecznej komunikacji z API HaveIBeenPwned przez TLS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Kopiowanie definicji zależności w celu wykorzystania cache Dockera
COPY go.mod go.sum ./
RUN go mod download

# Kopiowanie kodu źródłowego
COPY . .

# Kompilacja statyczna pliku binarnego (wyłączenie CGO, optymalizacja pod kontenery)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /pwd-evaluator ./cmd/server

# --- Etap 2: Środowisko produkcyjne (Runtime Stage) ---
# Używamy oficjalnego obrazu distroless od Google - brak basha, brak podatności CVE
FROM gcr.io/distroless/static-debian12:latest

# Kopiowanie certyfikatów CA z etapu budowania
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Kopiowanie skompilowanej mikrousługi
COPY --from=builder /pwd-evaluator /pwd-evaluator

# Uruchomienie aplikacji z prawami użytkownika nieuprzywilejowanego (Non-root, wymóg FedRAMP)
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/pwd-evaluator"]