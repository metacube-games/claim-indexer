FROM golang:latest AS build

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

RUN useradd -u 1001 metacube

COPY main.go .

RUN go build -ldflags="-linkmode external -extldflags -static" -buildvcs=false -o main .

RUN apt-get update && apt-get install ca-certificates -y

RUN update-ca-certificates

FROM scratch

COPY --from=build /etc/passwd /etc/passwd

COPY --from=build /app/main main

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER metacube

ENTRYPOINT ["./main"]
