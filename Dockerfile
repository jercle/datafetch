# One image for every tool: the tool is the first argument.
#   docker build -t datafetch --build-arg VERSION=1.2.3 .
#   docker run datafetch az-storage -loop
ARG GO_VERSION=1.27.4
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/jercle/datafetch/internal/version.Version=${VERSION}" \
    -o /out/datafetch ./cmd/datafetch

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/datafetch /datafetch
# dmarc-reporting's health endpoint.
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/datafetch"]
