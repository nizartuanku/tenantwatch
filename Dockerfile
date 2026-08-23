# Build
FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -ldflags "-s -w" -o /tenantwatch ./cmd/tenantwatch
# Run
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /tenantwatch /usr/local/bin/tenantwatch
EXPOSE 8430
ENTRYPOINT ["tenantwatch","-listen","0.0.0.0:8430"]
