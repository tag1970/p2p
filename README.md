# Prometheus exporter for p2p test case

## Build and run

```bash
go mod init myexporter
go mod tidy
GOOS=linux GOARCH=amd64 go build
```
