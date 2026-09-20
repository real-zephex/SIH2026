<project description goes here>

## Run (Phase 2)

```bash
go run .                                   # ingests samples/, serves :8080
curl -s http://127.0.0.1:8080/health
curl -s "http://127.0.0.1:8080/api/events?limit=2"
curl -sN http://127.0.0.1:8080/stream     # SSE live tail (connect + heartbeat)
curl -s http://127.0.0.1:8080/stats
```

Docker (needs registry access): `docker build -t ulpf . && docker run -p 8080:8080 -v ulpf-data:/data ulpf`

hello 
nice
