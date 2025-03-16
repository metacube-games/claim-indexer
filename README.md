# claim-indexer

Author: https://github.com/NilsDelage

## Build and run

```bash
docker build -t claim-indexer:latest .
docker run --rm -d \
    -v "$(pwd):/persistent" \
    -p 8080:8080 \
    -e API_URL=... \
    -e GIN_MODE=release \
    claim-indexer:latest
``` 
