# claim-indexer

Author: @NilsDelage

## Build and run

```bash
docker build -t claim-indexer:latest .
docker run --rm -d \
    -v "$(pwd):/persistent" \
    -p 8080:8080 \
    -e API_URL=... \
    claim-indexer:latest
``` 
