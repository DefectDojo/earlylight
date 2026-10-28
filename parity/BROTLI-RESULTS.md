# Validation: brotli detector against images with known fix status

Each case states the verdict every Brotli decoder in the image must get. See brotli.py for how it is checked.

| case | verdict | decoders | vulnerable | fixed | unknown | exit | evidence |
|---|---|---|---|---|---|---|---|
| node-24.22.0-slim | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| node-24.22.1-slim | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| node-22.23.3-slim | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| node-22.23.4-slim | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| node-26.12.0-slim | PASS | 1 | 1 | 0 | 0 | 1 | node-version |
| node-26.12.1-slim | PASS | 1 | 0 | 1 | 0 | 0 | node-version |
| node-20-slim (EOL) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| node-24.22.0-slim-arm64 | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| dotnet-runtime-8.0.32 | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| dotnet-runtime-8.0.33 | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| dotnet-runtime-8.0.32-arm64 (table stripped) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| dotnet-runtime-8.0.33-arm64 (table stripped) | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| dotnet-aspnet-8.0.33-alpine3.24 | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| dotnet-runtime-9.0.21 | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| dotnet-runtime-9.0.22 | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| dotnet-runtime-10.0.13 | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| dotnet-runtime-10.0.14 | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| dotnet-aspnet-8.0.32-alpine3.24 | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| bun-1.4.3-slim | PASS | 1 | 1 | 0 | 0 | 1 | bun-version |
| bun-1.4.4-slim | PASS | 1 | 0 | 1 | 0 | 0 | bun-version |
| envoy-v1.37.7 | PASS | 1 | 1 | 0 | 0 | 1 | envoy-version |
| envoy-v1.37.8 | PASS | 1 | 0 | 1 | 0 | 0 | envoy-version |
| istio-proxyv2-1.31.1 (Ubuntu libbrotlidec too) | PASS | 2 | 2 | 0 | 0 | 1 | brotli-error-table, envoy-version |
| istio-proxyv2-1.31.2 (Ubuntu libbrotlidec too) | PASS | 2 | 1 | 1 | 0 | 1 | brotli-error-table, envoy-version |
| curl-8.23.0 (Alpine 3.24, brotli 1.2.0) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| python-3.13-slim (no Brotli) | PASS | 0 | 0 | 0 | 0 | 0 |  |
| debian12-unfixed (1.0.9-2+b6) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| debian12-fixed (1.0.9-2+deb12u1) | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| debian13-fixed (1.1.0-2+deb13u1) | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| ubuntu2204-fixed (1.0.9-2ubuntu0.1) | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| ubuntu2404-fixed (1.1.0-2ubuntu0.1) | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| ubi9-fixed (1.0.9-10.el9_8.1) | PASS | 2 | 0 | 2 | 0 | 0 | brotli-error-table |
| fedora43-unfixed (1.2.0-1.fc43) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| al2023-unfixed (1.1.0-1.amzn2023.0.1) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| alpine320-unfixed (EOL) | PASS | 1 | 1 | 0 | 0 | 1 | brotli-error-table |
| alpine322-fixed | PASS | 1 | 0 | 1 | 0 | 0 | brotli-error-table |
| python-wheels-unfixed (Brotli 1.2.0, brotlicffi 1.2.0.0) | PASS | 2 | 2 | 0 | 0 | 1 | brotli-error-table |
| python-wheels-fixed (Brotli 1.2.1, brotlicffi 1.2.1.0) | PASS | 2 | 0 | 2 | 0 | 0 | brotli-error-table |
