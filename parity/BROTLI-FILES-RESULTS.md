# Validation: brotli detector on release binaries and bundling packages

Each case is one release's files, unpacked and never run. See brotli_files.py and brotli-files.json.

| case | result | verdict | evidence | sha256 (first 16) |
|---|---|---|---|---|
| bundlers__brotli4j-native-linux-aarch64-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-armv7-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-ppc64le-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-riscv64-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-s390x-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-x86_64-1.23.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__brotli4j-native-linux-x86_64-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-linux-x86_64-1.3.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__brotli4j-native-linux_x86-64-1.0.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__brotli4j-native-osx-aarch64-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-osx-x86_64-1.24.0 | PASS | fixed | brotli-error-table |  |
| bundlers__brotli4j-native-windows-aarch64-1.24.0 | PASS | fixed | decoder-code |  |
| bundlers__brotli4j-native-windows-x86_64-1.23.0 | PASS | vulnerable | decoder-code |  |
| bundlers__brotli4j-native-windows-x86_64-1.24.0 | PASS | fixed | decoder-code |  |
| bundlers__jvmbrotli-jvmbrotli-darwin-x86-amd64-0.2.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__jvmbrotli-jvmbrotli-linux-x86-amd64-0.1.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__jvmbrotli-jvmbrotli-linux-x86-amd64-0.2.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__jvmbrotli-jvmbrotli-win32-x86-amd64-0.2.0 | PASS | vulnerable | decoder-code |  |
| bundlers__npm-brotli-2.1.0 | PASS | none |  |  |
| bundlers__npm-brotli-wasm-3.0.1 | PASS | none |  |  |
| bundlers__npm-oven__bun-linux-x64-1.4.4 | PASS | fixed | bun-version |  |
| bundlers__npm-tiny-brotli-dec-wasm-1.0.1 | PASS | unknown | decoder-tables |  |
| bundlers__org.brotli-dec-0.1.2 | PASS | none |  |  |
| bundlers__pypi-PyMuPDF-1.27.2.3 | PASS | vulnerable | decoder-code |  |
| bundlers__pypi-PyMuPDF-1.28.0 | PASS | fixed | decoder-code |  |
| bundlers__pypi-PyMuPDF-2.0 | PASS | fixed | decoder-code |  |
| bundlers__pypi-brotlipy-0.7.0 | PASS | fixed | brotli-error-table |  |
| bundlers__pypi-cramjam-2.14.0 | PASS | none |  |  |
| bundlers__pypi-curl_cffi-0.16.3 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-curl_cffi-0.17.0 | PASS | fixed | brotli-error-table |  |
| bundlers__pypi-duckdb-1.5.6 | PASS | vulnerable | decoder-code |  |
| bundlers__pypi-duckdb-2.0.0 | PASS | vulnerable | decoder-code |  |
| bundlers__pypi-nodejs-wheel-binaries-24.19.0 | PASS | vulnerable | node-version |  |
| bundlers__pypi-pillow-10.0.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pillow-11.0.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pillow-12.3.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pillow-13.0.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pillow-9.5.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pyarrow-25.0.1 | PASS | vulnerable | decoder-code |  |
| bundlers__pypi-pyarrow-26.0.0 | PASS | vulnerable | decoder-code |  |
| bundlers__pypi-pycurl-7.45.3 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pycurl-7.47.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pycurl-7.48.0 | PASS | vulnerable | brotli-error-table |  |
| bundlers__pypi-pycurl-7.49.0 | PASS | fixed | brotli-error-table |  |
| platforms__bun-1.4.3-darwin-aarch64 | PASS | vulnerable | brotli-error-table |  |
| platforms__bun-1.4.3-windows-x64 | PASS | vulnerable | brotli-error-table |  |
| platforms__bun-1.4.4-darwin-aarch64 | PASS | fixed | brotli-error-table |  |
| platforms__bun-1.4.4-windows-x64 | PASS | fixed | brotli-error-table |  |
| platforms__dotnet-8.0.32-osx-arm64 | PASS | vulnerable | brotli-error-table |  |
| platforms__dotnet-8.0.32-win-x64 | PASS | vulnerable | dotnet-version |  |
| platforms__dotnet-8.0.33-osx-arm64 | PASS | fixed | brotli-error-table |  |
| platforms__dotnet-8.0.33-win-x64 | PASS | fixed | dotnet-version |  |
| platforms__dotnet-9.0.21-osx-arm64 | PASS | vulnerable | brotli-error-table |  |
| platforms__dotnet-9.0.21-win-x64 | PASS | vulnerable | dotnet-version |  |
| platforms__dotnet-9.0.22-osx-arm64 | PASS | fixed | brotli-error-table |  |
| platforms__dotnet-9.0.22-win-x64 | PASS | fixed | dotnet-version |  |
| platforms__electron-40.0.0-linux-x64 | PASS | vulnerable | decoder-code |  |
| platforms__electron-42.11.18-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__electron-44.10.0-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__electron-44.7.0-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__electron-44.9.2-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__electron-45.0.0-beta.6-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__electron-45.1.0-linux-x64 | PASS | fixed | decoder-code |  |
| platforms__envoyproxy-envoy-v1.37.7 | PASS | vulnerable | envoy-version | db763cc157cc6012 |
| platforms__envoyproxy-envoy-v1.37.8 | PASS | fixed | envoy-version | 17524ceaaa649843 |
| platforms__istio-proxyv2-1.31.1 | PASS | vulnerable | envoy-version | 5de45e860a356253 |
| platforms__istio-proxyv2-1.31.2 | PASS | fixed | envoy-version | 004c3f2480387718 |
| platforms__node-24.22.0-darwin-arm64 | PASS | vulnerable | brotli-error-table |  |
| platforms__node-24.22.0-win-x64 | PASS | vulnerable | node-version |  |
| platforms__node-24.22.1-darwin-arm64 | PASS | fixed | brotli-error-table |  |
| platforms__node-24.22.1-win-x64 | PASS | fixed | node-version |  |
| platforms__node-26.12.0-win-x64 | PASS | vulnerable | node-version |  |
| platforms__node-26.12.1-win-x64 | PASS | fixed | node-version |  |
