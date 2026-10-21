# Parity: engine emudhra detector vs standalone emudhra-scan

| case | verdict | files | findings | vulnerable | exit |
|---|---|---|---|---|---|
| python-3.13-slim | PASS | 4447 | 6 | 6 | 1 |
| python-3.13-slim-latest | PASS | 4445 | 2 | 2 | 1 |
| node-22-slim | PASS | 5770 | 0 | 0 | 0 |
| node-openssl-ca | PASS | 5953 | 0 | 0 | 0 |
| temurin-21-jdk | PASS | 7715 | 4 | 4 | 1 |
| temurin-patched | PASS | 7945 | 3 | 3 | 1 |
| golang-1.27.2 | PASS | 30881 | 5 | 5 | 1 |
| golang-1.27.3 | PASS | 30879 | 0 | 0 | 0 |
| alpine-3.23-curl | PASS | 97 | 1 | 1 | 1 |
| alpine-patched | PASS | 97 | 0 | 0 | 0 |
| wolfi-r2 | PASS | 104 | 1 | 1 | 1 |
| wolfi-latest | PASS | 104 | 0 | 0 | 0 |
| ubuntu-24.04 | PASS | 2585 | 0 | 0 | 0 |
| ubuntu-patched | PASS | 2857 | 0 | 0 | 0 |
| ubuntu-patched-requests | PASS | 5014 | 2 | 0 | 0 |
| debian12-requests | PASS | 9206 | 3 | 0 | 0 |
| ubi9-minimal | PASS | 1175 | 12 | 10 | 1 |
| ubi9-blocklisted | PASS | 1174 | 7 | 3 | 1 |
| opensuse-leap-15.6 | PASS | 2580 | 7 | 5 | 1 |
| opensuse-workaround | PASS | 2581 | 4 | 0 | 0 |
| opensuse-advisory-literal | PASS | 2584 | 7 | 5 | 1 |
| corretto-21 | PASS | 6021 | 12 | 10 | 1 |
| corretto-patched | PASS | 6019 | 11 | 9 | 1 |
| ruby-3.3-slim | PASS | 5395 | 0 | 0 | 0 |
| php-8.3-cli | PASS | 9113 | 0 | 0 | 0 |
| composer-2 | PASS | 3433 | 4 | 4 | 1 |
| jar-truststore | PASS | 7946 | 5 | 5 | 1 |
| pyinstaller-app | PASS | 2678 | 2 | 2 | 1 |
| distroless-debian12 | PASS | 964 | 2 | 2 | 1 |
| distroless-debian13 | PASS | 960 | 0 | 0 | 0 |
| fs-emudhra-repo | PASS | 271 | 15 | 15 | 1 |
| fs-etc | PASS | 219 | 2 | 2 | 1 |
| fs-goroot | PASS | 12093 | 0 | 0 | 0 |
| fs-as-root | PASS | 57 | 3 | 3 | 1 |
| host-google | PASS | 3 | 0 | 0 | 0 |
| host-github | PASS | 3 | 0 | 0 | 0 |

36 of 36 cases identical.
