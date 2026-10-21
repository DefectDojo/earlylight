# Parity: engine php2shell detector vs standalone php2shell-scan

Each case compares php2shell-scan (built from the commit in SNAPSHOT), this repo's php2shell-scan and `earlylight scan --detector php2shell`. See php.py for exactly what is compared.

| case | verdict | runtimes | vulnerable | unknown | exit | also checked |
|---|---|---|---|---|---|---|
| php-8.3.35-fpm | PASS | 2 | 2 | 0 | 1 | fs root + subdir, all detectors at once |
| php-8.3.35-fpm-amd64 | PASS | 2 | 2 | 0 | 1 |  |
| php-8.3.35-apache | PASS | 2 | 2 | 0 | 1 |  |
| php-8.1-fpm | PASS | 2 | 2 | 0 | 1 |  |
| php-7.4-fpm | PASS | 2 | 2 | 0 | 1 |  |
| php-8.4-cli-alpine | PASS | 3 | 0 | 0 | 0 |  |
| php-8.3.36-cli | PASS | 4 | 0 | 0 | 0 |  |
| php-8.5-zts | PASS | 4 | 0 | 0 | 0 |  |
| wordpress-latest | PASS | 2 | 2 | 0 | 1 | all detectors at once |
| drupal-latest | PASS | 2 | 2 | 0 | 1 |  |
| frankenphp-latest | PASS | 4 | 0 | 0 | 0 |  |
| bitnami-php-fpm-latest | PASS | 4 | 0 | 0 | 0 |  |
| bitnamilegacy-php-fpm-8.4.11 | PASS | 4 | 4 | 0 | 1 |  |
| debian12-php82 | PASS | 5 | 0 | 0 | 0 |  |
| debian12-php82-amd64 | PASS | 5 | 0 | 0 | 0 |  |
| debian12-php82-vuln | PASS | 3 | 3 | 0 | 1 | fs root + subdir, all detectors at once |
| debian13-php84 | PASS | 3 | 0 | 0 | 0 |  |
| debian-sid-php84 | PASS | 2 | 2 | 0 | 1 |  |
| ubuntu2404-php83 | PASS | 5 | 0 | 0 | 0 |  |
| ubuntu2404-php83-vuln | PASS | 2 | 2 | 0 | 1 |  |
| ubuntu2204-php81 | PASS | 2 | 0 | 0 | 0 |  |
| ubuntu2004-php74 | PASS | 2 | 2 | 0 | 1 |  |
| ubuntu2404-sury | PASS | 3 | 0 | 1 | 3 |  |
| alpine322-php | PASS | 5 | 5 | 0 | 1 | fs root + subdir, all detectors at once |
| alpine322-php-amd64 | PASS | 5 | 5 | 0 | 1 |  |
| alpine324-php | PASS | 4 | 4 | 0 | 1 |  |
| alpine-edge-php | PASS | 4 | 0 | 4 | 3 |  |
| ubi9-php | PASS | 3 | 3 | 0 | 1 | fs root + subdir, all detectors at once |
| ubi9-php83 | PASS | 3 | 3 | 0 | 1 |  |
| al2023-php83 | PASS | 3 | 3 | 0 | 1 |  |
| leap156-php | PASS | 1 | 0 | 1 | 3 |  |
| leap156-php7 | PASS | 1 | 0 | 1 | 3 |  |
| fedora-php | PASS | 3 | 0 | 3 | 3 |  |
| rocky9-remi | PASS | 3 | 0 | 0 | 0 |  |
| hostile-strings | PASS | 0 | 0 | 0 | 0 |  |
| hostile-forgery | PASS | 1 | 1 | 0 | 1 |  |
| ubuntu-replaced | PASS | 1 | 0 | 1 | 3 | fs root + subdir |
| upx-php | PASS | 2 | 2 | 0 | 1 |  |
| ubuntu-source-build | PASS | 2 | 2 | 0 | 1 |  |
| repo | PASS |  |  |  | 2 | online, --offline, --platform; fix --dry-run (7 plan lines) |

40 of 40 cases identical.
