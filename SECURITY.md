# Security Policy

## Authorized use

ALL1n is intended for vulnerability verification against systems for which the operator has explicit authorization. Do not use it against third-party systems without permission.

## Reporting a vulnerability

When reporting a security issue in ALL1n itself, include:

- affected version
- operating system and Go version
- reproduction steps
- expected and actual behavior
- minimal POC or sample data with secrets removed

Do not include production credentials, private targets, session cookies, access tokens, or customer data in reports.

## Sensitive data

POC definitions may contain targets, headers, cookies or payloads. Protect the user configuration directory and exported reports accordingly. Authorization confirmation is intentionally not persisted between application sessions.
