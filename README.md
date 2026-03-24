# Password Vault PWA (React + TypeScript)

A fully client-side password vault with:

- Master password required to unlock
- Browser-side encryption before data is written to storage
- Offline support through a service worker
- PWA install support (works as a home-screen app)
- Entry fields: Site Name, User Name, Password, Notes

## Security model

- Vault data is encrypted with AES-GCM.
- Key derivation uses PBKDF2 (SHA-256, 250000 iterations) with a per-vault random salt.
- The master password is never stored in plain text.
- Encrypted data is stored in localStorage.

Important:

- This is a client-side vault. If someone gets your unlocked device/browser session, they can see decrypted data while the app is open.
- Use a strong master password.
- Make backups by exporting browser storage manually if needed. Clearing browser data removes your vault.

## Run locally

1. Install dependencies:

```bash
npm install
```

2. Start dev server:

```bash
npm run dev
```

3. Build production version:

```bash
npm run build
```

4. Preview production build:

```bash
npm run preview
```

## iPhone usage

Best option:

1. Deploy to GitHub Pages (HTTPS).
2. Open the URL in Safari on iPhone.
3. Tap Share -> Add to Home Screen.
4. Launch from Home Screen and use once online to let the app cache.
5. It should then work offline.

Local network note:

- Service workers require secure contexts. Plain HTTP on a LAN URL may not provide full PWA/offline behavior on iPhone.

## Deploy free on GitHub Pages

This repo includes a workflow at .github/workflows/deploy-pages.yml.

1. Push to GitHub (branch main).
2. In GitHub repository settings:
   - Pages -> Source: GitHub Actions
3. The workflow builds and deploys automatically.

The workflow uses:

```bash
npm run build -- --base=./
```

You can also build this way manually:

```bash
npm run build:pages
```

## Tech stack

- React + TypeScript + Vite
- Web Crypto API for encryption
- Service Worker + Web App Manifest for offline/PWA behavior
