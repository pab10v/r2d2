# R2D2 - Secure Authenticator

A secure, transparent, and high-performance two-factor authentication extension built from the ground up with 100% visible and auditable source code.

## Why R2D2?

R2D2 was born following the discovery of compromised authenticator extensions that maliciously modified their cryptographic libraries. R2D2 represents our commitment to transparent code and verified security. No black boxes, no telemetry, no compromises.

## Key Features

### 🛡️ Production-Grade Security
- **Argon2id Hardening**: Master key derivation using **Argon2id** (via WebAssembly), the state-of-the-art hashing algorithm resistant to GPU/ASIC brute-force attacks.
- **Sandboxed Crypto**: Heavy cryptographic operations run in an isolated **Offscreen API** environment to maintain browser performance and security.
- **100% Transparent Code**: Every line of code is visible, documented, and easy to audit.
- **No External Dependencies**: Zero third-party libraries that could be compromised.
- **Local Storage Only**: Your secrets never leave your browser.
- **Offline First**: Works completely offline with zero network calls.
- **No Telemetry**: Absolutely no data collection or analytics.

### ⚙️ Functionality
- **TOTP & HOTP Support**: Full implementation of RFC 6238 (Time-based) and RFC 4226 (Counter-based) protocols.
- **Time Synchronization**: Integrated Google Server Time sync to resolve local clock drift issues automatically.
- **Smart Autofill**: Automatically detects 2FA input fields and injects codes with one click.
- **Domain Binding**: R2D2 remembers which account belongs to which website for seamless logins.
- **Secure Import/Export**: AES-GCM encrypted backup and restoration of your vault.

## Step-by-Step Installation

### For Regular Users

1.  **Download the Code**
    - Go to the [GitHub Repository](https://github.com/pab10v/r2d2).
    - Click the green "Code" button and select "Download ZIP".
    - Extract the file to a folder on your computer.

2.  **Install in Chrome/Brave/Edge**
    - Open your browser and navigate to `chrome://extensions/`.
    - Enable **"Developer mode"** (top right toggle).
    - Click **"Load unpacked"**.
    - Select the extracted `r2d2` folder.
    - Done! You'll see the R2D2 icon in your toolbar.

### For Developers

```bash
# Clone the repository
git clone https://github.com/pab10v/r2d2.git
cd r2d2

# Load in Chrome via chrome://extensions/ -> Load unpacked
```

## How to Use

### 1. Adding Your First Account
1. Click the R2D2 icon in your browser.
2. Click **"+ Add Account"**.
3. Choose between **TOTP** (Time-based) or **HOTP** (Counter-based).
4. Enter your **Secret Key** (Base32) provided by the service (e.g., Google, GitHub).
5. (Optional) Provide an **Account Name** and **Issuer**.

### 2. Time Synchronization (Fixing Code Errors)
If your codes are being rejected even though the PIN is correct, your system clock might be out of sync.
1. Open **Settings** (gear icon).
2. Click **"Sync with Google"**.
3. R2D2 will calculate the time drift and apply an offset to ensure codes are valid.

### 3. Using Autofill
1. Navigate to a login page with a 2FA field.
2. Click the **Clock Icon** that R2D2 injects into the input field.
3. Select your account; the code will be filled automatically.

## Security Architecture

### Cryptographic Stack
- **KDF**: Argon2id (Memory: 19MB, Iterations: 2, Parallelism: 1).
- **Encryption**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Isolation**: WebAssembly hashing runs in a dedicated `sandbox` page via the `offscreen` permission.

### File Structure
```
r2d2/
├── manifest.json       # Extension configuration (MV3)
├── background.js       # Service Worker for state and vault management
├── vault.js            # SecureVault class (AES-GCM + Argon2)
├── totp.js             # RFC 6238/4226 Implementation
├── sandbox.js/html     # Isolated environment for WASM/Argon2
├── lib/argon.js        # Argon2 WebAssembly bundle
├── popup.js/html/css   # Main UI components
└── content.js/css      # Smart detection and autofill injection
```

## Security Audit Status

| Feature | Status | Verification |
| :--- | :--- | :--- |
| **Network** | Secure | Verified 0 network calls (offline) |
| **Storage** | Secure | Encrypted local storage only (AES-GCM) |
| **KDF** | Secure | Argon2id implementation (verified vs RFC) |
| **Telemetry** | Secure | No tracking or analytics  |

## Security Notes

- Threat model (storage, SW, content, offscreen/sandbox): `docs/threat-model.md`
- RFC 6238 regression vectors (SHA1/SHA256/SHA512): `scratch/test_totp_vectors.js`

## Privacy and Permissions

- `storage`: stores encrypted vault data and local preferences.
- `activeTab` + `scripting`: fills OTP codes in the current page when explicitly requested.
- `offscreen`: runs isolated Argon2/QR tasks without blocking UI.
- `contextMenus` + `commands`: optional quick actions for OTP workflows.
- `notifications`: local success/error status notifications.
- `host_permissions: <all_urls>`: required to detect OTP inputs across arbitrary login domains. R2D2 does not send page data or secrets to external services.

## FAQ

### Is R2D2 safer than other extensions?
Yes. Many extensions use obfuscated code or third-party libraries that can be updated with malicious code. R2D2 uses zero dependencies and clear, auditable code.

### What if I lose my computer?
We recommend exporting your accounts regularly via the **"Export Accounts"** feature and saving the data in a secure password manager or an encrypted file.

### Does R2D2 see my Master PIN?
No. Your Master PIN is never stored. It is only used to derive the encryption key via Argon2 in memory and is discarded immediately after use.

## License

This project is licensed under the **MIT License**. Feel free to audit, modify, and distribute.

---

**Warning**: This extension was created as a secure alternative to compromised extensions. Always audit the source code of security-critical software.

**R2D2: Where trust is transparent code.**
