# Privacy Policy for R2D2 Secure Authenticator

**Last Updated: April 27, 2026**

## 1. Introduction
R2D2 Secure Authenticator ("we," "us," or "the Extension") is committed to protecting your privacy. This Privacy Policy explains our data practices and emphasizes our commitment to transparency and user security.

## 2. No Data Collection (No Telemetry)
R2D2 was built with the principle of "Privacy by Design." 
* **No Tracking:** We do not collect, store, or transmit any telemetry, analytics, or usage statistics.
* **No External Servers:** The Extension does not communicate with any external servers for tracking purposes.
* **No Personal Information:** We do not collect names, email addresses, or any other personal identifiers.

## 3. Data Storage and Encryption
Your security data (TOTP/HOTP secrets and account names) is stored exclusively on your local device.
* **Local Storage:** All account data is stored in your browser's local storage.
* **Military-Grade Encryption:** Data is encrypted using AES-256-GCM.
* **Master PIN:** Encryption keys are derived using Argon2id (state-of-the-art hashing). Your Master PIN is never stored; it is only held in memory temporarily to decrypt the vault and is discarded immediately.

## 4. Third-Party Services (Optional)
The Extension offers two optional features that interact with third-party services:

### A. Google Drive Backup
If you explicitly enable Google Drive backup:
* The Extension will request access to your Google Drive **App Data Folder** only.
* This folder is private and hidden from your regular Drive view.
* The backup payload is **fully encrypted** locally before being uploaded. We cannot read your secrets even if they are stored in your Drive.
* You control the backup password.

### B. Time Synchronization
If you explicitly enable "Sync with Google":
* The Extension will perform a simple HTTP HEAD request to `google.com` to fetch the current server time.
* This is used solely to correct time drift on your device to ensure valid code generation.
* No user data is sent during this request.

## 5. Transparency and Open Source
R2D2 is 100% open source. Our code is available for public audit on GitHub at: [https://github.com/pab10v/r2d2](https://github.com/pab10v/r2d2). We encourage users and security professionals to audit our implementation.

## 6. Permissions Justification
* `storage`: To save your encrypted vault.
* `identity`: For the optional Google Drive backup feature.
* `offscreen`: For secure cryptographic operations and QR scanning.
* `activeTab`: To allow autofill of codes when requested.

## 7. Changes to this Policy
We may update this Privacy Policy from time to time. Any changes will be reflected in the "Last Updated" date at the top of this document.

## 8. Contact
Since R2D2 is an open-source project, any questions or concerns regarding privacy can be addressed via GitHub Issues in our repository.
