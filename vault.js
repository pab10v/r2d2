/**
 * SecureVault — AES-256-GCM encrypted storage for TOTP secrets
 *
 * Architecture:
 *  - Key derivation : PBKDF2-SHA256, 310 000 iterations (OWASP 2024)
 *  - Encryption     : AES-256-GCM (random IV per write)
 *  - Salt           : 16 random bytes, stored in chrome.storage.local (non-secret)
 *  - Session key    : CryptoKey object kept only in memory — never persisted
 *  - Auto-lock      : key is lost when the service worker terminates (MV3)
 */

class SecureVault {
  constructor() {
    this._sessionKey  = null;          // in-memory only
    this.SALT_KEY     = 'r2d2_vault_salt';
    this.VAULT_KEY    = 'r2d2_vault_data';
    this.LEGACY_KEY   = 'secure_authenticator_accounts'; // migration source
    this.ITERATIONS   = 310_000;
    this.SALT_LEN     = 16;  // bytes
    this.IV_LEN       = 12;  // bytes (AES-GCM recommended)
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /** Returns true if an encrypted vault exists in storage */
  async hasVault() {
    const r = await chrome.storage.local.get(this.VAULT_KEY);
    return !!r[this.VAULT_KEY];
  }

  /** Returns true if the session key is NOT in memory */
  isLocked() {
    return this._sessionKey === null;
  }

  /**
   * Create a new vault protected by PIN.
   * Migrates existing plaintext accounts automatically.
   * @param {string} pin
   */
  async setup(pin) {
    if (pin.length < 4) throw new Error('PIN must be at least 4 characters');

    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LEN));
    const key  = await this._deriveKey(pin, salt);

    // Migrate legacy plaintext accounts if they exist
    const legacy = await chrome.storage.local.get(this.LEGACY_KEY);
    const accounts = legacy[this.LEGACY_KEY] || [];

    await this._writeVault(accounts, key, salt);
    this._sessionKey = key;

    // Remove legacy plaintext data
    await chrome.storage.local.remove(this.LEGACY_KEY);
  }

  /**
   * Unlock the vault with PIN.
   * @param {string} pin
   * @returns {boolean} true if PIN is correct
   */
  async unlock(pin) {
    const saltHex = (await chrome.storage.local.get(this.SALT_KEY))[this.SALT_KEY];
    if (!saltHex) throw new Error('Vault salt not found');

    const salt = this._fromHex(saltHex);
    try {
      const key = await this._deriveKey(pin, salt);
      await this._readVault(key); // throws if PIN is wrong (GCM auth tag fails)
      this._sessionKey = key;
      return true;
    } catch {
      return false;
    }
  }

  /** Clear the session key from memory */
  lock() {
    this._sessionKey = null;
  }

  /**
   * Read all accounts from the encrypted vault.
   * @returns {Array}
   */
  async get() {
    if (!this._sessionKey) throw new Error('Vault is locked');
    return this._readVault(this._sessionKey);
  }

  /**
   * Write all accounts to the encrypted vault.
   * @param {Array} accounts
   */
  async set(accounts) {
    if (!this._sessionKey) throw new Error('Vault is locked');
    const saltHex = (await chrome.storage.local.get(this.SALT_KEY))[this.SALT_KEY];
    const salt = this._fromHex(saltHex);
    await this._writeVault(accounts, this._sessionKey, salt);
  }

  /**
   * Re-encrypt the vault with a new PIN.
   * @param {string} oldPin
   * @param {string} newPin
   */
  async changePin(oldPin, newPin) {
    if (newPin.length < 4) throw new Error('PIN must be at least 4 characters');

    const saltHex = (await chrome.storage.local.get(this.SALT_KEY))[this.SALT_KEY];
    const oldSalt = this._fromHex(saltHex);

    let accounts;
    try {
      const oldKey = await this._deriveKey(oldPin, oldSalt);
      accounts = await this._readVault(oldKey);
    } catch {
      throw new Error('Incorrect PIN');
    }

    // Re-encrypt with new PIN + fresh salt
    const newSalt = crypto.getRandomValues(new Uint8Array(this.SALT_LEN));
    const newKey  = await this._deriveKey(newPin, newSalt);
    await this._writeVault(accounts, newKey, newSalt);
    this._sessionKey = newKey;
  }

  /**
   * Encrypt a JSON object with a custom password (for export)
   */
  async encryptExport(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LEN));
    const key  = await this._deriveKey(password, salt);
    const plaintext = JSON.stringify(data);
    const { ciphertext, iv } = await this._encrypt(plaintext, key);
    
    return {
      encrypted: true,
      version: 1,
      salt: this._toHex(salt),
      iv: this._toHex(iv),
      ciphertext: this._toHex(ciphertext)
    };
  }

  /**
   * Decrypt a JSON object with a custom password (for import)
   */
  async decryptExport(encryptedObj, password) {
    const salt = this._fromHex(encryptedObj.salt);
    const iv   = this._fromHex(encryptedObj.iv);
    const ciphertext = this._fromHex(encryptedObj.ciphertext);
    const key  = await this._deriveKey(password, salt);
    const plaintext = await this._decrypt(ciphertext, key, iv);
    return JSON.parse(plaintext);
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  async _readVault(key) {
    const r = await chrome.storage.local.get(this.VAULT_KEY);
    const data = r[this.VAULT_KEY];
    if (!data) return [];

    const iv         = this._fromHex(data.iv);
    const ciphertext = this._fromHex(data.ciphertext);
    const plaintext  = await this._decrypt(ciphertext, key, iv);
    return JSON.parse(plaintext);
  }

  async _writeVault(accounts, key, salt) {
    const plaintext = JSON.stringify(accounts);
    const { ciphertext, iv } = await this._encrypt(plaintext, key);

    await chrome.storage.local.set({
      [this.SALT_KEY]: this._toHex(salt),
      [this.VAULT_KEY]: {
        version: 1,
        iv:         this._toHex(iv),
        ciphertext: this._toHex(ciphertext)
      }
    });
  }

  async _deriveKey(pin, salt) {
    const pinBytes     = new TextEncoder().encode(pin);
    const keyMaterial  = await crypto.subtle.importKey(
      'raw', pinBytes, 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: this.ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async _encrypt(plaintext, key) {
    const data = new TextEncoder().encode(plaintext);
    const iv   = crypto.getRandomValues(new Uint8Array(this.IV_LEN));
    const buf  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { ciphertext: new Uint8Array(buf), iv };
  }

  async _decrypt(ciphertext, key, iv) {
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(buf);
  }

  _toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  _fromHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
}

// Export for service worker and popup contexts
if (typeof window !== 'undefined') {
  window.SecureVault = SecureVault;
} else if (typeof self !== 'undefined') {
  self.SecureVault = SecureVault;
}
