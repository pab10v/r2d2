/**
 * Secure Authenticator Background Service Worker
 * Handles storage, TOTP generation, and secure communication
 */

importScripts('totp.js');
importScripts('vault.js');

class SecureAuthenticator {
  constructor() {
    this.totp  = new self.SecureTOTP(false);
    this.vault = new self.SecureVault();
    this.vault.setExternalDeriver((pw, salt) => this.deriveKeyOffscreen(pw, salt));
    this.domainBindingKey = 'secure_authenticator_domain_bindings';

    // Initialize time offset from storage
    this.initTimeOffset();

    // Initialize event listeners
    this.initEventListeners();
    this.setupAutoLock();
    this.OFFSCREEN_PATH = 'offscreen.html';
  }

  async initTimeOffset() {
    const data = await chrome.storage.local.get('vault_time_offset');
    if (data.vault_time_offset) {
      this.totp.setTimeOffset(data.vault_time_offset);
    }
  }

  async syncTime() {
    try {
      // Fetch google.com to get its server time from headers
      const start = Date.now();
      const response = await fetch('https://www.google.com/generate_204', { 
        method: 'HEAD',
        cache: 'no-store'
      });
      const end = Date.now();
      
      const serverDateStr = response.headers.get('date');
      if (!serverDateStr) throw new Error('Could not get server date');
      
      const serverTime = new Date(serverDateStr).getTime();
      // Estimate network latency (round trip / 2)
      const latency = (end - start) / 2;
      const adjustedServerTime = serverTime + latency;
      
      const offset = adjustedServerTime - end;
      
      await chrome.storage.local.set({ vault_time_offset: offset });
      this.totp.setTimeOffset(offset);
      
      return { success: true, offset };
    } catch (error) {
      console.error('Time sync failed:', error);
      return { success: false, error: error.message };
    }
  }

  setupAutoLock() {
    chrome.alarms.create('autoLockCheck', { periodInMinutes: 1 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'autoLockCheck') {
        this.checkAutoLock();
      }
    });
  }

  async updateLastInteraction() {
    await chrome.storage.session.set({ lastInteraction: Date.now() });
  }

  async checkAutoLock() {
    if (this.vault.isLocked()) return;
    
    const [settings, session] = await Promise.all([
      chrome.storage.local.get('vault_lock_timeout'),
      chrome.storage.session.get('lastInteraction')
    ]);
    
    const timeoutMin = settings.vault_lock_timeout !== undefined ? settings.vault_lock_timeout : 5;
    if (timeoutMin === 0) return; // Never lock
    
    const lastInteraction = session.lastInteraction || 0;
    const now = Date.now();
    
    if (now - lastInteraction > timeoutMin * 60 * 1000) {
      this.vault.lock();
      chrome.runtime.sendMessage({ type: 'VAULT_LOCKED' });
    }
  }

  initEventListeners() {
    // Extension installation
    chrome.runtime.onInstalled.addListener((details) => {
      if (details.reason === 'install') {
        this.showWelcomePage();
      }
    });

    // Message handling from content scripts and popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      const isBridgeMessage =
        message &&
        (message.target === 'background' || message.target === 'offscreen');
      this.handleMessage(message, sender, sendResponse);
      // Bridge/offscreen messages are fire-and-forget and do not require sendResponse.
      return !isBridgeMessage;
    });

    // Keyboard commands
    chrome.commands.onCommand.addListener((command) => {
      this.handleCommand(command);
    });

    // Context menus
    chrome.contextMenus.onClicked.addListener((info, tab) => {
      this.handleContextMenuClick(info, tab);
    });

    // Update menus on start
    this.updateContextMenus();
  }

  /**
   * Handle incoming messages
   */
  async handleMessage(message, sender, sendResponse) {
    // Ignore bridge/internal messages handled by dedicated listeners
    if (message && (message.target === 'background' || message.target === 'offscreen')) {
      return;
    }

    await this.updateLastInteraction();
    try {
      // ── Vault management (no auth required) ──────────────────────────────
      switch (message.type) {
        case 'VAULT_STATUS': {
          const exists = await this.vault.hasVault();
          const locked = this.vault.isLocked();
          sendResponse({ success: true, exists, locked });
          return;
        }

        case 'SETUP_VAULT': {
          console.log('Background: Starting SETUP_VAULT');
          await this.vault.setup(message.pin);
          console.log('Background: SETUP_VAULT complete');
          sendResponse({ success: true });
          return;
        }

        case 'UNLOCK_VAULT': {
          const ok = await this.vault.unlock(message.pin);
          if (ok) this.updateContextMenus();
          sendResponse({ success: true, unlocked: ok });
          return;
        }

        case 'LOCK_VAULT': {
          this.vault.lock();
          this.updateContextMenus();
          sendResponse({ success: true });
          return;
        }

        case 'CHANGE_PIN': {
          try {
            await this.vault.changePin(message.data.oldPin, message.data.newPin);
            sendResponse({ success: true });
          } catch (error) {
            sendResponse({ success: false, error: error.message });
          }
          return;
        }

        case 'SYNC_TIME': {
          this.syncTime().then(sendResponse);
          return true; // Async
        }

        case 'ARGON2_DERIVE': {
          this.deriveKeyOffscreen(message.password, message.salt).then(sendResponse);
          return true; // Async
        }
      }

      // ── Vault-protected operations ────────────────────────────────────────
      if (this.vault.isLocked()) {
        sendResponse({ success: false, locked: true, error: 'Vault is locked' });
        return;
      }

      switch (message.type) {
        case 'GET_ACCOUNTS': {
          const accounts = await this.getAccounts();
          sendResponse({ success: true, accounts });
          break;
        }

        case 'ADD_ACCOUNT': {
          const addedAccount = await this.addAccount(message.account);
          this.updateContextMenus();
          sendResponse({ success: true, account: addedAccount });
          break;
        }

        case 'UPDATE_ACCOUNT': {
          const updatedAccount = await this.updateAccount(message.account);
          this.updateContextMenus();
          sendResponse({ success: true, account: updatedAccount });
          break;
        }

        case 'DELETE_ACCOUNT': {
          await this.deleteAccount(message.accountId);
          this.updateContextMenus();
          sendResponse({ success: true });
          break;
        }

        case 'GENERATE_TOTP': {
          const code = await this.generateTOTP(message.secret, message.digits);
          sendResponse({ success: true, code });
          break;
        }

        case 'GET_TOTP_CODES_FOR_DOMAIN': {
          const codes = await this.getTOTPCodesForDomain(message.domain);
          sendResponse({ success: true, ...codes });
          break;
        }

        case 'SAVE_DOMAIN_BINDING': {
          await this.saveDomainBinding(message.domain, message.accountId);
          sendResponse({ success: true });
          break;
        }

        case 'EXPORT_ACCOUNTS': {
          const exportData = await this.exportAccounts();
          sendResponse({ success: true, data: exportData });
          break;
        }

        case 'IMPORT_ACCOUNTS': {
          await this.importAccounts(message.data);
          this.updateContextMenus();
          sendResponse({ success: true });
          break;
        }

        case 'IMPORT_FROM_OTPAUTH': {
          const result = await this.importFromOtpauth(message.data);
          if (result.success) this.updateContextMenus();
          sendResponse(result);
          break;
        }

        case 'DEBUG_TOTP': {
          if (!this.isDev()) {
            sendResponse({ success: false, error: 'Debug commands are disabled in production' });
            break;
          }
          const debugResult = await this.debugTOTP(message.data);
          sendResponse(debugResult);
          break;
        }

        case 'DEBUG_TIME_SYNC': {
          if (!this.isDev()) {
            sendResponse({ success: false, error: 'Debug commands are disabled in production' });
            break;
          }
          sendResponse({ success: true, data: this.totp.debugTimeSync() });
          break;
        }

        case 'DEBUG_TEST_VECTORS': {
          if (!this.isDev()) {
            sendResponse({ success: false, error: 'Debug commands are disabled in production' });
            break;
          }
          this.totp.debugWithTestVectors();
          sendResponse({ success: true, message: 'Test vectors executed — check console' });
          break;
        }

        case 'DEBUG_TIME_WINDOW': {
          if (!this.isDev()) {
            sendResponse({ success: false, error: 'Debug commands are disabled in production' });
            break;
          }
          const twResult = await this.totp.generateTimeWindow(
            message.data.secret,
            message.data.algorithm || 'SHA1',
            message.data.steps || 3
          );
          sendResponse({ success: true, data: twResult });
          break;
        }

        case 'CAPTURE_TAB': {
          chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
            if (chrome.runtime.lastError) {
              sendResponse({ success: false, error: chrome.runtime.lastError.message });
            } else {
              sendResponse({ success: true, dataUrl: dataUrl });
            }
          });
          return true; // Keep message channel open for async response
        }

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Background script error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async handleCommand(command) {
    if (command === 'autofill_code') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url || tab.url.startsWith('chrome://')) return;
      
      const account = await this.findMatchingAccount(tab.url);
      if (account) {
        const code = await this.generateCodeForAccount(account);
        chrome.tabs.sendMessage(tab.id, { type: 'AUTOFILL', code });
      }
    } else if (command === 'scan_qr') {
      this.handleScanQRCommand();
    }
  }

  async handleScanQRCommand() {
    try {
      // 1. Capture the tab
      const dataUrl = await new Promise((resolve, reject) => {
        chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve(dataUrl);
        });
      });

      // 2. Detect QR in Offscreen Document
      const result = await this.detectQROffscreen(dataUrl);
      
      if (!result.code) {
        this.showNotification('R2D2: QR Not Found', 'No QR code detected on the current page.');
        return;
      }

      // 3. Import from otpauth URI
      if (result.code.startsWith('otpauth://')) {
        const importResult = await this.importFromOtpauth(result.code);
        if (importResult.success) {
          this.updateContextMenus();
          this.showNotification('R2D2: Success', `Account "${importResult.account.name}" imported successfully.`);
        } else {
          this.showNotification('R2D2: Error', 'Failed to import QR data.');
        }
      } else {
        this.showNotification('R2D2: Unsupported QR', 'This QR code is not a valid OTP setup URI.');
      }
    } catch (error) {
      console.error('Scan QR Command error:', error);
      this.showNotification('R2D2: Scan Error', error.message);
    }
  }

  async detectQROffscreen(dataUrl) {
    try {
      const result = await this._callOffscreen('detect_qr', { dataUrl });
      return { success: true, code: result.code };
    } catch (error) {
      console.error('detectQROffscreen error:', error);
      throw error;
    }
  }

  async _callOffscreen(action, payload, timeout = 30000) {
    console.log(`Background: _callOffscreen starting for ${action}`);
    await this.ensureOffscreenDocument();
    console.log(`Background: Offscreen document ensured for ${action}`);
    
    return new Promise((resolve, reject) => {
      const id = this.generateRequestId();
      
      const timer = setTimeout(() => {
        console.error(`Background: _callOffscreen TIMEOUT for ${action}`);
        chrome.runtime.onMessage.removeListener(listener);
        reject(new Error(`Offscreen timeout (${action}) ID: ${id}`));
      }, timeout);

      const listener = (message) => {
        if (message.target === 'background' && message.id === id) {
          console.log(`Background: _callOffscreen response received for ${action}`);
          clearTimeout(timer);
          chrome.runtime.onMessage.removeListener(listener);
          if (message.action.endsWith('_success')) {
            resolve(message.payload);
          } else {
            reject(new Error(message.payload.error || 'Unknown offscreen error'));
          }
        }
      };

      chrome.runtime.onMessage.addListener(listener);

      console.log(`Background: _callOffscreen sending message for ${action}`);
      chrome.runtime.sendMessage({
        target: 'offscreen',
        action,
        payload,
        id
      });
    });
  }

  showNotification(title, message) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon.svg',
      title: title,
      message: message,
      priority: 2
    });
  }

  async handleContextMenuClick(info, tab) {
    if (info.menuItemId === 'unlock-vault') {
      chrome.action.openPopup();
      return;
    }
    
    if (info.menuItemId.startsWith('fill-')) {
      const accountId = info.menuItemId.replace('fill-', '');
      const accounts = await this.vault.get();
      const account = accounts.find(a => a.id === accountId);
      if (account) {
        const code = await this.generateCodeForAccount(account);
        chrome.tabs.sendMessage(tab.id, { type: 'AUTOFILL', code });
      }
    }
  }

  async updateContextMenus() {
    try {
      chrome.contextMenus.removeAll();
      if (this.vault.isLocked()) {
        chrome.contextMenus.create({
          id: 'unlock-vault',
          title: 'Unlock R2D2 Vault',
          contexts: ['editable']
        });
        return;
      }

      const accounts = await this.vault.get();
      if (accounts.length === 0) return;

      chrome.contextMenus.create({
        id: 'r2d2-root',
        title: 'R2D2: Insert Code',
        contexts: ['editable']
      });

      // Show up to 5 accounts in the menu
      for (const account of accounts.slice(0, 5)) {
        chrome.contextMenus.create({
          id: `fill-${account.id}`,
          parentId: 'r2d2-root',
          title: account.name,
          contexts: ['editable']
        });
      }
    } catch (error) {
      console.error('Error updating context menus:', error);
    }
  }

  async findMatchingAccount(url) {
    if (this.vault.isLocked()) return null;
    const accounts = await this.vault.get();
    let hostname;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }
    
    // 1. Try explicit domain binding
    const data = await chrome.storage.local.get(this.domainBindingKey);
    const domainBindings = data[this.domainBindingKey] || {};
    const boundAccountId = domainBindings[hostname];
    if (boundAccountId) {
      const match = accounts.find(a => a.id === boundAccountId);
      if (match) return match;
    }
    
    // 2. Fallback to issuer/name matching
    return accounts.find(acc => {
      const issuer = (acc.issuer || '').toLowerCase();
      const name = acc.name.toLowerCase();
      return (issuer && hostname.includes(issuer)) || hostname.includes(name);
    });
  }

  async generateCodeForAccount(account) {
    if (account.type === 'HOTP') {
      const code = await this.totp.generateHOTP(account.secret, account.counter || 0, account.digits || 6);
      // Increment counter
      account.counter = (account.counter || 0) + 1;
      await this.vault.saveAccount(account);
      this.updateContextMenus(); // update menu if counter changes? (not strictly needed but good for state)
      return code;
    } else {
      return await this.totp.generate(account.secret, account.period || 30, account.digits || 6);
    }
  }

  /**
   * Derive a key using Argon2 via an Offscreen Document
   */
  async deriveKeyOffscreen(password, salt) {
    try {
      const result = await this._callOffscreen('derive_key', { password, salt });
      return { success: true, hash: result.hash };
    } catch (error) {
      console.error('Offscreen Argon2 error:', error);
      return { success: false, error: error.message };
    }
  }

  async ensureOffscreenDocument() {
    // If a document is already being created, wait for it
    if (this.creatingOffscreenDocument) {
      await this.creatingOffscreenDocument;
      return;
    }

    const existingContexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT']
    });

    if (existingContexts.length > 0) {
      return;
    }

    // Create the document and store the promise
    this.creatingOffscreenDocument = chrome.offscreen.createDocument({
      url: this.OFFSCREEN_PATH,
      reasons: ['LOCAL_STORAGE'], 
      justification: 'Argon2 key derivation and QR scanning for secure vault'
    });

    try {
      await this.creatingOffscreenDocument;
      // The bridge will send OFFSCREEN_READY when it and the sandbox are loaded
      console.log('Background: Offscreen document created, waiting for ready signal...');
      
      // We still use a small timeout as fallback, but the ready signal is better
      await new Promise(resolve => {
        const timeout = setTimeout(() => {
          console.warn('Background: Offscreen document READY timeout');
          chrome.runtime.onMessage.removeListener(listener);
          resolve();
        }, 2000);

        const listener = (msg) => {
          if (msg.action === 'OFFSCREEN_READY') {
            clearTimeout(timeout);
            chrome.runtime.onMessage.removeListener(listener);
            console.log('Background: Offscreen document READY');
            resolve();
          }
        };
        chrome.runtime.onMessage.addListener(listener);
      });
    } catch (error) {
      console.error('Error creating offscreen document:', error);
      throw error;
    } finally {
      this.creatingOffscreenDocument = null;
    }
  }

  /**
   * Get all accounts from the encrypted vault
   */
  async getAccounts() {
    try {
      return await this.vault.get();
    } catch (error) {
      console.error('Error getting accounts:', error);
      return [];
    }
  }

  /**
   * Save accounts to the encrypted vault
   */
  async saveAccounts(accounts) {
    await this.vault.set(accounts);
  }

  /**
   * Add a new account
   */
  async addAccount(accountData) {
    const accounts = await this.getAccounts();
    const newAccount = {
      id: this.generateId(),
      name: accountData.name,
      issuer: accountData.issuer || accountData.name,
      secret: accountData.secret,
      algorithm: accountData.algorithm || 'SHA1',
      digits: accountData.digits || 6,
      period: accountData.period || 30,
      createdAt: Date.now(),
      ...accountData
    };
    accounts.push(newAccount);
    await this.saveAccounts(accounts);
    return newAccount;
  }

  /**
   * Update an existing account
   */
  async updateAccount(accountData) {
    const accounts = await this.getAccounts();
    const index = accounts.findIndex(acc => acc.id === accountData.id);
    if (index === -1) throw new Error('Account not found');
    accounts[index] = { ...accounts[index], ...accountData };
    await this.saveAccounts(accounts);
    return accounts[index];
  }

  /**
   * Delete an account
   */
  async deleteAccount(accountId) {
    const accounts = await this.getAccounts();
    await this.saveAccounts(accounts.filter(acc => acc.id !== accountId));
  }


  /**
   * Generate TOTP code
   */
  async generateTOTP(secret, digits = 6) {
    return await this.totp.generate(secret, 30, digits);
  }

  /**
   * Get TOTP codes for a specific domain
   */
  async getTOTPCodesForDomain(domain) {
    const accounts = await this.getAccounts();
    const domainBindings = await this.getDomainBindings();

    // Check for bound account first
    const boundAccountId = domainBindings[domain.toLowerCase()];
    if (boundAccountId) {
      const boundAccount = accounts.find(acc => acc.id === boundAccountId);
      if (boundAccount) {
        return {
          accounts: [{
            id: boundAccount.id,
            name: boundAccount.name,
            issuer: boundAccount.issuer,
            code: await this.generateTOTP(boundAccount.secret, boundAccount.digits)
          }],
          bound: true
        };
      }
    }

    // Filter accounts by domain matching
    const matchingAccounts = this.filterAccountsByDomain(accounts, domain);
    if (matchingAccounts.length === 0) {
      return { accounts: [], bound: false };
    }

    const accountsWithCodes = await Promise.all(
      matchingAccounts.map(async account => ({
        id: account.id,
        name: account.name,
        issuer: account.issuer,
        code: await this.generateTOTP(account.secret, account.digits)
      }))
    );

    return { accounts: accountsWithCodes, bound: false };
  }

  /**
   * Filter accounts by domain matching logic
   */
  filterAccountsByDomain(accounts, domain) {
    const normalizedHost = this.normalizeHostLikeValue(domain);
    if (!normalizedHost) return [];

    return accounts.filter((account) => this.accountMatchesDomain(account, normalizedHost));
  }

  normalizeHostLikeValue(value) {
    if (!value || typeof value !== 'string') return '';

    let normalized = value.trim().toLowerCase();
    if (!normalized) return '';

    // Handle account-like identifiers such as "user@example.com".
    const atIndex = normalized.lastIndexOf('@');
    if (atIndex > 0) {
      normalized = normalized.slice(atIndex + 1);
    }

    // Handle issuer strings that may include protocol/path/port.
    normalized = normalized.replace(/^[a-z]+:\/\//, '');
    normalized = normalized.split('/')[0].split(':')[0];
    normalized = normalized.replace(/^www\./, '');
    normalized = normalized.replace(/\.+$/g, '');

    // Keep only host-safe characters.
    normalized = normalized.replace(/[^a-z0-9.-]/g, '');
    return normalized;
  }

  getRegistrableDomain(host) {
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) return host;

    const last = parts[parts.length - 1];
    const secondLast = parts[parts.length - 2];
    // Heuristic for common ccTLD second-level domains (co.uk, com.mx, etc.).
    if (last.length === 2 && secondLast.length <= 3 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  accountMatchesDomain(account, normalizedHost) {
    const hostLabels = normalizedHost.split('.').filter(Boolean);
    const registrable = this.getRegistrableDomain(normalizedHost);
    const candidates = [account.issuer, account.name]
      .map((value) => this.normalizeHostLikeValue(value))
      .filter(Boolean);

    return candidates.some((candidate) => {
      // Full host or domain candidate (e.g., google.com).
      if (candidate.includes('.')) {
        return normalizedHost === candidate || normalizedHost.endsWith(`.${candidate}`);
      }

      // Single-label candidate (e.g., google) must match a full label, not substring.
      return hostLabels.includes(candidate) || registrable.startsWith(`${candidate}.`);
    });
  }

  /**
   * Get domain bindings
   */
  async getDomainBindings() {
    try {
      const result = await chrome.storage.local.get([this.domainBindingKey]);
      return result[this.domainBindingKey] || {};
    } catch (error) {
      console.error('Error getting domain bindings:', error);
      return {};
    }
  }

  /**
   * Save domain binding
   */
  async saveDomainBinding(domain, accountId) {
    const bindings = await this.getDomainBindings();
    bindings[domain.toLowerCase()] = accountId;
    await chrome.storage.local.set({ [this.domainBindingKey]: bindings });
  }

  /**
   * Export accounts (for backup)
   */
  async exportAccounts() {
    const accounts = await this.getAccounts();
    
    // Export in both JSON and otpauth formats
    const jsonExport = {
      version: '1.0',
      exportDate: new Date().toISOString(),
      accounts: accounts.map(({ id, name, issuer, secret, algorithm, digits, period }) => ({
        id,
        name,
        issuer,
        secret,
        algorithm,
        digits,
        period
      }))
    };
    
    const otpauthExport = this.exportToOtpauth(accounts);
    
    return {
      json: jsonExport,
      otpauth: otpauthExport
    };
  }

  // Export accounts in otpauth:// format
  exportToOtpauth(accounts) {
    return accounts.map(account => {
      const params = new URLSearchParams();
      params.append('secret', account.secret);
      params.append('issuer', account.issuer || 'Unknown');
      
      // Create otpauth URI
      const accountName = account.name || 'Unknown';
      const issuer = account.issuer || 'Unknown';
      const label = issuer !== account.name ? `${issuer}:${accountName}` : accountName;
      
      return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
    }).join('\n');
  }

  /**
   * Import accounts from backup
   */
  async importAccounts(data) {
    if (!data.version || !data.accounts) {
      throw new Error('Invalid import data format');
    }

    const accounts = await this.getAccounts();
    const newAccounts = data.accounts.map(account => ({
      ...account,
      id: this.generateId(),
      createdAt: Date.now()
    }));

    const mergedAccounts = [...accounts, ...newAccounts];
    await this.saveAccounts(mergedAccounts);
  }

  /**
   * Import accounts from otpauth format
   */
  async importFromOtpauth(otpauthData) {
    const accounts = await this.getAccounts();
    
    // Parse each otpauth URI according to RFC 6063
    const otpauthLines = otpauthData.split('\n').filter(line => line.trim().startsWith('otpauth://'));
    const newAccounts = otpauthLines.map(line => {
      try {
        // RFC 6063: Validate URI length (max 2048 characters)
        if (line.length > 2048) {
          throw new Error('URI too long');
        }
        
        const url = new URL(line);
        
        // RFC 6063: Validate scheme
        if (url.protocol !== 'otpauth:') {
          throw new Error('Invalid scheme');
        }
        
        // RFC 6063: Parse type (totp/hotp)
        const type = url.host.toLowerCase();
        if (!['totp', 'hotp'].includes(type)) {
          throw new Error('Invalid OTP type');
        }
        if (type === 'hotp') {
          throw new Error('HOTP is not supported');
        }
        
        // RFC 6063: Parse label (issuer:accountname)
        const pathParts = url.pathname.substring(1).split(':'); // Remove leading / and split by :
        const params = new URLSearchParams(url.search);
        
        // RFC 6063: Validate required secret parameter
        const secret = params.get('secret');
        if (!secret || !/^[A-Z2-7]+=*$/i.test(secret)) {
          throw new Error('Invalid or missing secret');
        }
        
        // RFC 6063: Parse optional parameters with defaults
        const algorithm = params.get('algorithm') || 'SHA1';
        const digits = parseInt(params.get('digits')) || 6;
        const period = parseInt(params.get('period')) || 30;
        const counter = params.get('counter');
        
        // RFC 6063: Validate parameter values
        if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) {
          throw new Error('Invalid algorithm');
        }
        if (![6, 7, 8].includes(digits)) {
          throw new Error('Invalid digits');
        }
        if (period && ![30, 60, 90].includes(period)) {
          throw new Error('Invalid period');
        }
        if (type === 'hotp' && !counter) {
          throw new Error('HOTP requires counter');
        }
        
        // RFC 6063: Parse issuer and account name
        let issuer, accountName;
        const issuerParam = params.get('issuer');
        
        if (pathParts.length === 2) {
          issuer = pathParts[0];
          accountName = pathParts[1];
        } else if (pathParts.length === 1) {
          accountName = pathParts[0];
          issuer = issuerParam || 'Unknown';
        } else {
          throw new Error('Invalid label format');
        }
        
        // RFC 6063: Issuer parameter takes precedence if different
        if (issuerParam && issuerParam !== issuer) {
          issuer = issuerParam;
        }
        
        // Decode URL-encoded characters
        const decodedIssuer = decodeURIComponent(issuer);
        const decodedAccountName = decodeURIComponent(accountName);
        
        // RFC 6063: Validate label length (max 255 chars each)
        if (decodedIssuer.length > 255 || decodedAccountName.length > 255) {
          throw new Error('Label too long');
        }
        
        return {
          id: this.generateId(),
          name: decodedAccountName,
          issuer: decodedIssuer,
          secret: secret.toUpperCase(),
          algorithm: algorithm,
          digits: digits,
          period: period,
          counter: counter ? parseInt(counter) : null,
          type: type,
          createdAt: Date.now()
        };
      } catch (error) {
        console.warn('Failed to parse otpauth line:', line, error);
        return { isError: true, error: error.message, line };
      }
    });

    // Check for duplicates and errors
    const duplicates = [];
    const uniqueNewAccounts = [];
    const errors = [];
    
    for (const item of newAccounts) {
      if (item.isError) {
        errors.push(item.error);
        continue;
      }
      
      const newAccount = item;
      const isDuplicate = accounts.some(existingAccount => 
        existingAccount.secret.toLowerCase() === newAccount.secret.toLowerCase() ||
        (existingAccount.issuer.toLowerCase() === newAccount.issuer.toLowerCase() && 
         existingAccount.name.toLowerCase() === newAccount.name.toLowerCase())
      );
      
      if (isDuplicate) {
        duplicates.push(newAccount);
      } else {
        uniqueNewAccounts.push(newAccount);
      }
    }
    
    const mergedAccounts = [...accounts, ...uniqueNewAccounts];
    await this.saveAccounts(mergedAccounts);
    
    return {
      success: true,
      imported: uniqueNewAccounts.length,
      duplicates: duplicates.length,
      total: mergedAccounts.length,
      duplicateDetails: duplicates.map(d => `${d.issuer}: ${d.name}`),
      errors: errors
    };
  }

  /**
   * Debug TOTP generation for specific account
   */
  async debugTOTP(accountData) {
    try {
      const accounts = await this.getAccounts();
      const account = accounts.find(acc => acc.id === accountData.accountId);
      
      if (!account) {
        return { success: false, error: 'Account not found' };
      }
      
      // Generate detailed debug info
      const debugInfo = {
        account: {
          id: account.id,
          name: account.name,
          issuer: account.issuer,
          secret: account.secret.substring(0, 8) + '...' // Show only first 8 chars for security
        },
        currentCode: await this.totp.generate(account.secret, account.period || 30, account.digits || 6, account.algorithm || 'SHA1'),
        timeWindow: await this.totp.generateTimeWindow(account.secret, account.algorithm || 'SHA1', 2)
      };
      
      return { success: true, data: debugInfo };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Generate unique ID
   */
  generateId() {
    return crypto.randomUUID();
  }

  generateRequestId() {
    return crypto.randomUUID();
  }

  isDev() {
    const manifest = chrome.runtime.getManifest();
    return Boolean(
      manifest.version_name &&
      manifest.version_name.toLowerCase().includes('dev')
    );
  }

  /**
   * Show welcome page on first install
   */
  showWelcomePage() {
    chrome.tabs.create({
      url: chrome.runtime.getURL('popup.html')
    });
  }
}

// Initialize the secure authenticator
const secureAuthenticator = new SecureAuthenticator();
