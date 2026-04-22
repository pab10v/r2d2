/**
 * Secure Authenticator Background Service Worker
 * Handles storage, TOTP generation, and secure communication
 */

importScripts('totp.js');

class SecureAuthenticator {
  constructor() {
    this.totp = new self.SecureTOTP();
    this.storageKey = 'secure_authenticator_accounts';
    this.domainBindingKey = 'secure_authenticator_domain_bindings';
    
    // Initialize event listeners
    this.initEventListeners();
  }

  initEventListeners() {
    // Extension installation
    chrome.runtime.onInstalled.addListener((details) => {
      if (details.reason === 'install') {
        console.log('Secure Authenticator installed');
        this.showWelcomePage();
      }
    });

    // Message handling from content scripts and popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async response
    });
  }

  /**
   * Handle incoming messages
   */
  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'GET_ACCOUNTS':
          const accounts = await this.getAccounts();
          sendResponse({ success: true, accounts });
          break;

        case 'ADD_ACCOUNT':
          const addedAccount = await this.addAccount(message.account);
          sendResponse({ success: true, account: addedAccount });
          break;

        case 'UPDATE_ACCOUNT':
          const updatedAccount = await this.updateAccount(message.account);
          sendResponse({ success: true, account: updatedAccount });
          break;

        case 'DELETE_ACCOUNT':
          await this.deleteAccount(message.accountId);
          sendResponse({ success: true });
          break;

        case 'GENERATE_TOTP':
          const code = this.generateTOTP(message.secret, message.digits);
          sendResponse({ success: true, code });
          break;

        case 'GET_TOTP_CODES_FOR_DOMAIN':
          const codes = await this.getTOTPCodesForDomain(message.domain);
          sendResponse({ success: true, ...codes });
          break;

        case 'SAVE_DOMAIN_BINDING':
          await this.saveDomainBinding(message.domain, message.accountId);
          sendResponse({ success: true });
          break;

        case 'EXPORT_ACCOUNTS':
          const exportData = await this.exportAccounts();
          sendResponse({ success: true, data: exportData });
          break;

        case 'IMPORT_ACCOUNTS':
          await this.importAccounts(message.data);
          sendResponse({ success: true });
          break;

        case 'IMPORT_FROM_OTPAUTH':
          const result = await this.importFromOtpauth(message.data);
          sendResponse(result);
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Background script error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  /**
   * Get all stored accounts
   */
  async getAccounts() {
    try {
      const result = await chrome.storage.local.get([this.storageKey]);
      return result[this.storageKey] || [];
    } catch (error) {
      console.error('Error getting accounts:', error);
      return [];
    }
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
    
    if (index === -1) {
      throw new Error('Account not found');
    }

    accounts[index] = { ...accounts[index], ...accountData };
    await this.saveAccounts(accounts);
    return accounts[index];
  }

  /**
   * Delete an account
   */
  async deleteAccount(accountId) {
    const accounts = await this.getAccounts();
    const filteredAccounts = accounts.filter(acc => acc.id !== accountId);
    await this.saveAccounts(filteredAccounts);
  }

  /**
   * Save accounts to storage
   */
  async saveAccounts(accounts) {
    await chrome.storage.local.set({ [this.storageKey]: accounts });
  }

  /**
   * Generate TOTP code
   */
  generateTOTP(secret, digits = 6) {
    return this.totp.generate(secret, 30, digits);
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
            code: this.generateTOTP(boundAccount.secret, boundAccount.digits)
          }],
          bound: true
        };
      }
    }

    // Filter accounts by domain matching
    const matchingAccounts = this.filterAccountsByDomain(accounts, domain);
    
    if (matchingAccounts.length === 0) {
      // Return all accounts if no matches
      return {
        accounts: accounts.map(account => ({
          id: account.id,
          name: account.name,
          issuer: account.issuer,
          code: this.generateTOTP(account.secret, account.digits)
        })),
        bound: false
      };
    }

    return {
      accounts: matchingAccounts.map(account => ({
        id: account.id,
        name: account.name,
        issuer: account.issuer,
        code: this.generateTOTP(account.secret, account.digits)
      })),
      bound: false
    };
  }

  /**
   * Filter accounts by domain matching logic
   */
  filterAccountsByDomain(accounts, domain) {
    const domainLower = domain.toLowerCase();
    const domainWithoutWww = domainLower.replace(/^www\./, '').split('.')[0];

    return accounts.filter(account => {
      const issuerLower = account.issuer.toLowerCase();
      const nameLower = account.name.toLowerCase();

      return domainLower.includes(issuerLower) ||
             issuerLower.includes(domainWithoutWww) ||
             domainLower.includes(nameLower) ||
             nameLower.includes(domainWithoutWww);
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
    
    // Parse each otpauth URI
    const otpauthLines = otpauthData.split('\n').filter(line => line.trim().startsWith('otpauth://'));
    const newAccounts = otpauthLines.map(line => {
      try {
        const url = new URL(line);
        const pathParts = url.pathname.substring(1).split(':'); // Remove leading / and split by :
        const params = new URLSearchParams(url.search);
        
        const issuer = params.get('issuer') || (pathParts.length > 1 ? pathParts[0] : 'Unknown');
        const accountName = pathParts.length > 1 ? pathParts[1] : (pathParts[0] || 'Unknown');
        
        // Decode URL-encoded characters (like %40 -> @)
        const decodedIssuer = decodeURIComponent(issuer);
        const decodedAccountName = decodeURIComponent(accountName);
        
        return {
          id: this.generateId(),
          name: decodedAccountName,
          issuer: decodedIssuer,
          secret: params.get('secret'),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          createdAt: Date.now()
        };
      } catch (error) {
        console.warn('Failed to parse otpauth line:', line, error);
        return null;
      }
    }).filter(account => account !== null);

    const mergedAccounts = [...accounts, ...newAccounts];
    await this.saveAccounts(mergedAccounts);
    
    return {
      success: true,
      imported: newAccounts.length,
      total: mergedAccounts.length
    };
  }

  /**
   * Generate unique ID
   */
  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }

  /**
   * Show welcome page on first install
   */
  showWelcomePage() {
    chrome.tabs.create({
      url: chrome.runtime.getURL('welcome.html')
    });
  }
}

// Initialize the secure authenticator
const secureAuthenticator = new SecureAuthenticator();
