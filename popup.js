/**
 * Secure Authenticator Popup Script
 * Handles user interface and interactions
 */

class SecureAuthenticatorUI {
  constructor() {
    this.accounts = [];
    this.totp = new SecureTOTP();
    this.timers = {};
    this.i18n = null;
    this.sounds = null;
    
    this.init();
  }

  async init() {
    // Initialize internationalization first
    this.i18n = new R2D2I18n();
    await this.i18n.init();
    
    // Initialize R2D2 sounds
    this.sounds = new R2D2Sounds();
    
    await this.loadAccounts();
    this.setupEventListeners();
    this.renderAccounts();
    this.startTOTPUpdates();
    
    // Play welcome sound
    setTimeout(() => this.sounds.playWelcome(), 500);
  }

  setupEventListeners() {
    // Header buttons
    document.getElementById('add-account-btn').addEventListener('click', () => this.showAddAccountModal());
    document.getElementById('menu-btn').addEventListener('click', () => this.toggleMenu());

    // Modal controls
    document.getElementById('close-modal-btn').addEventListener('click', () => this.hideAddAccountModal());
    document.getElementById('cancel-add-btn').addEventListener('click', () => this.hideAddAccountModal());
    document.getElementById('add-account-form').addEventListener('submit', (e) => this.handleAddAccount(e));

    // Menu items
    document.getElementById('export-btn').addEventListener('click', () => this.showExportModal());
    document.getElementById('import-btn').addEventListener('click', () => this.showImportModal());
    document.getElementById('sounds-toggle-btn').addEventListener('click', () => this.toggleSounds());
    document.getElementById('test-sounds-btn').addEventListener('click', () => this.testSounds());
    document.getElementById('settings-btn').addEventListener('click', () => this.showSettings());

    // Import/Export modals
    document.getElementById('close-import-modal-btn').addEventListener('click', () => this.hideImportModal());
    document.getElementById('cancel-import-btn').addEventListener('click', () => this.hideImportModal());
    document.getElementById('confirm-import-btn').addEventListener('click', () => this.handleImport());

    document.getElementById('close-export-modal-btn').addEventListener('click', () => this.hideExportModal());
    document.getElementById('close-export-btn').addEventListener('click', () => this.hideExportModal());
    document.getElementById('copy-export-btn').addEventListener('click', () => this.copyExportData());

    // Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('#menu-btn') && !e.target.closest('#menu-dropdown')) {
        this.hideMenu();
      }
    });

    // Close modals when clicking outside
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) {
        this.hideAllModals();
      }
    });
  }

  async loadAccounts() {
    try {
      const response = await this.sendMessage({ type: 'GET_ACCOUNTS' });
      if (response.success) {
        this.accounts = response.accounts;
      }
    } catch (error) {
      console.error('Error loading accounts:', error);
      this.showError('Failed to load accounts');
    }
  }

  renderAccounts() {
    const accountList = document.getElementById('account-list');
    const emptyState = document.getElementById('empty-state');

    if (this.accounts.length === 0) {
      accountList.style.display = 'none';
      emptyState.style.display = 'block';
      document.getElementById('add-first-account-btn').addEventListener('click', () => this.showAddAccountModal());
      return;
    }

    accountList.style.display = 'flex';
    emptyState.style.display = 'none';

    accountList.innerHTML = '';
    this.accounts.forEach(account => {
      const accountElement = this.createAccountElement(account);
      accountList.appendChild(accountElement);
    });
  }

  createAccountElement(account) {
    const div = document.createElement('div');
    div.className = 'account-item';
    div.dataset.accountId = account.id;

    const code = this.totp.generate(account.secret, account.period || 30, account.digits || 6);
    const remainingTime = this.totp.getRemainingTime(account.period || 30);

    div.innerHTML = `
      <div class="account-header">
        <div class="account-info">
          <h3>${this.escapeHtml(account.name)}</h3>
          <p>${this.escapeHtml(account.issuer || account.name)}</p>
        </div>
        <div class="account-actions">
          <button class="icon-btn edit-btn" title="Edit">✏️</button>
          <button class="icon-btn delete-btn" title="Delete">🗑️</button>
        </div>
      </div>
      <div class="totp-code">
        <div class="code-display" data-account-id="${account.id}">${this.formatCode(code)}</div>
        <button class="copy-btn" data-account-id="${account.id}" data-code="${code}">📋 Copy</button>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" data-account-id="${account.id}" style="width: ${(remainingTime / (account.period || 30)) * 100}%"></div>
      </div>
    `;

    // Add event listeners
    const copyBtn = div.querySelector('.copy-btn');
    copyBtn.addEventListener('click', () => this.copyCode(account.id, code));

    const editBtn = div.querySelector('.edit-btn');
    editBtn.addEventListener('click', () => this.editAccount(account));

    const deleteBtn = div.querySelector('.delete-btn');
    deleteBtn.addEventListener('click', () => this.deleteAccount(account.id));

    return div;
  }

  formatCode(code) {
    // Format code with spaces for better readability
    return code.replace(/(.{3})/g, '$1 ').trim();
  }

  copyCode(accountId, code) {
    const cleanCode = code.replace(/\s/g, '');
    navigator.clipboard.writeText(cleanCode).then(() => {
      const copyBtn = document.querySelector(`.copy-btn[data-account-id="${accountId}"]`);
      copyBtn.textContent = 'Copied';
      copyBtn.classList.add('copied');
      
      // Play copy sound
      this.sounds.playCopy();
      
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy code:', err);
      this.sounds.playError();
      this.showError('Failed to copy code');
    });
  }

  startTOTPUpdates() {
    // Update TOTP codes every second
    setInterval(() => {
      this.updateTOTPCodes();
    }, 1000);
  }

  updateTOTPCodes() {
    this.accounts.forEach(account => {
      const codeDisplay = document.querySelector(`.code-display[data-account-id="${account.id}"]`);
      const progressBar = document.querySelector(`.progress-fill[data-account-id="${account.id}"]`);
      
      if (codeDisplay && progressBar) {
        const code = this.totp.generate(account.secret, account.period || 30, account.digits || 6);
        const remainingTime = this.totp.getRemainingTime(account.period || 30);
        
        codeDisplay.textContent = this.formatCode(code);
        progressBar.style.width = `${(remainingTime / (account.period || 30)) * 100}%`;
      }
    });
  }

  showAddAccountModal() {
    document.getElementById('add-account-modal').style.display = 'flex';
    document.getElementById('account-name').focus();
  }

  hideAddAccountModal() {
    document.getElementById('add-account-modal').style.display = 'none';
    document.getElementById('add-account-form').reset();
  }

  async handleAddAccount(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const accountData = {
      name: formData.get('name') || document.getElementById('account-name').value,
      issuer: document.getElementById('account-issuer').value,
      secret: document.getElementById('account-secret').value.toUpperCase().replace(/\s/g, ''),
      digits: parseInt(document.getElementById('account-digits').value)
    };

    try {
      // Validate secret format
      if (!this.isValidBase32(accountData.secret)) {
        throw new Error(this.i18n.t('messages.invalid_secret'));
      }

      // Test the secret by generating a code
      this.totp.generate(accountData.secret);
      
      const response = await this.sendMessage({
        type: 'ADD_ACCOUNT',
        account: accountData
      });

      if (response.success) {
        this.hideAddAccountModal();
        await this.loadAccounts();
        this.renderAccounts();
        this.sounds.playSuccess();
        this.showSuccess('account_added');
      } else {
        throw new Error(response.error || 'Failed to add account');
      }
    } catch (error) {
      console.error('Error adding account:', error);
      this.sounds.playError();
      this.showError(error.message);
    }
  }

  isValidBase32(secret) {
    const base32Regex = /^[A-Z2-7]+=*$/;
    return base32Regex.test(secret.replace(/\s/g, ''));
  }

  async editAccount(account) {
    // For now, just show the add modal with pre-filled data
    // In a full implementation, you'd have a separate edit modal
    document.getElementById('account-name').value = account.name;
    document.getElementById('account-issuer').value = account.issuer || '';
    document.getElementById('account-secret').value = account.secret;
    document.getElementById('account-digits').value = account.digits || 6;
    
    this.showAddAccountModal();
    
    // Update form submission to handle edit
    const form = document.getElementById('add-account-form');
    form.onsubmit = async (e) => {
      e.preventDefault();
      
      const accountData = {
        id: account.id,
        name: document.getElementById('account-name').value,
        issuer: document.getElementById('account-issuer').value,
        secret: document.getElementById('account-secret').value.toUpperCase().replace(/\s/g, ''),
        digits: parseInt(document.getElementById('account-digits').value)
      };

      try {
        const response = await this.sendMessage({
          type: 'UPDATE_ACCOUNT',
          account: accountData
        });

        if (response.success) {
          this.hideAddAccountModal();
          await this.loadAccounts();
          this.renderAccounts();
          this.showSuccess('account_updated');
          
          // Reset form handler
          form.onsubmit = (e) => this.handleAddAccount(e);
        } else {
          throw new Error(response.error || 'Failed to update account');
        }
      } catch (error) {
        console.error('Error updating account:', error);
        this.showError(error.message);
      }
    };
  }

  async deleteAccount(accountId) {
    if (!confirm('Are you sure you want to delete this account? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await this.sendMessage({
        type: 'DELETE_ACCOUNT',
        accountId: accountId
      });

      if (response.success) {
        await this.loadAccounts();
        this.renderAccounts();
        this.showSuccess('account_deleted');
      } else {
        throw new Error(response.error || 'Failed to delete account');
      }
    } catch (error) {
      console.error('Error deleting account:', error);
      this.showError(error.message);
    }
  }

  toggleMenu() {
    const dropdown = document.getElementById('menu-dropdown');
    dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
  }

  hideMenu() {
    document.getElementById('menu-dropdown').style.display = 'none';
  }

  async showExportModal() {
    try {
      const response = await this.sendMessage({ type: 'EXPORT_ACCOUNTS' });
      if (response.success) {
        const exportData = response.data;
        const jsonExport = JSON.stringify(exportData.json, null, 2);
        const otpauthExport = exportData.otpauth;
        
        document.getElementById('export-data').value = jsonExport;
        document.getElementById('export-modal').style.display = 'flex';
        
        // Add format selector
        const modalContent = document.querySelector('#export-modal .modal-content');
        const formatSelector = document.createElement('div');
        formatSelector.innerHTML = `
          <div class="export-format-selector">
            <label>Export Format:</label>
            <div class="format-tabs">
              <button class="format-tab active" data-format="json">JSON</button>
              <button class="format-tab" data-format="otpauth">otpauth://</button>
            </div>
          </div>
        `;
        
        const modalHeader = modalContent.querySelector('.modal-header');
        modalHeader.insertAdjacentElement('afterend', formatSelector);
        
        // Add event listeners for format switching
        document.querySelectorAll('.format-tab').forEach(tab => {
          tab.addEventListener('click', (e) => {
            document.querySelectorAll('.format-tab').forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            
            const format = e.target.dataset.format;
            const textarea = document.getElementById('export-data');
            textarea.value = format === 'otpauth' ? otpauthExport : jsonExport;
          });
        });
      }
    } catch (error) {
      console.error('Error exporting accounts:', error);
      this.sounds.playError();
      this.showError('Failed to export accounts');
    }
    this.hideMenu();
  }

  hideExportModal() {
    document.getElementById('export-modal').style.display = 'none';
  }

  copyExportData() {
    const exportData = document.getElementById('export-data');
    exportData.select();
    document.execCommand('copy');
    
    const copyBtn = document.getElementById('copy-export-btn');
    copyBtn.textContent = '✓ Copied';
    setTimeout(() => {
      copyBtn.textContent = '📋 Copy to Clipboard';
    }, 2000);
  }

  showImportModal() {
    document.getElementById('import-modal').style.display = 'flex';
    this.hideMenu();
  }

  hideImportModal() {
    document.getElementById('import-modal').style.display = 'none';
    document.getElementById('import-data').value = '';
  }

  async handleImport() {
    const importData = document.getElementById('import-data').value;
    
    try {
      let response;
      
      // Check if data is in otpauth format
      if (importData.trim().startsWith('otpauth://')) {
        // Import from otpauth format
        response = await this.sendMessage({
          type: 'IMPORT_FROM_OTPAUTH',
          data: importData
        });
      } else {
        // Import from JSON format
        const data = JSON.parse(importData);
        response = await this.sendMessage({
          type: 'IMPORT_ACCOUNTS',
          data: data
        });
      }

      if (response.success) {
        this.hideImportModal();
        await this.loadAccounts();
        this.renderAccounts();
        this.sounds.playSuccess();
        this.showSuccess('Accounts imported successfully!');
      } else {
        throw new Error(response.error || 'Failed to import accounts');
      }
    } catch (error) {
      console.error('Error importing accounts:', error);
      this.sounds.playError();
      this.showError(error.message);
    }
  }

  showSettings() {
    // For now, just show an alert
    alert('Settings coming soon!');
    this.hideMenu();
  }

  toggleSounds() {
    const enabled = this.sounds.toggle();
    const button = document.getElementById('sounds-toggle-btn');
    button.textContent = `R2D2 Sounds: ${enabled ? 'ON' : 'OFF'}`;
    
    // Play sound feedback when enabling
    if (enabled) {
      this.sounds.playOK();
    }
    
    this.hideMenu();
  }

  testSounds() {
    this.sounds.testAllSounds();
    this.showMessage('Testing R2D2 sounds...', 'info');
    this.hideMenu();
  }

  hideAllModals() {
    document.querySelectorAll('.modal').forEach(modal => {
      modal.style.display = 'none';
    });
  }

  showMessage(message, type = 'info') {
    // Create a toast notification
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 6px;
      color: white;
      font-weight: 500;
      z-index: 10000;
      max-width: 300px;
      word-wrap: break-word;
    `;

    switch (type) {
      case 'success':
        toast.style.background = '#4CAF50';
        break;
      case 'error':
        toast.style.background = '#f44336';
        break;
      default:
        toast.style.background = '#2196F3';
    }

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 3000);
  }

  showSuccess(messageKey, params = {}) {
    const message = this.i18n.t(`messages.${messageKey}`, params);
    this.showMessage(message, 'success');
  }

  showError(messageKey, params = {}) {
    const message = this.i18n.t(`messages.${messageKey}`, params);
    this.showMessage(message, 'error');
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  sendMessage(message) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, resolve);
    });
  }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new SecureAuthenticatorUI();
});
