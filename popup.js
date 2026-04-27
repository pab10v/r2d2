/**
 * Secure Authenticator Popup Script
 * Handles user interface and interactions
 */

class SecureAuthenticatorUI {
  constructor() {
    this.accounts = [];
    this.totp = new SecureTOTP(false);
    this.timers = {};
    this.i18n = null;
    this.sounds = null;
    this.qrScanner = null;
    this.editingAccountId = null;
    this.totpIntervalId = null;
    this.inactivityTimeoutId = null;
    this.inactivityTimeoutMs = 5 * 60 * 1000;
    this.activityEventsBound = false;
    this.unlockHandlerBound = false;
    this.unlockAttempts = 0;
    this.unlockBlockedUntil = 0;
    this.unlockLockoutLevel = 0;
    this.maxUnlockAttempts = 5;
    this.qrListenersBound = false;
    this.mainListenersBound = false;
    this.lastCodeWindowByAccount = {};
    this.codeRefreshTimeoutId = null;
    this.contextDomain = null;
    this.contextRelatedAccountIds = null;
    this.contextFilterEnabled = true;
    this.siteIntegrationOrigin = null;
    this.driveHandlersBound = false;
    
    this.setupBackgroundListeners();
    this.init();
  }

  setupBackgroundListeners() {
    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === 'VAULT_LOCKED') {
        this.showView('view-unlock');
        this.setupUnlockHandlers();
        this.showMessage(this.t('messages.vault_locked_inactivity'), 'info');
      }
    });
  }

  async init() {
    // Always initialize i18n and sounds first
    this.i18n = new R2D2I18n();
    await this.i18n.init();
    this.sounds = new R2D2Sounds();
    await this.initSettings();

    // Check vault state and route to the correct view
    try {
      const status = await this.sendMessage({ type: 'VAULT_STATUS' });
      if (!status.exists) {
        this.showView('view-setup');
        this.setupVaultHandlers();
      } else if (status.locked) {
        this.showView('view-unlock');
        this.setupUnlockHandlers();
      } else {
        await this.initMainView();
      }
    } catch (err) {
      // Service worker not responding — show unlock as safe fallback
      this.showView('view-unlock');
      this.setupUnlockHandlers();
    }
  }

  /** Show one vault view and hide the others */
  showView(id) {
    ['view-setup', 'view-unlock', 'view-main'].forEach(viewId => {
      const el = document.getElementById(viewId);
      if (el) el.style.display = (viewId === id) ? (viewId === 'view-main' ? 'block' : 'flex') : 'none';
    });

    // Handle header elements visibility
    const addBtn = document.getElementById('add-account-btn');
    const menuBtn = document.getElementById('menu-btn');
    
    if (id === 'view-main') {
      if (addBtn) addBtn.style.display = 'block';
      if (menuBtn) menuBtn.style.display = 'flex';
    } else {
      if (addBtn) addBtn.style.display = 'none';
      if (menuBtn) menuBtn.style.display = 'none';
    }

    if (id === 'view-setup') {
      this.isInitialSetup = true;
    }
  }

  /** Wire up the Setup (first-use PIN creation) form */
  setupVaultHandlers() {
    const form   = document.getElementById('setup-form');
    const errEl  = document.getElementById('setup-error');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pin     = document.getElementById('setup-pin').value;
      const confirm = document.getElementById('setup-pin-confirm').value;

      if (pin.length < 4) {
        return this.showVaultError(errEl, 'PIN must be at least 4 digits');
      }
      if (pin !== confirm) {
        return this.showVaultError(errEl, 'PINs do not match');
      }

      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = this.t('ui.creating_vault');

      try {
        const res = await this.sendMessage({ type: 'SETUP_VAULT', pin });
        if (res.success) {
          await this.initMainView();
        } else {
          this.showVaultError(errEl, res.error || 'Failed to create vault');
          btn.disabled = false;
          btn.textContent = this.t('ui.create_vault');
        }
      } catch (err) {
        this.showVaultError(errEl, err.message);
        btn.disabled = false;
        btn.textContent = this.t('ui.create_vault');
      }
    });

    setTimeout(() => document.getElementById('setup-pin')?.focus(), 100);
  }

  async initSettings() {
    const settings = await chrome.storage.local.get([
      'vault_lock_timeout',
      'vault_theme',
      'vault_sort_order',
      'vault_sounds_enabled'
    ]);
    
    // Update inactivity timeout to match user settings
    const timeoutMin = settings.vault_lock_timeout !== undefined ? settings.vault_lock_timeout : 5;
    this.inactivityTimeoutMs = timeoutMin === 0 ? 0 : timeoutMin * 60 * 1000;
    
    // Set lock timeout select
    const lockSelect = document.getElementById('lock-timeout');
    if (lockSelect) {
      if (settings.vault_lock_timeout !== undefined) {
        lockSelect.value = settings.vault_lock_timeout;
      }
      const lockTimeout = document.getElementById('lock-timeout');
      if (lockTimeout) {
        lockTimeout.addEventListener('change', (e) => {
          const newTimeout = parseInt(e.target.value);
          chrome.storage.local.set({ vault_lock_timeout: newTimeout });
          this.inactivityTimeoutMs = newTimeout === 0 ? 0 : newTimeout * 60 * 1000;
          this.showMessage(this.t('messages.lock_timeout_updated'), 'success');
        });
      }

      // Sync Time Button
      const syncBtn = document.getElementById('sync-time-btn');
      if (syncBtn) {
        syncBtn.addEventListener('click', async () => {
          const status = document.getElementById('sync-status');
          const originalText = syncBtn.innerHTML;
          
          syncBtn.disabled = true;
          syncBtn.innerHTML = `<span>⏳</span> ${this.t('ui.syncing')}`;
          if (status) status.textContent = '';
          
          const response = await this.sendMessage({ type: 'SYNC_TIME' });
          
          syncBtn.disabled = false;
          syncBtn.innerHTML = originalText;
          
          if (response.success) {
            const offsetSec = Math.round(response.offset / 1000);
            if (status) {
              status.textContent = this.t('messages.sync_success_drift', { seconds: offsetSec });
              status.style.color = '#4CAF50';
            }
            this.sounds.playSuccess();
            
            // Force update local offset and codes
            await this.initTimeOffset();
            await this.updateTOTPCodes();
          } else {
            if (status) {
              status.textContent = `${this.t('messages.sync_failed_prefix')}: ${response.error}`;
              status.style.color = '#f44336';
            }
            this.sounds.playError();
          }
        });
      }
    }
    
    // Set theme select
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
      if (settings.vault_theme) {
        themeSelect.value = settings.vault_theme;
        this.applyTheme(settings.vault_theme);
      }
      themeSelect.addEventListener('change', (e) => {
        chrome.storage.local.set({ vault_theme: e.target.value });
        this.applyTheme(e.target.value);
      });
    }

    // Account type listener
    const accountTypeSelect = document.getElementById('account-type');
    if (accountTypeSelect) {
      accountTypeSelect.addEventListener('change', (e) => {
        const counterGroup = document.getElementById('counter-group');
        if (counterGroup) {
          counterGroup.style.display = e.target.value === 'HOTP' ? 'block' : 'none';
        }
      });
    }

    // Set sort order select
    const sortSelect = document.getElementById('sort-order');
    if (sortSelect) {
      if (settings.vault_sort_order) {
        sortSelect.value = settings.vault_sort_order;
      }
      sortSelect.addEventListener('change', (e) => {
        chrome.storage.local.set({ vault_sort_order: e.target.value });
        this.renderAccounts();
      });
    }

    // Search accounts listener
    const searchInput = document.getElementById('search-accounts');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase();
        this.renderAccounts();
      });
    }
    const showAllBtn = document.getElementById('show-all-accounts-btn');
    if (showAllBtn) {
      showAllBtn.addEventListener('click', () => {
        this.contextFilterEnabled = false;
        this.renderContextFilterInfo();
        this.renderAccounts();
      });
    }

    // Hide "Expand to Tab" if already in a full tab view
    if (window.matchMedia('(min-width: 401px)').matches) {
      const expandBtn = document.getElementById('expand-tab-btn');
      if (expandBtn) expandBtn.style.display = 'none';
      
      const closeTabBtn = document.getElementById('close-tab-btn');
      if (closeTabBtn) {
        closeTabBtn.style.display = 'block';
        closeTabBtn.addEventListener('click', () => window.close());
      }
    }

    if (typeof settings.vault_sounds_enabled === 'boolean') {
      this.sounds.enabled = settings.vault_sounds_enabled;
    }
  }

  applyTheme(theme) {
    if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.body.classList.add('theme-dark');
    } else {
      document.body.classList.remove('theme-dark');
    }
  }

  /** Wire up the Unlock (PIN entry) form with attempt limiting */
  setupUnlockHandlers() {
    const form       = document.getElementById('unlock-form');
    const errEl      = document.getElementById('unlock-error');
    const attemptsEl = document.getElementById('unlock-attempts');
    const btn        = document.getElementById('unlock-btn');

    this.clearInactivityLock();
    this.stopTOTPUpdates();

    const resetUnlockView = () => {
      document.getElementById('unlock-pin').value = '';
      attemptsEl.style.display = 'none';
      errEl.style.display = 'none';
      btn.disabled = false;
      btn.textContent = this.t('ui.unlock');
    };

    resetUnlockView();

    if (this.unlockHandlerBound) {
      setTimeout(() => document.getElementById('unlock-pin').focus(), 100);
      return;
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const now = Date.now();
      if (now < this.unlockBlockedUntil) {
        const secondsLeft = Math.ceil((this.unlockBlockedUntil - now) / 1000);
        this.showVaultError(errEl, `Too many attempts. Wait ${secondsLeft} seconds.`);
        attemptsEl.style.display = 'none';
        return;
      }

      const pin = document.getElementById('unlock-pin').value;
      btn.disabled = true;
      btn.textContent = this.t('ui.unlocking');

      try {
        const res = await this.sendMessage({ type: 'UNLOCK_VAULT', pin });
        if (res.unlocked) {
          this.unlockAttempts = 0;
          this.unlockBlockedUntil = 0;
          this.unlockLockoutLevel = 0;
          await this.initMainView();
        } else {
          this.unlockAttempts++;
          const remaining = this.maxUnlockAttempts - this.unlockAttempts;
          document.getElementById('unlock-pin').value = '';

          if (remaining <= 0) {
            const blockMs = this.getCurrentLockoutDurationMs();
            const blockSeconds = Math.ceil(blockMs / 1000);
            this.unlockBlockedUntil = Date.now() + blockMs;
            this.unlockAttempts = 0;
            this.unlockLockoutLevel = Math.min(this.unlockLockoutLevel + 1, 6);

            this.showVaultError(errEl, this.t('messages.too_many_attempts_wait', { seconds: blockSeconds }));
            attemptsEl.style.display = 'none';
            btn.disabled = true;
            btn.textContent = this.t('ui.locked');

            setTimeout(() => {
              if (Date.now() >= this.unlockBlockedUntil) {
                btn.disabled = false;
                btn.textContent = this.t('ui.unlock');
                errEl.style.display = 'none';
              }
            }, blockMs);
          } else {
            this.showVaultError(errEl, this.t('messages.incorrect_pin'));
            attemptsEl.textContent = this.t('messages.attempts_remaining', { count: remaining });
            attemptsEl.style.display = 'block';
            btn.disabled    = false;
            btn.textContent = this.t('ui.unlock');
          }
        }
      } catch (err) {
        this.showVaultError(errEl, err.message);
        btn.disabled    = false;
        btn.textContent = this.t('ui.unlock');
      }
    });

    this.unlockHandlerBound = true;
    setTimeout(() => document.getElementById('unlock-pin').focus(), 100);
  }

  async initTimeOffset() {
    try {
      const data = await chrome.storage.local.get('vault_time_offset');
      if (data.vault_time_offset !== undefined) {
        this.totp.setTimeOffset(data.vault_time_offset);
      }
    } catch (error) {
      this.logError(error, 'initTimeOffset', false);
    }
  }

  /** Show error text inside a vault view error element */
  showVaultError(el, msg) {
    el.textContent    = msg;
    el.style.display  = 'block';
  }

  t(key, params = {}) {
    return this.i18n ? this.i18n.t(key, params) : key;
  }

  /** Initialize the main authenticator view */
  async initMainView() {
    this.showView('view-main');
    this.applyEnvironmentFlags();
    await this.loadAccounts();
    await this.loadContextDomainMatches();
    this.setupEventListeners();
    this.initTimeOffset();
    await this.renderAccounts();
    this.startTOTPUpdates();
    this.setupInactivityLock();
    this.handleStartupRoute();
    this.updateSoundsToggleLabel(this.sounds.enabled);
    await this.initSiteIntegrationControls();
    await this.initDriveBackupControls();
    setTimeout(() => this.sounds.playWelcome(), 300);

    // Auto-close tab if we just finished initial setup
    if (this.isInitialSetup && window.matchMedia('(min-width: 401px)').matches) {
      this.showSuccess(this.t('messages.setup_complete_closing'));
      setTimeout(() => window.close(), 3000);
    }
  }

  setupEventListeners() {
    if (this.mainListenersBound) {
      return;
    }

    // Header buttons
    document.getElementById('add-account-btn').addEventListener('click', () => this.showAddAccountModal());
    document.getElementById('menu-btn').addEventListener('click', () => this.toggleMenu());

    // Modal controls
    document.getElementById('close-modal-btn').addEventListener('click', () => this.hideAddAccountModal());
    document.getElementById('cancel-add-btn').addEventListener('click', () => this.hideAddAccountModal());
    document.getElementById('add-account-form').addEventListener('submit', (e) => this.handleAddAccount(e));

    // Menu items
    document.getElementById('export-btn').addEventListener('click', () => this.showExportModal());
    document.getElementById('import-btn').addEventListener('click', async () => {
      const inTab = await this.isExtensionTabView();
      if (!inTab) {
        chrome.tabs.create({ url: chrome.runtime.getURL('popup.html#import') });
        window.close();
        return;
      }
      this.showImportModal();
    });
    document.getElementById('qr-scanner-btn').addEventListener('click', () => this.showQRScannerModal());
    document.getElementById('sounds-toggle-btn').addEventListener('click', () => this.toggleSounds());
    document.getElementById('test-sounds-btn').addEventListener('click', () => this.testSounds());
    const debugBtn = document.getElementById('debug-btn');
    if (debugBtn && this.isDevMode()) {
      debugBtn.addEventListener('click', () => this.showDebugModal());
    }
    document.getElementById('settings-btn').addEventListener('click', () => this.showSettings());
    
    // Add QR scanner button listener from the "Add Account" form
    const scanQrBtn = document.getElementById('scan-qr-btn');
    if (scanQrBtn) {
      scanQrBtn.addEventListener('click', () => {
        this.hideAddAccountModal();
        this.showQRScannerModal();
      });
    }

    // Settings Modal
    document.getElementById('close-settings-modal-btn').addEventListener('click', () => this.hideSettingsModal());
    document.getElementById('close-settings-btn').addEventListener('click', () => this.hideSettingsModal());
    this.setupSettingsTabs();
    
    // Settings actions
    document.getElementById('settings-sounds-toggle-btn')?.addEventListener('click', (e) => {
      const enabled = this.sounds.toggle();
      e.target.textContent = enabled ? this.t('ui.on') : this.t('ui.off');
      this.updateSoundsToggleLabel(enabled);
      chrome.storage.local.set({ vault_sounds_enabled: enabled });
      if (enabled) this.sounds.playOK();
    });

    document.getElementById('expand-tab-btn').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') });
      window.close();
    });

    document.getElementById('change-pin-btn')?.addEventListener('click', () => {
      this.hideSettingsModal();
      document.getElementById('change-pin-modal').style.display = 'flex';
    });

    document.getElementById('close-change-pin-modal-btn').addEventListener('click', () => this.hideChangePinModal());
    document.getElementById('cancel-change-pin-btn').addEventListener('click', () => this.hideChangePinModal());
    document.getElementById('change-pin-form').addEventListener('submit', (e) => this.handleChangePin(e));

    document.getElementById('lock-timeout')?.addEventListener('change', async (e) => {
      const timeout = parseInt(e.target.value);
      await chrome.storage.local.set({ vault_lock_timeout: timeout });
      const valueLabel = timeout === 0
        ? this.t('ui.never')
        : this.t('ui.minutes_short', { count: timeout });
      this.showMessage(this.t('messages.auto_lock_set_to', { value: valueLabel }), 'success');
    });

    document.getElementById('theme-select')?.addEventListener('change', async (e) => {
      const theme = e.target.value;
      await chrome.storage.local.set({ vault_theme: theme });
      this.applyTheme(theme);
    });

    // Import/Export modals
    document.getElementById('close-import-modal-btn').addEventListener('click', () => this.hideImportModal());
    document.getElementById('cancel-import-btn').addEventListener('click', () => this.hideImportModal());
    document.getElementById('confirm-import-btn').addEventListener('click', () => this.handleImport());
    document.getElementById('import-file-input').addEventListener('change', (e) => this.handleImportFile(e));

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

    this.mainListenersBound = true;
  }

  setupSettingsTabs() {
    if (this.settingsTabsBound) return;
    const tabs = Array.from(document.querySelectorAll('.settings-tab'));
    if (!tabs.length) return;

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        this.setActiveSettingsTab(tab.dataset.settingsTab || 'general');
      });
    });
    this.settingsTabsBound = true;
  }

  setActiveSettingsTab(tabId) {
    const tabs = Array.from(document.querySelectorAll('.settings-tab'));
    const panels = Array.from(document.querySelectorAll('.settings-panel'));
    tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.settingsTab === tabId));
    panels.forEach((panel) => panel.classList.toggle('active', panel.id === `settings-panel-${tabId}`));
  }

  async initSiteIntegrationControls() {
    const statusEl = document.getElementById('site-access-status');
    const grantBtn = document.getElementById('grant-site-access-btn');
    const revokeBtn = document.getElementById('revoke-site-access-btn');

    if (!statusEl || !grantBtn || !revokeBtn) return;

    // Determine current tab origin.
    this.siteIntegrationOrigin = null;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab?.url ? new URL(tab.url) : null;
      if (url && (url.protocol === 'http:' || url.protocol === 'https:')) {
        this.siteIntegrationOrigin = url.origin;
      }
    } catch {
      this.siteIntegrationOrigin = null;
    }

    const render = async () => {
      const origin = this.siteIntegrationOrigin;
      if (!origin) {
        statusEl.textContent = this.t('messages.site_access_not_available') || 'Site access is not available for this page.';
        grantBtn.disabled = true;
        revokeBtn.disabled = true;
        return;
      }

      let has = false;
      try {
        has = await chrome.permissions.contains({ origins: [`${origin}/*`] });
      } catch {
        has = false;
      }

      statusEl.textContent = has
        ? (this.t('messages.site_access_enabled', { origin }) || `Enabled for ${origin}`)
        : (this.t('messages.site_access_disabled', { origin }) || `Disabled for ${origin}`);
      grantBtn.disabled = has;
      revokeBtn.disabled = !has;
    };

    if (!this.siteIntegrationHandlersBound) {
      grantBtn.addEventListener('click', async () => {
        const origin = this.siteIntegrationOrigin;
        if (!origin) return;
        try {
          const ok = await chrome.permissions.request({ origins: [`${origin}/*`] });
          if (!ok) {
            this.showMessage(this.t('messages.permission_denied') || 'Permission denied', 'error');
            return;
          }
          await this.sendMessage({ type: 'SITE_INTEGRATION_SYNC' });
          await render();
          this.showMessage(this.t('messages.site_access_enabled_short') || 'Enabled for this site', 'success');
        } catch (e) {
          this.logError(e, 'grantSiteAccess', true, this.t('messages.permission_request_failed') || 'Failed to request permission');
        }
      });

      revokeBtn.addEventListener('click', async () => {
        const origin = this.siteIntegrationOrigin;
        if (!origin) return;
        try {
          const ok = await chrome.permissions.remove({ origins: [`${origin}/*`] });
          if (!ok) {
            this.showMessage(this.t('messages.permission_remove_failed') || 'Failed to remove permission', 'error');
            return;
          }
          await this.sendMessage({ type: 'SITE_INTEGRATION_SYNC' });
          await render();
          this.showMessage(this.t('messages.site_access_disabled_short') || 'Disabled for this site', 'success');
        } catch (e) {
          this.logError(e, 'revokeSiteAccess', true, this.t('messages.permission_remove_failed') || 'Failed to remove permission');
        }
      });
      this.siteIntegrationHandlersBound = true;
    }

    await render();
  }

  async initDriveBackupControls() {
    const statusEl = document.getElementById('drive-status');
    const healthEl = document.getElementById('drive-health');
    const connectBtn = document.getElementById('drive-connect-btn');
    const backupBtn = document.getElementById('drive-backup-now-btn');
    const restoreBtn = document.getElementById('drive-restore-btn');
    const passEl = document.getElementById('drive-backup-password');

    if (!statusEl || !healthEl || !connectBtn || !backupBtn || !restoreBtn || !passEl) return;

    const setStatus = (text) => {
      statusEl.textContent = text || '';
    };
    const clearPassword = () => {
      passEl.value = '';
    };

    const ensureDriveLib = () => {
      if (!window.R2D2DriveSync) {
        throw new Error('Drive sync module not loaded');
      }
    };

    const formatDateTime = (iso) => {
      if (!iso) return '';
      try {
        return new Date(iso).toLocaleString();
      } catch {
        return '';
      }
    };

    const refreshDriveHealth = async (interactive = false) => {
      ensureDriveLib();
      try {
        let token;
        if (interactive) {
          token = await window.R2D2DriveSync.getAuthToken(true);
        } else {
          token = await window.R2D2DriveSync.getAuthToken(false);
        }

        const latest = await window.R2D2DriveSync.getLatestBackupMetadata(token);
        if (latest?.id) {
          restoreBtn.disabled = false;
          const when = formatDateTime(latest.modifiedTime);
          healthEl.textContent = when
            ? `Drive connected. Latest backup: ${when}`
            : 'Drive connected. Backup found.';
        } else {
          restoreBtn.disabled = true;
          healthEl.textContent = 'Drive connected. No backup found yet.';
        }
      } catch (e) {
        restoreBtn.disabled = true;
        healthEl.textContent = this.t('messages.drive_not_connected_hint') || 'Connect Drive to enable backups';
      }
    };

    const connect = async () => {
      ensureDriveLib();
      setStatus(this.t('messages.drive_connecting') || 'Connecting...');
      let token;
      try {
        token = await window.R2D2DriveSync.getAuthToken(true);
        setStatus(this.t('messages.drive_connected') || 'Connected');
      } catch (e) {
        setStatus(this.t('messages.drive_connect_failed') || 'Failed to connect');
        throw e;
      } finally {
        if (token) {
          // Keep token cached for non-interactive refresh later, but avoid storing it ourselves.
        }
      }
    };

    const backupNow = async () => {
      ensureDriveLib();
      const password = (passEl.value || '').trim();
      if (!password) {
        this.showError(this.t('messages.drive_password_required') || 'Backup password is required');
        return { cancelled: true };
      }

      setStatus(this.t('messages.drive_backup_in_progress') || 'Backing up...');

      // 1) Get current JSON export from background
      const exportRes = await this.sendMessage({ type: 'EXPORT_ACCOUNTS' });
      if (!exportRes?.success) {
        throw new Error(exportRes?.error || 'Export failed');
      }
      const rawJson = exportRes.data.json;

      // 2) Encrypt with user password
      const vault = new SecureVault();
      const encrypted = await vault.encryptExport(rawJson, password);

      // 3) Upload to Drive (appDataFolder)
      let token = await window.R2D2DriveSync.getAuthToken(false).catch(() => window.R2D2DriveSync.getAuthToken(true));
      try {
        await window.R2D2DriveSync.uploadBackupJson(token, encrypted);
        setStatus(this.t('messages.drive_backup_success') || 'Backup saved to Drive');
        this.sounds.playSuccess();
        return { ok: true };
      } catch (e) {
        // Token can be stale even if getAuthToken(false) returned one.
        const msg = String(e?.message || '');
        const shouldRefreshToken = msg.includes('(401)') || msg.includes('(403)');
        if (shouldRefreshToken) {
          try {
            await window.R2D2DriveSync.removeCachedToken(token);
            token = await window.R2D2DriveSync.getAuthToken(true);
            await window.R2D2DriveSync.uploadBackupJson(token, encrypted);
            setStatus(this.t('messages.drive_backup_success') || 'Backup saved to Drive');
            this.sounds.playSuccess();
            return { ok: true };
          } catch (retryErr) {
            throw retryErr;
          }
        }
        throw e;
      } finally {
        // Keep cached token (Chrome manages it).
      }
    };

    const restoreLatest = async () => {
      ensureDriveLib();
      const password = (passEl.value || '').trim();
      if (!password) {
        this.showError(this.t('messages.drive_password_required_restore') || 'Decryption password is required');
        return { cancelled: true, imported: 0, duplicates: 0 };
      }

      const confirmed = await this.showConfirm(
        this.t('ui.drive_restore_title') || 'Restore backup',
        this.t('ui.drive_restore_confirm') || 'This will import accounts from your latest Drive backup. Continue?'
      );
      if (!confirmed) return { cancelled: true, imported: 0, duplicates: 0 };

      setStatus(this.t('messages.drive_restore_in_progress') || 'Restoring...');

      let token = await window.R2D2DriveSync.getAuthToken(false).catch(() => window.R2D2DriveSync.getAuthToken(true));
      let encrypted;
      try {
        encrypted = await window.R2D2DriveSync.downloadBackupJson(token);
      } catch (e) {
        const msg = String(e?.message || '');
        const shouldRefreshToken = msg.includes('(401)') || msg.includes('(403)');
        if (shouldRefreshToken) {
          await window.R2D2DriveSync.removeCachedToken(token);
          token = await window.R2D2DriveSync.getAuthToken(true);
          encrypted = await window.R2D2DriveSync.downloadBackupJson(token);
        } else {
          throw e;
        }
      }
      if (!encrypted) {
        const msg = this.t('messages.drive_no_backup_found') || 'No backup found in Drive';
        setStatus(msg);
        throw new Error(msg);
      }

      const vault = new SecureVault();
      let decrypted;
      try {
        decrypted = await vault.decryptExport(encrypted, password);
      } catch (e) {
        this.showError(this.t('messages.bad_decryption_password_or_corrupt') || 'Wrong password or corrupt backup');
        setStatus(this.t('messages.drive_restore_failed') || 'Restore failed');
        throw e;
      }

      if (!decrypted || !Array.isArray(decrypted.accounts)) {
        const msg = this.t('messages.invalid_file_format_expected_json') || 'Invalid backup format';
        setStatus(msg);
        throw new Error(msg);
      }

      const importRes = await this.sendMessage({ type: 'IMPORT_ACCOUNTS', data: decrypted });
      if (!importRes?.success) {
        throw new Error(importRes?.error || 'Import failed');
      }

      const imported = Number(importRes.imported || 0);
      const duplicates = Number(importRes.duplicates || 0);
      setStatus(
        imported > 0
          ? `${this.t('messages.drive_restore_success') || 'Restore complete'} (${imported})`
          : `${this.t('messages.drive_restore_no_new_accounts') || 'Restore completed with no new accounts'} (${duplicates})`
      );
      await this.loadAccounts();
      await this.loadContextDomainMatches();
      await this.renderAccounts();
      this.sounds.playSuccess();
      return { imported, duplicates };
    };

    if (!this.driveHandlersBound) {
      connectBtn.addEventListener('click', async () => {
        try {
          await connect();
          await refreshDriveHealth(false);
          this.showMessage(this.t('messages.drive_connected_short') || 'Drive connected', 'success');
        } catch (e) {
          this.logError(e, 'driveConnect', true, this.t('messages.drive_connect_failed') || 'Failed to connect Drive');
        }
      });

      backupBtn.addEventListener('click', async () => {
        try {
          const result = await backupNow();
          if (!result || result.cancelled) {
            return;
          }
          await refreshDriveHealth(false);
          this.showMessage(this.t('messages.drive_backup_success') || 'Backup saved to Drive', 'success');
          clearPassword();
        } catch (e) {
          this.logError(e, 'driveBackupNow', true, this.t('messages.drive_backup_failed') || 'Drive backup failed');
          setStatus(`${this.t('messages.drive_backup_failed') || 'Drive backup failed'}: ${e?.message || 'unknown error'}`);
          clearPassword();
        }
      });

      restoreBtn.addEventListener('click', async () => {
        try {
          const result = await restoreLatest();
          if (!result || result.cancelled) {
            return;
          }
          await refreshDriveHealth(false);
          if (result.imported > 0) {
            this.showMessage(
              `${this.t('messages.drive_restore_success') || 'Restore complete'}: ${result.imported}`,
              'success'
            );
          } else {
            this.showMessage(
              this.t('messages.drive_restore_no_new_accounts') || 'Restore completed with no new accounts',
              'info'
            );
          }
          clearPassword();
        } catch (e) {
          this.logError(e, 'driveRestore', true, this.t('messages.drive_restore_failed') || 'Drive restore failed');
          setStatus(`${this.t('messages.drive_restore_failed') || 'Drive restore failed'}: ${e?.message || 'unknown error'}`);
          clearPassword();
        }
      });

      this.driveHandlersBound = true;
    }

    setStatus(this.t('messages.drive_not_connected_hint') || 'Connect Drive to enable backups');
    await refreshDriveHealth(false);
  }

  async loadAccounts() {
    try {
      const response = await this.sendMessage({ type: 'GET_ACCOUNTS' });
      if (response.success) {
        this.accounts = response.accounts;
      } else if (response.locked) {
        // Service worker restarted while popup was open — re-lock
        this.showView('view-unlock');
        this.setupUnlockHandlers();
      } else {
        this.logError(response.error || 'Failed to load accounts', 'loadAccounts', false);
        this.accounts = [];
      }
    } catch (error) {
      this.logError(error, 'loadAccounts', false);
      this.accounts = [];
    }
  }

  async loadContextDomainMatches() {
    this.contextDomain = null;
    // Default posture: hide accounts until context is known or user opts to show all.
    this.contextRelatedAccountIds = new Set();
    this.contextFilterEnabled = true;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) return;

      const url = new URL(tab.url);
      if (!/^https?:$/.test(url.protocol)) return;

      const domain = (url.hostname || '').toLowerCase();
      if (!domain) return;
      this.contextDomain = domain;
      this.contextFilterEnabled = true;

      const response = await this.sendMessage({
        type: 'GET_TOTP_CODES_FOR_DOMAIN',
        domain
      });

      if (response?.success && Array.isArray(response.accounts)) {
        this.contextRelatedAccountIds = new Set(
          response.accounts.map((account) => account.id).filter(Boolean)
        );
      }
    } catch (error) {
      // Context filtering is a UX enhancement; fail silently.
      this.contextDomain = null;
      this.contextRelatedAccountIds = new Set();
      this.contextFilterEnabled = true;
    }
    this.renderContextFilterInfo();
  }

  renderContextFilterInfo() {
    const info = document.getElementById('context-filter-info');
    const label = document.getElementById('context-filter-label');
    if (!info || !label) return;

    const hasContextFilter =
      this.contextFilterEnabled &&
      this.contextRelatedAccountIds instanceof Set &&
      !this.searchQuery;

    if (!hasContextFilter) {
      info.style.display = 'none';
      return;
    }

    label.textContent = this.contextDomain
      ? this.t('ui.filtered_by_domain', { domain: this.contextDomain })
      : (this.t('ui.filtered_by_no_domain') || 'No web domain context. Accounts hidden.');
    info.style.display = 'flex';
  }

  async renderAccounts() {
    const accountList = document.getElementById('account-list');
    const emptyState = document.getElementById('empty-state');

    if (!this.accounts || this.accounts.length === 0) {
      accountList.style.display = 'none';
      emptyState.style.display = 'block';
      document.getElementById('add-first-account-btn').addEventListener('click', () => this.showAddAccountModal());
      return;
    }

    accountList.style.display = 'flex';
    emptyState.style.display = 'none';

    // Apply sorting
    const settings = await chrome.storage.local.get('vault_sort_order');
    const sortOrder = settings.vault_sort_order || 'manual';
    
    let sortedAccounts = [...this.accounts];

    // Filter by search query
    if (this.searchQuery) {
      sortedAccounts = sortedAccounts.filter(acc => {
        const name = (acc.name || '').toLowerCase();
        const issuer = (acc.issuer || '').toLowerCase();
        return name.includes(this.searchQuery) || issuer.includes(this.searchQuery);
      });
    } else if (this.contextFilterEnabled && this.contextRelatedAccountIds instanceof Set) {
      // If opened from a web domain, limit visible accounts to strict domain matches (possibly none).
      sortedAccounts = sortedAccounts.filter((acc) => this.contextRelatedAccountIds.has(acc.id));
    }
    this.renderContextFilterInfo();

    if (sortOrder === 'alpha') {
      sortedAccounts.sort((a, b) => {
        const nameA = (a.issuer || a.name || '').toLowerCase();
        const nameB = (b.issuer || b.name || '').toLowerCase();
        return nameA.localeCompare(nameB);
      });
    }

    if (sortedAccounts.length === 0) {
      accountList.innerHTML = '';
      accountList.style.display = 'none';
      emptyState.style.display = 'block';
      const titleEl = emptyState.querySelector('h2');
      const subtitleEl = emptyState.querySelector('p');
      const isContextFilteredEmpty =
        this.contextFilterEnabled &&
        this.contextRelatedAccountIds instanceof Set &&
        !this.searchQuery;
      if (titleEl) {
        titleEl.textContent = isContextFilteredEmpty
          ? (this.contextDomain
            ? this.t('ui.no_accounts_for_domain')
            : (this.t('ui.no_accounts_without_domain') || 'Accounts hidden outside websites'))
          : this.t('ui.no_accounts');
      }
      if (subtitleEl) {
        subtitleEl.textContent = isContextFilteredEmpty
          ? (this.contextDomain
            ? this.t('ui.no_accounts_for_domain_subtitle', { domain: this.contextDomain })
            : (this.t('ui.no_accounts_without_domain_subtitle') || 'Open on an http(s) site or press Show all.'))
          : this.t('ui.add_first_subtitle');
      }
      return;
    }

    accountList.innerHTML = '';
    for (const account of sortedAccounts) {
      try {
        const accountElement = await this.createAccountElement(account);
        accountList.appendChild(accountElement);
      } catch (error) {
        this.logError(error, `renderAccounts[${account.name}]`, false);
      }
    }
  }

  async createAccountElement(account) {
    const div = document.createElement('div');
    div.className = 'account-item';
    div.dataset.accountId = account.id;

    try {
      const isHOTP = account.type === 'HOTP';
      let code;
      if (isHOTP) {
        code = await this.totp.generateHOTP(account.secret, account.counter || 0, account.digits || 6);
      } else {
        code = await this.totp.generate(account.secret, account.period || 30, account.digits || 6);
      }
      
      const remainingTime = isHOTP ? 0 : this.totp.getRemainingTime(account.period || 30);

      const iconUrl = this.getServiceIcon(account.issuer, account.name);

      div.innerHTML = `
        <div class="account-header">
          <div class="account-icon">
            <img src="${iconUrl}" width="24" height="24" alt="" onerror="this.style.display='none'">
          </div>
          <div class="account-info">
            <div class="account-name">${this.escapeHtml(account.name)}</div>
            <div class="account-issuer">${this.escapeHtml(account.issuer || '')}</div>
          </div>
          <div class="account-actions">
            <button class="autofill-btn icon-btn" data-account-id="${account.id}" data-code="${code}" title="${this.escapeHtml(this.t('ui.autofill_in_page'))}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
            </button>
            <button class="copy-btn btn-sm" data-account-id="${account.id}" data-code="${code}">${this.escapeHtml(this.t('ui.copy'))}</button>
            ${isHOTP ? `
            <button class="refresh-btn icon-btn" data-account-id="${account.id}" title="${this.escapeHtml(this.t('ui.increment_counter'))}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                </svg>
            </button>` : ''}
            <div class="more-menu">
              <button class="menu-dots">⋮</button>
              <div class="more-dropdown">
                <button class="edit-btn">${this.escapeHtml(this.t('ui.edit'))}</button>
                <button class="delete-btn">${this.escapeHtml(this.t('ui.delete'))}</button>
              </div>
            </div>
          </div>
        </div>
        <div class="account-body">
          <div class="code-display" data-account-id="${account.id}">${this.formatCode(code)}</div>
        </div>
        ${!isHOTP ? `
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill" data-account-id="${account.id}" style="width: ${(remainingTime / (account.period || 30)) * 100}%"></div>
          </div>
          <div class="timer-seconds" data-account-id="${account.id}">${remainingTime}s</div>
        </div>` : `
        <div class="counter-container">
          <div class="counter-label">Counter: ${account.counter || 0}</div>
        </div>`}
      `;

      this.lastCodeWindowByAccount[account.id] = Math.floor(Date.now() / 1000 / (account.period || 30));
      div.querySelector('.copy-btn').addEventListener('click', (e) => {
        const currentCode = e.currentTarget.getAttribute('data-code') || code;
        this.copyCode(account.id, currentCode);
      });
      div.querySelector('.autofill-btn').addEventListener('click', (e) => {
        const currentCode = e.currentTarget.getAttribute('data-code') || code;
        this.autofillCode(currentCode);
      });
      
      if (isHOTP) {
        div.querySelector('.refresh-btn').addEventListener('click', () => this.incrementCounter(account));
      }

      div.querySelector('.edit-btn').addEventListener('click', () => this.editAccount(account));
      div.querySelector('.delete-btn').addEventListener('click', () => this.deleteAccount(account.id));

      return div;
    } catch (error) {
      this.logError(error, `createAccountElement[${account.name}]`, false);
      throw error;
    }
  }

  getServiceIcon(issuer, name) {
    const extractDomain = (str) => {
      if (!str) return '';
      const s = str.toLowerCase().replace(/\s+/g, '');
      if (s.includes('.')) return s;
      return s + '.com';
    };
    const domain = extractDomain(issuer) || extractDomain(name) || 'example.com';
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  }

  formatCode(code) {
    // Format code with spaces for better readability
    return code.replace(/(.{3})/g, '$1 ').trim();
  }

  async incrementCounter(account) {
    try {
      account.counter = (account.counter || 0) + 1;
      const response = await this.sendMessage({
        type: 'UPDATE_ACCOUNT',
        account: account
      });

      if (response.success) {
        await this.loadAccounts();
        await this.renderAccounts();
        this.sounds.playSuccess();
      } else {
        throw new Error(response.error);
      }
    } catch (error) {
      this.logError(error, 'incrementCounter', true, this.t('messages.counter_increment_failed'));
    }
  }

  async autofillCode(code) {
    const cleanCode = code.replace(/\s/g, '');
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return;

      // Ensure we don't try to inject into restricted pages
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
        this.showError(this.t('messages.autofill_system_pages'));
        return;
      }

      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (codeToFill) => {
          const selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name*="otp"]',
            'input[name*="2fa"]',
            'input[name*="code"]',
            'input[id*="otp"]',
            'input[id*="2fa"]',
            'input[id*="code"]',
            'input[type="text"][maxlength="6"]',
            'input[type="tel"][maxlength="6"]'
          ];
          
          let target = document.activeElement;
          if (!target || target.tagName !== 'INPUT' || (target.type !== 'text' && target.type !== 'tel' && target.type !== 'password')) {
             for (const selector of selectors) {
               const el = document.querySelector(selector);
               if (el) {
                 target = el;
                 break;
               }
             }
          }

          if (target && target.tagName === 'INPUT') {
            target.focus();
            target.value = codeToFill;
            target.dispatchEvent(new Event('input', { bubbles: true }));
            target.dispatchEvent(new Event('change', { bubbles: true }));
            return true;
          }
          return false;
        },
        args: [cleanCode]
      }).then(results => {
        if (results && results[0] && results[0].result) {
          this.sounds.playSuccess();
          // Optional: window.close() if not in full tab
          if (!window.matchMedia('(min-width: 401px)').matches) {
            window.close();
          }
        } else {
          this.showError(this.t('messages.no_input_field_found'));
        }
      });
    } catch (err) {
      this.logError(err, 'autofillCode', true, this.t('messages.autofill_error'));
    }
  }

  copyCode(accountId, code) {
    const cleanCode = code.replace(/\s/g, '');
    navigator.clipboard.writeText(cleanCode).then(() => {
      const copyBtn = document.querySelector(`.copy-btn[data-account-id="${accountId}"]`);
      copyBtn.textContent = this.t('ui.copied');
      copyBtn.classList.add('copied');
      
      // Play copy sound
      this.sounds.playCopy();
      
      setTimeout(() => {
        copyBtn.textContent = this.t('ui.copy');
        copyBtn.classList.remove('copied');
      }, 2000);
    }).catch(err => {
      this.logError(err, 'copyCode', true, this.t('messages.copy_code_failed'));
    });
  }

  startTOTPUpdates() {
    this.stopTOTPUpdates();

    // Render current codes once, then only refresh on each TOTP window rollover.
    this.updateTOTPCodes();
    this.scheduleNextCodeRefresh();

    // Keep countdown/progress responsive without running per-frame.
    this.totpIntervalId = setInterval(() => {
      this.updateProgressBarsOnly();
    }, 1000);
  }

  stopTOTPUpdates() {
    if (this.totpIntervalId) {
      clearInterval(this.totpIntervalId);
      this.totpIntervalId = null;
    }
    if (this.codeRefreshTimeoutId) {
      clearTimeout(this.codeRefreshTimeoutId);
      this.codeRefreshTimeoutId = null;
    }
  }

  async updateTOTPCodes() {
    const nowSeconds = Math.floor(Date.now() / 1000);
    for (const account of this.accounts) {
      const codeDisplay = document.querySelector(`.code-display[data-account-id="${account.id}"]`);
      const copyBtn = document.querySelector(`.copy-btn[data-account-id="${account.id}"]`);
      
      if (codeDisplay) {
        const period = account.period || 30;
        const currentWindow = Math.floor(nowSeconds / period);
        const previousWindow = this.lastCodeWindowByAccount[account.id];

        if (previousWindow !== currentWindow) {
          const code = await this.totp.generate(account.secret, period, account.digits || 6);
          codeDisplay.textContent = this.formatCode(code);
          if (copyBtn) {
            copyBtn.setAttribute('data-code', code);
          }
          this.lastCodeWindowByAccount[account.id] = currentWindow;
        }
      }
    }
    this.updateProgressBarsOnly();
  }

  updateProgressBarsOnly() {
    for (const account of this.accounts) {
      const progressBar = document.querySelector(`.progress-fill[data-account-id="${account.id}"]`);
      const remainingTimeEl = document.querySelector(`.timer-seconds[data-account-id="${account.id}"]`);
      if (progressBar) {
        const period = account.period || 30;
        // Using exact ms for smooth animation
        const now = Date.now();
        const periodMs = period * 1000;
        const elapsedMs = now % periodMs;
        const remainingMs = periodMs - elapsedMs;
        const remainingTime = Math.ceil(remainingMs / 1000);
        
        progressBar.style.transform = `scaleX(${remainingMs / periodMs})`;
        
        if (remainingTimeEl) {
          remainingTimeEl.textContent = `${remainingTime}s`;
          // Alert state for final 5 seconds
          if (remainingTime <= 5) {
            remainingTimeEl.style.color = '#f44336';
            progressBar.classList.add('warning');
          } else {
            remainingTimeEl.style.color = '';
            progressBar.classList.remove('warning');
          }
        }
      }
    }
  }

  scheduleNextCodeRefresh() {
    const totpAccounts = this.accounts.filter((account) => account.type !== 'HOTP');
    if (totpAccounts.length === 0) {
      return;
    }

    const nowMs = Date.now();
    const msUntilNextWindow = totpAccounts.reduce((minMs, account) => {
      const periodMs = (account.period || 30) * 1000;
      const elapsedInWindow = nowMs % periodMs;
      const remaining = periodMs - elapsedInWindow;
      return Math.min(minMs, remaining);
    }, Number.POSITIVE_INFINITY);

    const delay = Math.max(50, Math.min(msUntilNextWindow + 20, 60_000));
    this.codeRefreshTimeoutId = setTimeout(async () => {
      await this.updateTOTPCodes();
      this.scheduleNextCodeRefresh();
    }, delay);
  }

  showAddAccountModal() {
    this.hideAllModals();
    document.getElementById('add-account-modal').style.display = 'flex';
    document.getElementById('account-name').focus();
  }

  hideAddAccountModal() {
    document.getElementById('add-account-modal').style.display = 'none';
    document.getElementById('add-account-form').reset();
    this.editingAccountId = null;
    const title = document.querySelector('#add-account-modal .modal-header h2');
    const submitBtn = document.querySelector('#add-account-form button[type="submit"]');
    if (title) title.textContent = this.t('ui.add_account');
    if (submitBtn) submitBtn.textContent = this.t('ui.add_account');
  }

  async handleAddAccount(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const accountData = {
      name: formData.get('name') || document.getElementById('account-name').value,
      issuer: document.getElementById('account-issuer').value,
      secret: document.getElementById('account-secret').value.toUpperCase().replace(/\s/g, ''),
      digits: parseInt(document.getElementById('account-digits').value),
      type: document.getElementById('account-type').value,
      counter: parseInt(document.getElementById('account-counter').value) || 0
    };

    try {
      // Validate secret format
      if (!this.isValidBase32(accountData.secret)) {
        throw new Error(this.i18n.t('messages.invalid_secret'));
      }

      // Test the secret by generating a code
      await this.totp.generate(accountData.secret);
      
      const isEditing = Boolean(this.editingAccountId);
      let response;
      if (isEditing) {
        accountData.id = this.editingAccountId;
        response = await this.sendMessage({
          type: 'UPDATE_ACCOUNT',
          account: accountData
        });
      } else {
        response = await this.sendMessage({
          type: 'ADD_ACCOUNT',
          account: accountData
        });
      }

      if (response.success) {
        this.hideAddAccountModal();
        await this.loadAccounts();
        await this.loadContextDomainMatches();
        await this.renderAccounts();
        this.sounds.playSuccess();
        this.showSuccess(isEditing ? 'account_updated' : 'account_added');
      } else {
        throw new Error(response.error || 'Failed to save account');
      }
    } catch (error) {
      this.logError(error, 'handleAddAccount', true, this.t('messages.save_account_failed'));
    }
  }

  isValidBase32(secret) {
    const base32Regex = /^[A-Z2-7]+=*$/;
    return base32Regex.test(secret.replace(/\s/g, ''));
  }

  async editAccount(account) {
    this.editingAccountId = account.id;
    document.getElementById('account-name').value = account.name;
    document.getElementById('account-issuer').value = account.issuer || '';
    document.getElementById('account-secret').value = account.secret;
    document.getElementById('account-digits').value = account.digits || 6;
    document.getElementById('account-type').value = account.type || 'TOTP';
    document.getElementById('account-counter').value = account.counter || 0;
    
    const counterGroup = document.getElementById('counter-group');
    if (counterGroup) {
      counterGroup.style.display = (account.type === 'HOTP') ? 'block' : 'none';
    }

    this.showAddAccountModal();
    const title = document.querySelector('#add-account-modal .modal-header h2');
    const submitBtn = document.querySelector('#add-account-form button[type="submit"]');
    if (title) title.textContent = this.t('ui.edit_account');
    if (submitBtn) submitBtn.textContent = this.t('ui.save');
  }

  async deleteAccount(accountId) {
    const confirmed = await this.showConfirm(
      this.t('ui.delete_account_title'),
      this.t('ui.delete_account_confirm')
    );
    if (!confirmed) {
      return;
    }

    try {
      const response = await this.sendMessage({
        type: 'DELETE_ACCOUNT',
        accountId: accountId
      });

      if (response.success) {
        await this.loadAccounts();
        await this.renderAccounts();
        this.showSuccess('account_deleted');
      } else {
        throw new Error(response.error || 'Failed to delete account');
      }
    } catch (error) {
      this.logError(error, 'deleteAccount', true, this.t('messages.delete_account_failed'));
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
        const rawJson = response.data.json;
        const otpauthExport = response.data.otpauth;
        const textarea = document.getElementById('export-data');
        const passInput = document.getElementById('export-password');
        
        let exportRenderToken = 0;
        const updateDisplay = async () => {
          const currentToken = ++exportRenderToken;
          const password = passInput.value;
          const activeTab = document.querySelector('.format-tab.active');
          const format = activeTab ? activeTab.dataset.format : 'json';
          
          if (format === 'otpauth') {
            textarea.value = otpauthExport;
            passInput.disabled = true;
          } else {
            passInput.disabled = false;
            if (password) {
              try {
                const vault = new SecureVault();
                const encrypted = await vault.encryptExport(rawJson, password);
                if (currentToken !== exportRenderToken) return;
                textarea.value = JSON.stringify(encrypted, null, 2);
              } catch (e) {
                this.logError(e, 'showExportModal/encrypt', false);
                if (currentToken !== exportRenderToken) return;
                textarea.value = 'Error encrypting data';
              }
            } else {
              if (currentToken !== exportRenderToken) return;
              textarea.value = JSON.stringify(rawJson, null, 2);
            }
          }
        };

        passInput.value = '';
        passInput.oninput = updateDisplay;
        
        document.getElementById('export-modal').style.display = 'flex';
        
        // Add format selector (only once)
        const modalContent = document.querySelector('#export-modal .modal-content');
        let formatSelector = modalContent.querySelector('.export-format-selector');
        if (!formatSelector) {
          const wrapper = document.createElement('div');
          wrapper.innerHTML = `
            <div class="export-format-selector">
              <label>${this.i18n.t('ui.export_format')}</label>
              <div class="format-tabs">
                <button class="format-tab active" data-format="json">JSON</button>
                <button class="format-tab" data-format="otpauth">otpauth://</button>
              </div>
            </div>
          `;

          formatSelector = wrapper.firstElementChild;
          const modalHeader = modalContent.querySelector('.modal-header');
          modalHeader.insertAdjacentElement('afterend', formatSelector);

          formatSelector.querySelectorAll('.format-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
              formatSelector.querySelectorAll('.format-tab').forEach(t => t.classList.remove('active'));
              e.target.classList.add('active');
              updateDisplay();
            });
          });
        }
        
        // Initialize display
        await updateDisplay();
      }
    } catch (error) {
      this.logError(error, 'showExportModal', true, this.t('messages.export_failed'));
    }
    this.hideMenu();
  }

  hideExportModal() {
    document.getElementById('export-modal').style.display = 'none';
  }

  copyExportData() {
    const exportData = document.getElementById('export-data');
    navigator.clipboard.writeText(exportData.value).catch(() => {
      exportData.select();
      document.execCommand('copy');
    });

    const copyBtn = document.getElementById('copy-export-btn');
    copyBtn.textContent = this.t('ui.copied_short');
    setTimeout(() => {
      copyBtn.textContent = this.t('ui.copy_to_clipboard');
    }, 2000);
  }

  showImportModal() {
    document.getElementById('import-modal').style.display = 'flex';
    this.hideMenu();
  }

  isExpandedTabView() {
    return window.matchMedia('(min-width: 401px)').matches;
  }

  isExtensionTabView() {
    return new Promise((resolve) => {
      try {
        chrome.tabs.getCurrent((tab) => {
          resolve(Boolean(tab && tab.id));
        });
      } catch {
        resolve(false);
      }
    });
  }

  handleStartupRoute() {
    if (window.location.hash === '#import') {
      this.showImportModal();
    }
  }

  async handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target.result;
      document.getElementById('import-data').value = content;
      this.showMessage(this.t('messages.file_loaded_continue_import'), 'info');
    };
    reader.readAsText(file);
  }

  hideImportModal() {
    document.getElementById('import-modal').style.display = 'none';
    document.getElementById('import-data').value = '';
    document.getElementById('import-file-input').value = '';
  }

  async handleImport() {
    const importData = document.getElementById('import-data').value.trim();
    const password = document.getElementById('import-password').value;
    
    try {
      if (!importData) {
        throw this.createImportValidationError(this.t('messages.invalid_file_format_expected_json'));
      }
      
      // Check if data is in otpauth format
      if (importData.startsWith('otpauth://')) {
        const response = await this.sendMessage({
          type: 'IMPORT_FROM_OTPAUTH',
          data: importData
        });
        return await this.processImportResponse(response);
      } 
      
      // Validate JSON before parsing
      let data;
      try {
        // Basic validation to check if content looks like JSON
        const trimmed = importData.trim();
        if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
          throw this.createImportValidationError(this.t('messages.invalid_file_format_expected_json'));
        }
        data = JSON.parse(importData);
      } catch (parseError) {
        if (parseError instanceof SyntaxError) {
          throw this.createImportValidationError(this.t('messages.invalid_json_format'));
        }
        throw parseError;
      }
      
      // If encrypted, decrypt first
      if (data.encrypted) {
        if (!password) {
          throw this.createImportValidationError(this.t('messages.backup_encrypted_needs_password'));
        }
        const vault = new SecureVault();
        try {
          data = await vault.decryptExport(data, password);
        } catch (e) {
          throw this.createImportValidationError(this.t('messages.bad_decryption_password_or_corrupt'));
        }
      }
      
      const response = await this.sendMessage({
        type: 'IMPORT_ACCOUNTS',
        data: data
      });
      
      await this.processImportResponse(response);

    } catch (error) {
      // Validation errors carry a friendly message; log technical ones only.
      this.logError(
        error,
        'handleImport',
        true,
        error?.isImportValidationError ? error.message : this.t('messages.import_failed')
      );
    }
  }

  createImportValidationError(message) {
    const error = new Error(message);
    error.isImportValidationError = true;
    return error;
  }

  async processImportResponse(response) {
    if (response.success) {
      this.hideImportModal();
      await this.loadAccounts();
      await this.loadContextDomainMatches();
      await this.renderAccounts();
      this.sounds.playSuccess();
      
      let message = `Imported ${response.imported} new accounts`;
      if (response.duplicates > 0) {
        message += ` (${response.duplicates} duplicates skipped)`;
      }
      
      const hasImportErrors = Array.isArray(response.errors) && response.errors.length > 0;
      if (hasImportErrors) {
        message += ` (${response.errors.length} failed)`;
        this.showError(message);
      } else {
        this.showSuccess(message);
      }

      // Import launched from popup opens a dedicated extension tab (#import).
      // Close that tab only when import is clean (no partial errors),
      // so the user can inspect warnings when there are failures.
      const launchedAsImportTab = window.location.hash === '#import';
      if (launchedAsImportTab && !hasImportErrors) {
        this.showMessage(
          this.t('messages.import_complete_closing_tab') || 'Import complete. Closing this tab...',
          'info'
        );
        setTimeout(() => window.close(), 1400);
      }
    } else {
      throw new Error(response.error || 'Failed to import accounts');
    }
  }

  showSettings() {
    this.hideMenu();
    document.getElementById('settings-modal').style.display = 'flex';
    this.setActiveSettingsTab('general');
    
    // Populate languages if empty
    const langSelect = document.getElementById('language-select');
    if (langSelect && langSelect.children.length === 0) {
      this.i18n.getAvailableLocales().forEach(locale => {
        const option = document.createElement('option');
        option.value = locale.code;
        option.textContent = locale.name;
        if (locale.code === this.i18n.currentLocale) option.selected = true;
        langSelect.appendChild(option);
      });
      langSelect.addEventListener('change', (e) => {
        this.i18n.setLocale(e.target.value);
      });
    }

    const countEl = document.getElementById('settings-account-count');
    if (countEl) countEl.textContent = this.t('ui.accounts_count', { count: this.accounts.length });
    const settingsToggle = document.getElementById('settings-sounds-toggle-btn');
    if (settingsToggle) {
      settingsToggle.textContent = this.sounds.enabled ? this.t('ui.on') : this.t('ui.off');
    }

    // Never keep backup password lingering in UI when reopening settings.
    const drivePass = document.getElementById('drive-backup-password');
    if (drivePass) {
      drivePass.value = '';
    }
  }

  hideSettingsModal() {
    document.getElementById('settings-modal').style.display = 'none';
  }

  hideChangePinModal() {
    document.getElementById('change-pin-modal').style.display = 'none';
    document.getElementById('change-pin-form').reset();
  }

  async handleChangePin(event) {
    event.preventDefault();
    const oldPin = document.getElementById('current-pin').value;
    const newPin = document.getElementById('new-pin').value;
    const confirmPin = document.getElementById('confirm-new-pin').value;

    if (newPin !== confirmPin) {
      this.showError(this.t('messages.new_pins_no_match'));
      return;
    }

    if (newPin.length < 4) {
      this.showError(this.t('messages.new_pin_min_length'));
      return;
    }

    try {
      const response = await this.sendMessage({
        type: 'CHANGE_PIN',
        data: { oldPin, newPin }
      });

      if (response.success) {
        this.hideChangePinModal();
        this.showSuccess(this.t('messages.pin_updated_success'));
        this.sounds.playSuccess();
      } else {
        this.showError(response.error || this.t('messages.pin_update_failed'));
        this.sounds.playError();
      }
    } catch (error) {
      this.logError(error, 'handleChangePin', true, this.t('messages.pin_update_error'));
    }
  }

  toggleSounds() {
    const enabled = this.sounds.toggle();
    this.updateSoundsToggleLabel(enabled);
    chrome.storage.local.set({ vault_sounds_enabled: enabled });
    
    // Play sound feedback when enabling
    if (enabled) {
      this.sounds.playOK();
    }
    
    this.hideMenu();
  }

  updateSoundsToggleLabel(enabled) {
    const button = document.getElementById('sounds-toggle-btn');
    if (!button) return;
    const state = enabled ? this.t('ui.on') : this.t('ui.off');
    button.textContent = this.t('ui.r2d2_sounds_state', { state });
  }

  testSounds() {
    this.sounds.testAllSounds();
    this.showMessage(this.t('messages.testing_sounds'), 'info');
    this.hideMenu();
  }

  showDebugModal() {
    this.hideMenu();
    
    // Create debug modal
    const debugModal = document.createElement('div');
    debugModal.id = 'debug-modal';
    debugModal.className = 'modal';
    debugModal.style.display = 'block';
    debugModal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h2>${this.t('ui.debug_totp')}</h2>
          <button class="close-btn">&times;</button>
        </div>
        <div class="debug-content">
          <div class="debug-section">
            <h3>${this.t('ui.time_sync')}</h3>
            <button id="debug-time-sync" class="btn btn-secondary">${this.t('ui.check_time_sync')}</button>
            <div id="time-sync-result"></div>
          </div>
          
          <div class="debug-section">
            <h3>${this.t('ui.test_vectors_rfc6238')}</h3>
            <button id="debug-test-vectors" class="btn btn-secondary">${this.t('ui.run_test_vectors')}</button>
            <div id="test-vectors-result"></div>
          </div>
          
          <div class="debug-section">
            <h3>${this.t('ui.account_debug')}</h3>
            <select id="debug-account-select">
              <option value="">${this.t('ui.select_account')}</option>
            </select>
            <button id="debug-account" class="btn btn-secondary">${this.t('ui.debug_account')}</button>
            <div id="account-debug-result"></div>
          </div>
          
          <div class="debug-section">
            <h3>${this.t('ui.time_window_analysis')}</h3>
            <select id="debug-time-account">
              <option value="">${this.t('ui.select_account')}</option>
            </select>
            <button id="debug-time-window" class="btn btn-secondary">${this.t('ui.analyze_time_windows')}</button>
            <div id="time-window-result"></div>
          </div>
        </div>
        <div class="form-actions">
          <button id="close-debug-modal" class="btn btn-primary">${this.t('ui.close')}</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(debugModal);
    
    // Populate account selects
    this.populateDebugAccounts();
    
    // Add event listeners
    debugModal.querySelector('.close-btn').addEventListener('click', () => this.hideDebugModal());
    document.getElementById('close-debug-modal').addEventListener('click', () => this.hideDebugModal());
    document.getElementById('debug-time-sync').addEventListener('click', () => this.debugTimeSync());
    document.getElementById('debug-test-vectors').addEventListener('click', () => this.debugTestVectors());
    document.getElementById('debug-account').addEventListener('click', () => this.debugAccount());
    document.getElementById('debug-time-window').addEventListener('click', () => this.debugTimeWindow());
  }

  hideDebugModal() {
    const debugModal = document.getElementById('debug-modal');
    if (debugModal) {
      debugModal.remove();
    }
  }

  populateDebugAccounts() {
    const selects = [
      document.getElementById('debug-account-select'),
      document.getElementById('debug-time-account')
    ];
    
    selects.forEach(select => {
      select.innerHTML = `<option value="">${this.t('ui.select_account')}</option>`;
      this.accounts.forEach(account => {
        const option = document.createElement('option');
        option.value = account.id;
        option.textContent = `${account.issuer}: ${account.name}`;
        select.appendChild(option);
      });
    });
  }

  async debugTimeSync() {
    const resultDiv = document.getElementById('time-sync-result');
    resultDiv.innerHTML = '<div class="loading">Checking...</div>';
    
    try {
      const response = await this.sendMessage({ type: 'DEBUG_TIME_SYNC' });
      if (response.success) {
        const data = response.data;
        resultDiv.innerHTML = `
          <div class="debug-result">
            <p><strong>Local Time:</strong> ${new Date(data.compensatedTime).toLocaleString()}</p>
            <p><strong>Time Drift:</strong> ${data.drift}ms</p>
            <p><strong>Status:</strong> ${Math.abs(data.drift) > 1000 ? 
              '<span style="color: red;">WARNING: Drift > 1s</span>' : 
              '<span style="color: green;">OK</span>'}</p>
          </div>
        `;
      }
    } catch (error) {
      this.logError(error, 'debugTimeSync', false);
      resultDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
  }

  async debugTestVectors() {
    const resultDiv = document.getElementById('test-vectors-result');
    resultDiv.innerHTML = '<div class="loading">Running tests...</div>';
    
    try {
      const response = await this.sendMessage({ type: 'DEBUG_TEST_VECTORS' });
      if (response.success) {
        resultDiv.innerHTML = `
          <div class="debug-result">
            <p>Test vectors executed. Check browser console for detailed results.</p>
            <p><strong>Expected result:</strong> 94287082</p>
            <p>Open Developer Tools (F12) to see full debug output.</p>
          </div>
        `;
      }
    } catch (error) {
      this.logError(error, 'debugTestVectors', false);
      resultDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
  }

  async debugAccount() {
    const accountId = document.getElementById('debug-account-select').value;
    const resultDiv = document.getElementById('account-debug-result');
    
    if (!accountId) {
      resultDiv.innerHTML = '<div class="error">Please select an account</div>';
      return;
    }
    
    resultDiv.innerHTML = '<div class="loading">Debugging...</div>';
    
    try {
      const response = await this.sendMessage({ 
        type: 'DEBUG_TOTP', 
        data: { accountId } 
      });
      
      if (response.success) {
        const data = response.data;
        resultDiv.innerHTML = `
          <div class="debug-result">
            <p><strong>Account:</strong> ${data.account.issuer}: ${data.account.name}</p>
            <p><strong>Secret:</strong> ${data.account.secret}</p>
            <p><strong>Current Code:</strong> <span style="font-size: 1.2em; font-weight: bold;">${data.currentCode}</span></p>
            <p><strong>Time Windows:</strong></p>
            <div style="font-family: monospace; font-size: 0.9em;">
              ${data.timeWindow.map(w => 
                `<div>${w.relative}: ${w.code || 'ERROR'} (${new Date(w.time).toLocaleTimeString()})</div>`
              ).join('')}
            </div>
            <p><em>Check browser console for detailed debug information</em></p>
          </div>
        `;
      }
    } catch (error) {
      this.logError(error, 'debugAccount', false);
      resultDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
  }

  async debugTimeWindow() {
    const accountId = document.getElementById('debug-time-account').value;
    const resultDiv = document.getElementById('time-window-result');
    
    if (!accountId) {
      resultDiv.innerHTML = '<div class="error">Please select an account</div>';
      return;
    }
    
    const account = this.accounts.find(acc => acc.id === accountId);
    if (!account) {
      resultDiv.innerHTML = '<div class="error">Account not found</div>';
      return;
    }
    
    resultDiv.innerHTML = '<div class="loading">Analyzing...</div>';
    
    try {
      const response = await this.sendMessage({ 
        type: 'DEBUG_TIME_WINDOW', 
        data: { 
          secret: account.secret,
          algorithm: account.algorithm || 'SHA1',
          steps: 5
        } 
      });
      
      if (response.success) {
        const data = response.data;
        resultDiv.innerHTML = `
          <div class="debug-result">
            <p><strong>Time Window Analysis (±5 steps):</strong></p>
            <div style="font-family: monospace; font-size: 0.9em; max-height: 200px; overflow-y: auto;">
              ${data.map(w => 
                `<div style="${w.relative === 'CURRENT' ? 'background: #e3f2fd; font-weight: bold;' : ''}">
                  ${w.relative.padEnd(12)} | ${(w.code || 'ERROR').toString().padEnd(8)} | ${new Date(w.time).toLocaleTimeString()}
                </div>`
              ).join('')}
            </div>
            <p><em>Current window is highlighted in blue</em></p>
          </div>
        `;
      }
    } catch (error) {
      this.logError(error, 'debugTimeWindow', false);
      resultDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
  }

  hideAllModals() {
    const qrModal = document.getElementById('qr-scanner-modal');
    const qrWasOpen = qrModal && qrModal.style.display !== 'none';
    document.querySelectorAll('.modal').forEach((modal) => {
      modal.style.display = 'none';
    });
    if (qrWasOpen && this.qrScanner) {
      this.qrScanner.stop();
      this.qrScanner = null;
    }
  }

  showMessage(message, type = 'info') {
    // Keep a single visible toast to avoid overlapping/conflicting statuses.
    document.querySelectorAll('.toast').forEach((el) => el.remove());

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

  showConfirm(title, message) {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'modal';
      overlay.style.display = 'flex';
      overlay.innerHTML = `
        <div class="modal-content">
          <div class="modal-header">
            <h2>${this.escapeHtml(title)}</h2>
            <button class="close-btn" aria-label="Close">&times;</button>
          </div>
          <div class="form-group">
            <p>${this.escapeHtml(message)}</p>
          </div>
          <div class="form-actions">
            <button type="button" class="btn btn-secondary" data-confirm="cancel">${this.t('ui.cancel')}</button>
            <button type="button" class="btn btn-primary" data-confirm="ok">${this.t('ui.confirm')}</button>
          </div>
        </div>
      `;

      const cleanup = (result) => {
        overlay.remove();
        resolve(result);
      };

      overlay.querySelector('[data-confirm="cancel"]').addEventListener('click', () => cleanup(false));
      overlay.querySelector('[data-confirm="ok"]').addEventListener('click', () => cleanup(true));
      overlay.querySelector('.close-btn').addEventListener('click', () => cleanup(false));
      overlay.addEventListener('click', (event) => {
        if (event.target === overlay) cleanup(false);
      });

      document.body.appendChild(overlay);
    });
  }

  showSuccess(messageOrKey, params = {}) {
    const isLiteral = /\s/.test(messageOrKey) || /[A-Z]/.test(messageOrKey);
    const message = isLiteral ? messageOrKey : this.i18n.t(`messages.${messageOrKey}`, params);
    this.showMessage(message, 'success');
  }

  showError(messageOrKey, params = {}) {
    const isLiteral = /\s/.test(messageOrKey) || /[A-Z]/.test(messageOrKey);
    const message = isLiteral ? messageOrKey : this.i18n.t(`messages.${messageOrKey}`, params);
    this.showMessage(message, 'error');
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // QR Scanner Functions
  showQRScannerModal() {
    this.hideMenu();
    
    const modal = document.getElementById('qr-scanner-modal');
    modal.style.display = 'block';
    
    // Initialize QR scanner
    this.qrScanner = new QRScanner();
    
    // Add event listeners
    if (!this.qrListenersBound) {
      this.setupQRScannerListeners();
      this.qrListenersBound = true;
    }
  }

  hideQRScannerModal() {
    const modal = document.getElementById('qr-scanner-modal');
    modal.style.display = 'none';
    
    // Stop scanner if active
    if (this.qrScanner) {
      this.qrScanner.stop();
      this.qrScanner = null;
    }
  }

  setupQRScannerListeners() {
    // Modal close buttons
    document.querySelector('#qr-scanner-modal .close-btn').addEventListener('click', () => this.hideQRScannerModal());
    document.getElementById('close-scanner-btn').addEventListener('click', () => this.hideQRScannerModal());
    
    // Camera controls
    document.getElementById('start-camera-btn').addEventListener('click', () => this.startQRScanner());
    document.getElementById('stop-camera-btn').addEventListener('click', () => this.stopQRScanner());
    document.getElementById('scan-tab-btn').addEventListener('click', () => this.scanCurrentTab());
    
    // Manual input
    document.getElementById('manual-input-btn').addEventListener('click', () => this.toggleManualInput());
    document.getElementById('import-manual-btn').addEventListener('click', () => this.importManualQRData());
  }

  async scanCurrentTab() {
    try {
      this.showMessage(this.t('messages.scanning_current_tab'), 'info');
      const response = await this.sendMessage({ type: 'CAPTURE_TAB' });

      // User may close the modal while capture runs; hideQRScannerModal() nulls qrScanner.
      // scanImage() does not need camera — use a throwaway instance if needed.
      const qrDecoder = this.qrScanner || new QRScanner();

      if (response && response.success && response.dataUrl) {
        const qrData = await qrDecoder.scanImage(response.dataUrl);
        if (qrData) {
          await this.importOtpauthData(qrData);
        } else {
          this.showError(this.t('messages.no_qr_current_page'));
        }
      } else {
        this.showError(`${this.t('messages.capture_failed')}: ${response?.error || this.t('messages.unknown_error')}`);
      }
    } catch (err) {
      this.logError(err, 'scanCurrentTab', true, this.t('messages.capture_error'));
    }
  }

  async startQRScanner() {
    const video = document.getElementById('qr-video');
    const canvas = document.getElementById('qr-canvas');
    const placeholder = document.getElementById('scanner-placeholder');
    const status = document.getElementById('scanner-status');
    const startBtn = document.getElementById('start-camera-btn');
    const stopBtn = document.getElementById('stop-camera-btn');
    const container = document.querySelector('.scanner-container');
    
    try {
      // Request camera permission
      const hasPermission = await this.qrScanner.initialize();
      
      if (!hasPermission) {
        this.showManualQRInput();
        this.showError(this.t('messages.camera_access_denied'));
        return;
      }
      
      // Show video and hide placeholder
      video.style.display = 'block';
      canvas.style.display = 'block';
      placeholder.style.display = 'none';
      status.style.display = 'block';
      status.textContent = this.t('messages.camera_initializing');
      
      // Update buttons
      startBtn.style.display = 'none';
      stopBtn.style.display = 'inline-block';
      
      // Add scanning class
      container.classList.add('scanning');
      
      // Start scanning
      status.textContent = this.t('messages.camera_scanning');
      await this.qrScanner.startScan(video, canvas, async (qrPayload) => {
        try {
          status.textContent = this.t('messages.qr_detected_importing');
          await this.importOtpauthData(qrPayload);
        } catch (error) {
          this.logError(error, 'startScan/callback', true, this.t('messages.qr_import_failed'));
        } finally {
          this.resetQRScannerUI();
        }
      });
      
    } catch (error) {
      this.logError(error, 'startQRScanner', true, this.t('messages.qr_start_failed'));
      this.resetQRScannerUI();
    }
  }

  stopQRScanner() {
    if (this.qrScanner) {
      this.qrScanner.stop();
    }
    
    this.resetQRScannerUI();
  }

  resetQRScannerUI() {
    const video = document.getElementById('qr-video');
    const canvas = document.getElementById('qr-canvas');
    const placeholder = document.getElementById('scanner-placeholder');
    const status = document.getElementById('scanner-status');
    const startBtn = document.getElementById('start-camera-btn');
    const stopBtn = document.getElementById('stop-camera-btn');
    const container = document.querySelector('.scanner-container');
    
    // Reset UI
    video.style.display = 'none';
    canvas.style.display = 'none';
    placeholder.style.display = 'flex';
    status.style.display = 'none';
    status.textContent = '';
    
    startBtn.style.display = 'inline-block';
    stopBtn.style.display = 'none';
    
    container.classList.remove('scanning');
  }

  toggleManualInput() {
    const manualSection = document.getElementById('manual-input-section');
    const isVisible = manualSection.style.display !== 'none';
    
    manualSection.style.display = isVisible ? 'none' : 'block';
  }

  showManualQRInput() {
    const manualSection = document.getElementById('manual-input-section');
    manualSection.style.display = 'block';
    
    // Update status
    const status = document.getElementById('scanner-status');
    status.style.display = 'block';
    status.textContent = this.t('messages.camera_manual_fallback');
  }

  async importManualQRData() {
    const input = document.getElementById('manual-qr-input').value.trim();
    
    if (!input) {
      this.showError(this.t('messages.qr_enter_data'));
      return;
    }
    
    try {
      const decoder = this.qrScanner || new QRScanner();
      const qrData = decoder.parseQRCode(input);
      
      if (!qrData) {
        this.showError(this.t('messages.qr_invalid_data'));
        return;
      }
      
      // Handle different types of QR data
      if (qrData.type === 'otpauth') {
        // Import otpauth URI
        await this.importOtpauthData(qrData.raw);
      } else if (qrData.raw && qrData.raw.startsWith('otpauth://')) {
        // Handle raw otpauth URI
        await this.importOtpauthData(qrData.raw);
      } else {
        this.showError(this.t('messages.qr_unsupported_format'));
      }
      
    } catch (error) {
      this.logError(error, 'importManualQRData', true, this.t('messages.qr_import_failed'));
    }
  }

  async importOtpauthData(otpauthData) {
    try {
      const response = await this.sendMessage({
        type: 'IMPORT_FROM_OTPAUTH',
        data: otpauthData
      });
      
      if (response.success) {
        this.hideQRScannerModal();
        await this.loadAccounts();
        await this.loadContextDomainMatches();
        await this.renderAccounts();
        this.sounds.playSuccess();
        
        let message = `Imported ${response.imported} new accounts`;
        if (response.duplicates > 0) {
          message += ` (${response.duplicates} duplicates skipped)`;
        }
        message += ` - Total: ${response.total} accounts`;
        
        this.showSuccess(message);
      } else {
        throw new Error(response.error || 'Failed to import QR code');
      }
    } catch (error) {
      this.logError(error, 'importOtpauthData', true, this.t('messages.qr_import_failed'));
    }
  }

  sendMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          return reject(new Error(chrome.runtime.lastError.message));
        }
        if (response === undefined) {
          return reject(new Error('No response from background service worker'));
        }
        resolve(response);
      });
    });
  }

  getCurrentLockoutDurationMs() {
    const base = 30_000;
    return base * Math.pow(2, this.unlockLockoutLevel);
  }

  setupInactivityLock() {
    // Don't set up inactivity lock if timeout is 0 (never lock)
    if (this.inactivityTimeoutMs === 0) {
      this.clearInactivityLock();
      return;
    }
    
    if (!this.activityEventsBound) {
      const onActivity = () => this.resetInactivityTimer();
      ['click', 'keydown', 'mousemove', 'mousedown', 'touchstart', 'scroll'].forEach((eventName) => {
        document.addEventListener(eventName, onActivity, { passive: true });
      });
      this.activityEventsBound = true;
    }
    this.resetInactivityTimer();
  }

  resetInactivityTimer() {
    if (this.inactivityTimeoutId) {
      clearTimeout(this.inactivityTimeoutId);
    }
    this.inactivityTimeoutId = setTimeout(() => this.handleInactivityTimeout(), this.inactivityTimeoutMs);
    
    // Update background's lastInteraction timestamp for coordination
    this.sendMessage({ type: 'UPDATE_ACTIVITY' }).catch(() => {
      // Ignore failures - popup might be closing
    });
  }

  clearInactivityLock() {
    if (this.inactivityTimeoutId) {
      clearTimeout(this.inactivityTimeoutId);
      this.inactivityTimeoutId = null;
    }
  }

  async handleInactivityTimeout() {
    try {
      await this.sendMessage({ type: 'LOCK_VAULT' });
    } catch (error) {
      // Ignore send failures during timeout-driven lock transitions
    } finally {
      this.stopTOTPUpdates();
      this.clearInactivityLock();
      this.showView('view-unlock');
      this.setupUnlockHandlers();
    }
  }

  isDevMode() {
    const manifest = chrome.runtime.getManifest();
    return Boolean(
      manifest.version_name &&
      manifest.version_name.toLowerCase().includes('dev')
    );
  }

  /**
   * Gestor centralizado de errores.
   * En modo desarrollo muestra trazas completas en consola y en el toast.
   * En producción sólo muestra mensajes amigables al usuario.
   *
   * @param {Error|string} error   - El error original o un mensaje.
   * @param {string}  context      - Dónde ocurrió (ej. 'handleAddAccount').
   * @param {boolean} showUser     - Si debe mostrarse un toast al usuario.
   * @param {string|null} userMsg  - Mensaje amigable de fallback (opcional).
   */
  logError(error, context = 'General', showUser = true, userMsg = null) {
    const isDev = this.isDevMode();
    const errorDetails = error instanceof Error ? error.message : String(error);
    const stackTrace   = error instanceof Error ? error.stack  : 'No stack trace';

    if (isDev) {
      console.group(`❌ Error en [${context}]`);
      console.error('Mensaje:', errorDetails);
      console.error('Pila:',    stackTrace);
      console.groupEnd();

      if (showUser) {
        this.showError(`[DEV] ${context}: ${errorDetails}`);
      }
    } else {
      // En producción sólo se muestra el mensaje amigable.
      // Aquí se podría enviar a un servidor de telemetría:
      // this.sendErrorToTelemetry(context, errorDetails);
      if (showUser) {
        const displayMsg = userMsg || this.t('messages.unknown_error') || 'Ocurrió un error inesperado.';
        this.showError(displayMsg);
      }
    }

    if (this.sounds && showUser) {
      this.sounds.playError();
    }
  }

  applyEnvironmentFlags() {
    if (this.isDevMode()) return;
    const debugBtn = document.getElementById('debug-btn');
    if (debugBtn) {
      debugBtn.style.display = 'none';
    }
  }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new SecureAuthenticatorUI();
});
