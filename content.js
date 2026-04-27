/**
 * Secure Authenticator Content Script
 * Handles 2FA field detection and auto-fill functionality
 */

class SecureAuthenticatorContent {
  constructor() {
    this.processedInputs = new Set();
    this.buttonSVG = this.createButtonSVG();
    this.processTimeout = null;
    this.observer = null;
    this.init();
  }

  init() {
    // Process existing inputs
    this.processInputs();
    
    // Watch for new inputs
    this.observeDOM();
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      return this.handleMessage(message, sender, sendResponse);
    });
  }

  /**
   * Process all input fields on the page
   */
  processInputs() {
    const inputs = document.querySelectorAll('input:not([data-secure-auth-processed])');
    
    inputs.forEach(input => {
      if (this.is2FAField(input)) {
        this.addAutofillButton(input);
        input.setAttribute('data-secure-auth-processed', 'true');
        this.processedInputs.add(input);
      }
    });
  }

  /**
   * Check if an input field is likely a 2FA field
   */
  is2FAField(input) {
    // Check autocomplete attribute
    if (input.autocomplete === 'one-time-code') {
      return true;
    }

    // Check input type
    const validTypes = ['text', 'number', 'tel', ''];
    if (!validTypes.includes(input.type)) {
      return false;
    }

    // Check max length (2FA codes are typically 4-8 digits)
    if (input.maxLength >= 4 && input.maxLength <= 8) {
      return true;
    }

    // Check input mode
    if (input.inputMode === 'numeric') {
      return true;
    }

    // Check field attributes for 2FA-related keywords
    const keywords = [
      'otp', 'totp', '2fa', 'mfa', 'two.?factor', 'verification.?code',
      'auth.?code', 'authenticator', 'security.?code', 'one.?time',
      'token', 'pin.?code'
    ];

    const searchText = [
      input.name,
      input.id,
      input.placeholder,
      input.className,
      input.getAttribute('aria-label')
    ].filter(Boolean).join(' ').toLowerCase();

    const hasKeyword = keywords.some(keyword => {
      try {
        return new RegExp(keyword, 'i').test(searchText);
      } catch (e) {
        return false;
      }
    });

    if (hasKeyword) {
      return true;
    }

    // Check associated labels
    const labels = this.getAssociatedLabels(input);
    return labels.some(label => {
      const labelText = label.textContent.toLowerCase();
      return keywords.some(keyword => {
        try {
          return new RegExp(keyword, 'i').test(labelText);
        } catch (e) {
          return false;
        }
      });
    });
  }

  /**
   * Get associated labels for an input
   */
  getAssociatedLabels(input) {
    const labels = [];
    
    // Check for explicit label association
    if (input.id) {
      const explicitLabel = document.querySelector(`label[for="${input.id}"]`);
      if (explicitLabel) {
        labels.push(explicitLabel);
      }
    }

    // Check for parent labels
    if (input.labels && input.labels.length > 0) {
      labels.push(...Array.from(input.labels));
    }

    // Check for nearby labels
    const parent = input.closest('div, form, fieldset');
    if (parent) {
      const nearbyLabels = parent.querySelectorAll('label');
      labels.push(...Array.from(nearbyLabels));
    }

    return labels;
  }

  /**
   * Add autofill button to input field
   */
  addAutofillButton(input) {
    // Create wrapper div
    const wrapper = document.createElement('div');
    wrapper.className = 'secure-auth-wrapper';

    // Get computed styles
    const computedStyle = window.getComputedStyle(input);
    wrapper.style.width = computedStyle.width;

    // Wrap the input
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    // Create autofill button
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secure-auth-btn';
    button.innerHTML = this.buttonSVG;
    button.title = 'Fill 2FA code';
    button.setAttribute('aria-label', 'Fill 2FA code');

    // Add click handler
    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.showCodePicker(input, button);
    });

    // Add button to wrapper
    wrapper.appendChild(button);

    // Add some padding to input to make room for button
    input.style.paddingRight = '40px';
  }

  /**
   * Create SVG for the autofill button
   */
  createButtonSVG() {
    return `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="#4285F4" stroke-width="2" fill="none"/>
        <path d="M12 8v4l3 3" stroke="#4285F4" stroke-width="2" stroke-linecap="round"/>
        <circle cx="12" cy="12" r="2" fill="#4285F4"/>
      </svg>
    `;
  }

  /**
   * Show code picker for selecting 2FA account
   */
  async showCodePicker(input, button) {
    // Remove existing pickers
    this.removeCodePickers();

    // Get current domain
    const domain = window.location.hostname;
    
    try {
      // Get TOTP codes for current domain
      const response = await this.sendMessage({
        type: 'GET_TOTP_CODES_FOR_DOMAIN',
        domain: domain
      });

      if (response.locked) {
        this.showError('R2D2 is locked. Open the extension popup to unlock.');
      } else if (response.success && response.accounts.length > 0) {
        this.createCodePicker(input, button, response.accounts, response.bound, domain);
      } else {
        this.showError('No 2FA accounts found for this site');
      }
    } catch (error) {
      console.error('Error getting TOTP codes:', error);
      this.showError('Failed to get 2FA codes');
    }
  }

  /**
   * Create and display code picker UI
   */
  createCodePicker(input, button, accounts, isBound, domain) {
    const picker = document.createElement('div');
    picker.className = 'secure-auth-picker';

    // Create header
    const header = document.createElement('div');
    header.className = 'secure-auth-picker-header';
    header.textContent = isBound ? 'Bound Account' : `Accounts for ${domain}`;
    picker.appendChild(header);

    // Create account list
    accounts.forEach(account => {
      const accountItem = document.createElement('div');
      accountItem.className = 'secure-auth-picker-item';
      accountItem.innerHTML = `
        <div class="secure-auth-picker-item-content">
          <div class="secure-auth-picker-account">
            <div class="secure-auth-picker-issuer">
              ${this.escapeHtml(account.issuer || account.name)}
            </div>
            <div class="secure-auth-picker-name">
              ${this.escapeHtml(account.name)}
            </div>
          </div>
          <div class="secure-auth-picker-code">
            ${this.formatCode(account.code)}
          </div>
        </div>
      `;

      // Add click handler
      accountItem.addEventListener('click', () => {
        this.fillCode(input, account.code);
        this.saveDomainBinding(domain, account.id);
        this.removeCodePickers();
      });

      picker.appendChild(accountItem);
    });

    // Position and show picker
    const buttonRect = button.getBoundingClientRect();
    const inputRect = input.getBoundingClientRect();
    
    picker.style.top = `${buttonRect.bottom - inputRect.top + 4}px`;
    picker.style.right = '0';

    input.parentElement.appendChild(picker);

    // Add click outside handler
    setTimeout(() => {
      const clickOutsideHandler = (e) => {
        if (!picker.contains(e.target) && e.target !== button) {
          this.removeCodePickers();
          document.removeEventListener('click', clickOutsideHandler);
        }
      };
      document.addEventListener('click', clickOutsideHandler);
    }, 0);
  }

  /**
   * Fill the input field with the selected code
   */
  fillCode(input, code) {
    const cleanCode = code.replace(/\s/g, '');
    
    // Try to use the value setter if available
    const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    if (descriptor && descriptor.set) {
      descriptor.set.call(input, cleanCode);
    } else {
      input.value = cleanCode;
    }

    // Trigger events
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    
    // Focus the input
    input.focus();

    // Visual feedback
    input.style.backgroundColor = '#e8f5e8';
    setTimeout(() => {
      input.style.backgroundColor = '';
    }, 500);
  }

  /**
   * Save domain binding for future use
   */
  async saveDomainBinding(domain, accountId) {
    try {
      await this.sendMessage({
        type: 'SAVE_DOMAIN_BINDING',
        domain: domain,
        accountId: accountId
      });
    } catch (error) {
      console.error('Error saving domain binding:', error);
    }
  }

  /**
   * Remove all code pickers from the page
   */
  removeCodePickers() {
    const pickers = document.querySelectorAll('.secure-auth-picker');
    pickers.forEach(picker => picker.remove());
  }

  /**
   * Format code with spaces for better readability
   */
  formatCode(code) {
    return code.replace(/(.{3})/g, '$1 ').trim();
  }

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Show error message
   */
  showError(message) {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = 'secure-auth-toast secure-auth-toast-error';
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 3000);
  }

  /**
   * Observe DOM changes for new input fields
   */
  observeDOM() {
    this.observer = new MutationObserver((mutations) => {
      let shouldProcess = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type !== 'childList' || mutation.addedNodes.length === 0) {
          return;
        }

        const hasNewInputs = Array.from(mutation.addedNodes).some((node) => {
          if (node.nodeType !== Node.ELEMENT_NODE) return false;
          if (node.tagName === 'INPUT') return true;
          return typeof node.querySelector === 'function' && !!node.querySelector('input');
        });

        if (hasNewInputs) {
          shouldProcess = true;
        }
      });

      if (shouldProcess) {
        // Debounce aggressively to reduce overhead on noisy SPAs.
        clearTimeout(this.processTimeout);
        this.processTimeout = setTimeout(() => {
          this.processInputs();
        }, 250);
      }
    });

    if (!document.body) {
      return;
    }

    this.observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  /**
   * Handle messages from background script
   */
  handleMessage(message, sender, sendResponse) {
    // Handle any messages from background script if needed
    sendResponse({ success: true });
    return false;
  }

  /**
   * Send message to background script
   */
  sendMessage(message) {
    return new Promise((resolve, reject) => {
      this.sendMessageWithRetry(message, 1, resolve, reject);
    });
  }

  sendMessageWithRetry(message, retriesLeft, resolve, reject) {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        const errorMessage = chrome.runtime.lastError.message || 'Background communication error';
        const shouldRetry =
          retriesLeft > 0 &&
          (errorMessage.includes('Receiving end does not exist') ||
            errorMessage.includes('Could not establish connection') ||
            errorMessage.includes('message port closed'));

        if (shouldRetry) {
          setTimeout(() => {
            this.sendMessageWithRetry(message, retriesLeft - 1, resolve, reject);
          }, 120);
          return;
        }

        reject(new Error(errorMessage));
        return;
      }

      if (response === undefined) {
        reject(new Error('No response from background service worker'));
        return;
      }

      resolve(response);
    });
  }
}

// Initialize the content script
new SecureAuthenticatorContent();
