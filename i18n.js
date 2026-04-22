/**
 * R2D2 Internationalization System
 * Secure, offline translation system
 */

class R2D2I18n {
  constructor() {
    this.currentLocale = 'en';
    this.fallbackLocale = 'en';
    this.translations = new Map();
    this.loadedLocales = new Set();
    
    this.init();
  }

  async init() {
    // Detect browser language
    this.currentLocale = this.detectBrowserLanguage();
    
    // Load translations
    await this.loadTranslations(this.currentLocale);
    
    // Fallback to English if current locale not available
    if (!this.loadedLocales.has(this.currentLocale)) {
      await this.loadTranslations(this.fallbackLocale);
      this.currentLocale = this.fallbackLocale;
    }
  }

  detectBrowserLanguage() {
    // Get browser language
    const browserLang = navigator.language || navigator.userLanguage;
    
    // Map common language codes
    const langMap = {
      'en': 'en',
      'en-US': 'en',
      'en-GB': 'en',
      'es': 'es',
      'es-ES': 'es',
      'es-MX': 'es',
      'es-AR': 'es',
      'fr': 'fr',
      'fr-FR': 'fr',
      'de': 'de',
      'de-DE': 'de',
      'it': 'it',
      'it-IT': 'it',
      'pt': 'pt',
      'pt-BR': 'pt',
      'pt-PT': 'pt',
      'ja': 'ja',
      'ja-JP': 'ja',
      'ko': 'ko',
      'ko-KR': 'ko',
      'zh': 'zh',
      'zh-CN': 'zh',
      'zh-TW': 'zh',
      'ru': 'ru',
      'ru-RU': 'ru',
      'ar': 'ar',
      'ar-SA': 'ar',
      'hi': 'hi',
      'hi-IN': 'hi',
      'th': 'th',
      'th-TH': 'th',
      'vi': 'vi',
      'vi-VN': 'vi'
    };

    // Extract primary language code
    const primaryLang = browserLang.split('-')[0];
    
    // Return mapped language or fallback to English
    return langMap[browserLang] || langMap[primaryLang] || 'en';
  }

  async loadTranslations(locale) {
    if (this.loadedLocales.has(locale)) {
      return; // Already loaded
    }

    try {
      // Load translation file
      const response = await fetch(chrome.runtime.getURL(`locales/${locale}.json`));
      
      if (response.ok) {
        const translations = await response.json();
        this.translations.set(locale, translations);
        this.loadedLocales.add(locale);
      }
    } catch (error) {
      console.warn(`Failed to load translations for ${locale}:`, error);
    }
  }

  t(key, params = {}) {
    // Get translation for current locale
    let translation = this.getNestedValue(this.translations.get(this.currentLocale), key);
    
    // Fallback to English if not found
    if (!translation && this.currentLocale !== this.fallbackLocale) {
      translation = this.getNestedValue(this.translations.get(this.fallbackLocale), key);
    }
    
    // Return key if no translation found
    if (!translation) {
      return key;
    }
    
    // Replace parameters in translation
    return this.replaceParams(translation, params);
  }

  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : null;
    }, obj);
  }

  replaceParams(text, params) {
    return text.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return params[key] !== undefined ? params[key] : match;
    });
  }

  async setLocale(locale) {
    if (locale === this.currentLocale) {
      return; // Already set
    }

    await this.loadTranslations(locale);
    
    if (this.loadedLocales.has(locale)) {
      this.currentLocale = locale;
      this.updateUI();
    }
  }

  updateUI() {
    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(element => {
      const key = element.getAttribute('data-i18n');
      const translation = this.t(key);
      
      if (element.tagName === 'INPUT' && element.type === 'text') {
        element.placeholder = translation;
      } else if (element.tagName === 'INPUT' && element.type === 'submit') {
        element.value = translation;
      } else {
        element.textContent = translation;
      }
    });

    // Update title
    const titleKey = document.querySelector('title')?.getAttribute('data-i18n');
    if (titleKey) {
      document.title = this.t(titleKey);
    }
  }

  getAvailableLocales() {
    return [
      { code: 'en', name: 'English' },
      { code: 'es', name: 'Español' },
      { code: 'fr', name: 'Français' },
      { code: 'de', name: 'Deutsch' },
      { code: 'it', name: 'Italiano' },
      { code: 'pt', name: 'Português' },
      { code: 'ja', name: 'Japanese' },
      { code: 'ko', name: 'Korean' },
      { code: 'zh', name: 'Chinese' },
      { code: 'ru', name: 'Russian' },
      { code: 'ar', name: 'Arabic' },
      { code: 'hi', name: 'Hindi' }
    ];
  }

  getCurrentLocale() {
    return this.currentLocale;
  }
}

// Export for use in extension
window.R2D2I18n = R2D2I18n;
