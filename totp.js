/**
 * Secure TOTP Implementation
 * Pure JavaScript implementation without external dependencies
 * Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)
 */

class SecureTOTP {
  constructor(debug = false) {
    this.window = 30; // 30-second time window
    this.digits = 6;  // 6-digit codes by default
    this.debug = debug;
  }

  /**
   * Debug logging function
   */
  log(message, data = null) {
    if (this.debug) {
      console.log(`[TOTP DEBUG] ${message}`, data || '');
    }
  }

  /**
   * Generate a TOTP code from a secret key
   * @param {string} secret - Base32 encoded secret
   * @param {number} timeWindow - Time window in seconds (default: 30)
   * @param {number} digits - Number of digits (default: 6)
   * @param {string} algorithm - Hash algorithm (default: 'SHA1')
   * @param {number} timestamp - Unix timestamp (default: current time)
   * @returns {Promise<string>} TOTP code
   */
  async generate(secret, timeWindow = this.window, digits = this.digits, algorithm = 'SHA1', timestamp = null) {
    try {
      this.log('=== TOTP GENERATION START ===');
      this.log('Input parameters', { secret, timeWindow, digits, algorithm, timestamp });
      
      // RFC 6238: Validate parameters
      if (!secret || typeof secret !== 'string') {
        throw new Error('Invalid secret');
      }
      if (![6, 7, 8].includes(digits)) {
        throw new Error('Digits must be 6, 7, or 8');
      }
      if (![30, 60, 90].includes(timeWindow)) {
        throw new Error('Time step must be 30, 60, or 90 seconds');
      }
      if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) {
        throw new Error('Algorithm must be SHA1, SHA256, or SHA512');
      }
      
      // Decode base32 secret
      const decodedSecret = this.base32Decode(secret);
      this.log('Decoded secret', Array.from(decodedSecret));
      
      // RFC 6238: Get current time counter
      const currentTime = timestamp || Date.now();
      const counter = Math.floor(currentTime / 1000 / timeWindow);
      this.log('Time info', { currentTime, counter, timeWindow });
      
      // Generate counter bytes for debugging
      const counterBytes = this.intToBytes(counter);
      this.log('Counter bytes', Array.from(counterBytes));
      
      // Generate HMAC with specified algorithm
      const hmac = await this.hmac(decodedSecret, counterBytes, algorithm);
      this.log('HMAC result', Array.from(hmac));
      
      // RFC 4226: Dynamic truncation
      const offset = hmac[hmac.length - 1] & 0x0f;
      this.log('Dynamic truncation offset', offset);
      
      const binary = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
      
      this.log('Binary code', binary);
      this.log('Binary hex', '0x' + binary.toString(16));
      
      // Generate code
      const code = (binary % Math.pow(10, digits)).toString();
      const finalCode = code.padStart(digits, '0');
      this.log('Final TOTP code', finalCode);
      this.log('=== TOTP GENERATION END ===');
      
      return finalCode;
    } catch (error) {
      this.log('TOTP generation error', error);
      console.error('TOTP generation error:', error);
      throw new Error('Failed to generate TOTP code');
    }
  }

  /**
   * Decode Base32 string to Uint8Array
   * @param {string} base32 - Base32 encoded string
   * @returns {Uint8Array} Decoded bytes
   */
  base32Decode(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    // RFC 4648: Remove whitespace and handle padding
    const cleanBase32 = base32.toUpperCase()
      .replace(/\s+/g, '') // Remove all whitespace
      .replace(/[^A-Z2-7=]/g, ''); // Keep only valid chars and padding
    
    // RFC 4648: Validate padding
    const padIndex = cleanBase32.indexOf('=');
    if (padIndex !== -1) {
      const padLength = cleanBase32.length - padIndex;
      if (padLength > 6 || padLength % 2 !== 0) {
        throw new Error('Invalid Base32 padding');
      }
    }

    // Remove padding for decoding
    const withoutPadding = cleanBase32.replace(/=/g, '');


    let bits = '';
    for (const char of withoutPadding) {
      const val = alphabet.indexOf(char);
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, '0');
    }
    
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
      if (i + 8 <= bits.length) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
      }
    }
    
    return new Uint8Array(bytes);
  }

  /**
   * Convert integer to 8-byte array (big-endian)
   * @param {number} num - Integer to convert
   * @returns {Uint8Array} 8-byte array
   */
  intToBytes(num) {
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      bytes[i] = num & 0xff;
      num >>= 8;
    }
    return bytes;
  }

  /**
   * HMAC implementation using Web Crypto API
   * Supports SHA1, SHA256, SHA512
   * @param {Uint8Array} key - Secret key bytes
   * @param {Uint8Array} message - Message to authenticate
   * @param {string} algorithm - Hash algorithm ('SHA1', 'SHA256', 'SHA512')
   * @returns {Promise<Uint8Array>} HMAC digest
   */
  async hmac(key, message, algorithm = 'SHA1') {
    const algoMap = {
      'SHA1':   'SHA-1',
      'SHA256': 'SHA-256',
      'SHA512': 'SHA-512'
    };

    const cryptoAlgo = algoMap[algorithm];
    if (!cryptoAlgo) throw new Error(`Unsupported algorithm: ${algorithm}`);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: { name: cryptoAlgo } },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
  }

  /**
   * Get remaining time until next code refresh
   * @param {number} timeWindow - Time window in seconds
   * @returns {number} Remaining seconds
   */
  getRemainingTime(timeWindow = this.window) {
    const now = Math.floor(Date.now() / 1000);
    const nextWindow = Math.ceil(now / timeWindow) * timeWindow;
    return nextWindow - now;
  }

  /**
   * Debug function to test with known test vectors
   */
  debugWithTestVectors() {
    this.log('=== TESTING WITH RFC 6238 TEST VECTORS ===');
    
    // RFC 6238 Test Case 1
    const secret = '12345678901234567890'; // Base32 for "12345678901234567890"
    const time = 59; // Unix timestamp 59
    
    try {
      const result = this.generate(secret, 30, 8, 'SHA1', time * 1000);
      this.log('Test Case 1 (SHA1, time=59)', result);
      this.log('Expected: 94287082');
    } catch (error) {
      this.log('Test Case 1 failed', error);
    }
  }

  /**
   * Debug time synchronization
   */
  debugTimeSync() {
    this.log('=== TIME SYNCHRONIZATION DEBUG ===');
    
    const now = Date.now();
    const serverTime = now; // In production, get from NTP server
    const drift = now - serverTime;
    
    this.log('Local time', new Date(now));
    this.log('Server time', new Date(serverTime));
    this.log('Time drift (ms)', drift);
    
    if (Math.abs(drift) > 1000) {
      this.log('WARNING: Time drift > 1 second detected!');
    }
    
    // Test with time drift compensation
    const compensatedTime = now - drift;
    this.log('Compensated time', new Date(compensatedTime));
    
    return { drift, compensatedTime };
  }

  /**
   * Generate codes for multiple time steps (for debugging)
   */
  async generateTimeWindow(secret, algorithm = 'SHA1', steps = 3) {
    this.log(`=== GENERATING ${steps} TIME WINDOWS ===`);
    
    const now = Date.now();
    const timeWindow = 30;
    const currentCounter = Math.floor(now / 1000 / timeWindow);
    
    const results = [];
    for (let i = -steps; i <= steps; i++) {
      const counter = currentCounter + i;
      const timestamp = counter * timeWindow * 1000;
      const code = await this.generate(secret, timeWindow, 6, algorithm, timestamp);
      
      results.push({
        counter,
        timestamp,
        time: new Date(timestamp),
        code,
        relative: i === 0 ? 'CURRENT' : (i < 0 ? `${i} steps ago` : `+${i} steps`)
      });
    }
    
    this.log('Time window results', results);
    return results;
  }

  /**
   * Verify a TOTP code
   * @param {string} secret - Base32 encoded secret
   * @param {string} token - Token to verify
   * @param {number} window - Time windows to check (default: 1)
   * @returns {Promise<boolean>} True if valid
   */
  async verify(secret, token, window = 1) {
    const counter = Math.floor(Date.now() / 1000 / this.window);

    for (let i = -window; i <= window; i++) {
      const testToken = await this.generate(secret, this.window, this.digits);
      if (testToken === token) {
        return true;
      }
    }

    return false;
  }
}

// Export for use in extension (works in both popup and service worker)
if (typeof window !== 'undefined') {
  window.SecureTOTP = SecureTOTP;
} else if (typeof self !== 'undefined') {
  self.SecureTOTP = SecureTOTP;
}
