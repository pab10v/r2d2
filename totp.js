/**
 * Secure TOTP Implementation
 * Pure JavaScript implementation without external dependencies
 * Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)
 */

class SecureTOTP {
  constructor() {
    this.window = 30; // 30-second time window
    this.digits = 6;  // 6-digit codes by default
  }

  /**
   * Generate a TOTP code from a secret key
   * @param {string} secret - Base32 encoded secret
   * @param {number} timeWindow - Time window in seconds (default: 30)
   * @param {number} digits - Number of digits (default: 6)
   * @returns {string} TOTP code
   */
  generate(secret, timeWindow = this.window, digits = this.digits) {
    try {
      // Decode base32 secret
      const decodedSecret = this.base32Decode(secret);
      
      // Get current time counter
      const counter = Math.floor(Date.now() / 1000 / timeWindow);
      
      // Generate HMAC-SHA1
      const hmac = this.hmacSHA1(decodedSecret, this.intToBytes(counter));
      
      // Dynamic truncation
      const offset = hmac[hmac.length - 1] & 0x0f;
      const binary = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
      
      // Generate code
      const code = (binary % Math.pow(10, digits)).toString();
      return code.padStart(digits, '0');
    } catch (error) {
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
    const cleanBase32 = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
    
    let bits = '';
    for (const char of cleanBase32) {
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
   * Simple HMAC-SHA1 implementation
   * @param {Uint8Array} key - Secret key
   * @param {Uint8Array} message - Message to hash
   * @returns {Uint8Array} HMAC digest
   */
  hmacSHA1(key, message) {
    // Pad or truncate key to 64 bytes
    const paddedKey = new Uint8Array(64);
    if (key.length > 64) {
      const hash = this.sha1(key);
      paddedKey.set(hash);
    } else {
      paddedKey.set(key);
    }

    // Create inner and outer pads
    const innerPad = new Uint8Array(64);
    const outerPad = new Uint8Array(64);
    
    for (let i = 0; i < 64; i++) {
      innerPad[i] = paddedKey[i] ^ 0x36;
      outerPad[i] = paddedKey[i] ^ 0x5c;
    }

    // Compute inner hash
    const innerHash = this.sha1(this.concatUint8Arrays(innerPad, message));
    
    // Compute outer hash
    const outerHash = this.sha1(this.concatUint8Arrays(outerPad, innerHash));
    
    return outerHash;
  }

  /**
   * Simple SHA-1 implementation
   * @param {Uint8Array} data - Data to hash
   * @returns {Uint8Array} SHA-1 digest (20 bytes)
   */
  sha1(data) {
    // This is a simplified SHA-1 implementation
    // In production, use Web Crypto API for better security
    const words = this.bytesToWords(data);
    words.push(0x80);
    
    const len = data.length * 8;
    while (words.length % 16 !== 14) {
      words.push(0);
    }
    words.push(len >>> 29);
    words.push((len << 3) & 0xffffffff);

    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;

    for (let i = 0; i < words.length; i += 16) {
      const w = words.slice(i, i + 16);
      
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      
      for (let j = 0; j < 80; j++) {
        let f, k;
        
        if (j < 20) {
          f = (b & c) | (~b & d);
          k = 0x5a827999;
        } else if (j < 40) {
          f = b ^ c ^ d;
          k = 0x6ed9eba1;
        } else if (j < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8f1bbcdc;
        } else {
          f = b ^ c ^ d;
          k = 0xca62c1d6;
        }
        
        const temp = (this.rol(a, 5) + f + e + k + w[j % 16]) & 0xffffffff;
        e = d;
        d = c;
        c = this.rol(b, 30);
        b = a;
        a = temp;
      }
      
      h0 = (h0 + a) & 0xffffffff;
      h1 = (h1 + b) & 0xffffffff;
      h2 = (h2 + c) & 0xffffffff;
      h3 = (h3 + d) & 0xffffffff;
      h4 = (h4 + e) & 0xffffffff;
    }

    return this.wordsToBytes([h0, h1, h2, h3, h4]);
  }

  /**
   * Rotate left operation
   */
  rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }

  /**
   * Convert bytes to 32-bit words
   */
  bytesToWords(bytes) {
    const words = [];
    for (let i = 0; i < bytes.length; i += 4) {
      words.push(
        (bytes[i] << 24) |
        (bytes[i + 1] << 16) |
        (bytes[i + 2] << 8) |
        bytes[i + 3]
      );
    }
    return words;
  }

  /**
   * Convert 32-bit words to bytes
   */
  wordsToBytes(words) {
    const bytes = [];
    for (const word of words) {
      bytes.push(
        (word >>> 24) & 0xff,
        (word >>> 16) & 0xff,
        (word >>> 8) & 0xff,
        word & 0xff
      );
    }
    return new Uint8Array(bytes);
  }

  /**
   * Concatenate two Uint8Arrays
   */
  concatUint8Arrays(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
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
   * Verify a TOTP code
   * @param {string} secret - Base32 encoded secret
   * @param {string} token - Token to verify
   * @param {number} window - Time windows to check (default: 1)
   * @returns {boolean} True if valid
   */
  verify(secret, token, window = 1) {
    const counter = Math.floor(Date.now() / 1000 / this.window);
    
    for (let i = -window; i <= window; i++) {
      const testCounter = counter + i;
      const testToken = this.generate(secret, this.window, this.digits);
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
