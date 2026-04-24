/**
 * QR Scanner for R2D2 Authenticator
 * Lightweight QR code scanning implementation
 */

class QRScanner {
  constructor() {
    this.video = null;
    this.canvas = null;
    this.context = null;
    this.scanning = false;
    this.stream = null;
    this.scanAnimationId = null;
  }

  /**
   * Initialize QR scanner
   */
  async initialize() {
    try {
      // First check if mediaDevices and enumerateDevices are supported
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        return false;
      }
      
      // Check if any camera exists before requesting permission to avoid unhandled warnings
      const devices = await navigator.mediaDevices.enumerateDevices();
      const hasCamera = devices.some(device => device.kind === 'videoinput');
      
      if (!hasCamera) {
        // Silently fail if no camera is hardware present
        return false;
      }

      // Request camera permission
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      
      this.stream = stream;
      return true;
    } catch (error) {
      console.warn('Camera access denied or not available:', error);
      return false;
    }
  }

  /**
   * Scan static image dataUrl
   */
  async scanImage(dataUrl) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = this.detectQRCode(imageData);
        resolve(code);
      };
      img.onerror = () => resolve(null);
      img.src = dataUrl;
    });
  }

  /**
   * Start scanning QR codes
   * @param {HTMLVideoElement} video - Video element
   * @param {HTMLCanvasElement} canvas - Canvas element
   * @param {Function} onScan - Callback when QR code is detected
   */
  async startScan(video, canvas, onScan) {
    this.video = video;
    this.canvas = canvas;
    this.context = canvas.getContext('2d');
    this.scanning = true;

    // Set up video stream
    this.video.srcObject = this.stream;
    await this.video.play();

    // Start scanning loop
    this.scanFrame(onScan);
  }

  /**
   * Scan video frame for QR codes
   */
  async scanFrame(onScan) {
    if (!this.scanning) return;

    try {
      // Draw video frame to canvas
      this.context.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
      
      // Get image data
      const imageData = this.context.getImageData(0, 0, this.canvas.width, this.canvas.height);
      
      // Try to detect QR code using jsQR
      const qrData = this.detectQRCode(imageData);
      
      if (qrData) {
        onScan(qrData);
        this.stop();
      }
    } catch (error) {
      console.error('Scan frame error:', error);
    }

    // Continue scanning
    this.scanAnimationId = requestAnimationFrame(() => this.scanFrame(onScan));
  }

  /**
   * Detect QR code payload from ImageData using jsQR.
   */
  detectQRCode(imageData) {
    if (typeof window.jsQR !== 'function') {
      return null;
    }

    const code = window.jsQR(imageData.data, imageData.width, imageData.height);
    return code ? code.data : null;
  }

  /**
   * Stop scanning
   */
  stop() {
    this.scanning = false;
    if (this.scanAnimationId) {
      cancelAnimationFrame(this.scanAnimationId);
      this.scanAnimationId = null;
    }
    
    if (this.stream) {
      this.stream.getTracks().forEach(track => track.stop());
      this.stream = null;
    }
    
    if (this.video) {
      this.video.srcObject = null;
    }
  }

  /**
   * Parse QR code data (otpauth URI)
   */
  parseQRCode(qrData) {
    try {
      // Check if it's an otpauth URI
      if (qrData.startsWith('otpauth://')) {
        return this.parseOtpauthURI(qrData);
      }
      
      // Try to parse as JSON
      try {
        return JSON.parse(qrData);
      } catch (e) {
        // Return as raw text
        return { raw: qrData };
      }
    } catch (error) {
      console.error('QR parse error:', error);
      return null;
    }
  }

  /**
   * Parse otpauth URI
   */
  parseOtpauthURI(uri) {
    try {
      const url = new URL(uri);
      const pathParts = url.pathname.substring(1).split(':');
      const params = new URLSearchParams(url.search);
      
      return {
        type: 'otpauth',
        otpType: url.host,
        issuer: params.get('issuer') || (pathParts.length > 1 ? pathParts[0] : 'Unknown'),
        name: pathParts.length > 1 ? pathParts[1] : (pathParts[0] || 'Unknown'),
        secret: params.get('secret'),
        algorithm: params.get('algorithm') || 'SHA1',
        digits: parseInt(params.get('digits')) || 6,
        period: parseInt(params.get('period')) || 30,
        raw: uri
      };
    } catch (error) {
      console.error('otpauth parse error:', error);
      return null;
    }
  }
}

// Export for use in other modules
if (typeof window !== 'undefined') {
  window.QRScanner = QRScanner;
} else if (typeof self !== 'undefined') {
  self.QRScanner = QRScanner;
}
