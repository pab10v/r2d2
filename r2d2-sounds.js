/**
 * R2D2 Sound System
 * Pure JavaScript sound generation using Web Audio API
 * No external dependencies, 100% offline and secure
 */

class R2D2Sounds {
  constructor() {
    this.audioContext = null;
    this.enabled = true;
    this.volume = 0.3; // Conservative volume level
    
    this.init();
  }

  init() {
    // Initialize Audio Context on user interaction (required by browsers)
    this.initAudioContext();
  }

  initAudioContext() {
    try {
      if (!this.audioContext) {
        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      }
    } catch (error) {
      console.warn('Audio not supported:', error);
      this.enabled = false;
    }
  }

  /**
   * Generate a beep sound with specific parameters
   * @param {number} frequency - Frequency in Hz
   * @param {number} duration - Duration in milliseconds
   * @param {number} type - Wave type (sine, square, sawtooth, triangle)
   */
  playBeep(frequency, duration, type = 'sine') {
    if (!this.enabled || !this.audioContext) return;

    try {
      // Resume audio context if suspended (browser requirement)
      if (this.audioContext.state === 'suspended') {
        this.audioContext.resume();
      }

      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();

      // Configure oscillator
      oscillator.type = type;
      oscillator.frequency.setValueAtTime(frequency, this.audioContext.currentTime);

      // Configure gain (volume)
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(this.volume, this.audioContext.currentTime + 0.01);
      gainNode.gain.linearRampToValueAtTime(0, this.audioContext.currentTime + duration / 1000);

      // Connect nodes
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);

      // Play sound
      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + duration / 1000);

    } catch (error) {
      console.warn('Error playing sound:', error);
    }
  }

  /**
   * R2D2 OK sound - Positive confirmation
   * Series of ascending beeps
   */
  playOK() {
    if (!this.enabled) return;

    const beeps = [
      { freq: 800, duration: 100, delay: 0 },
      { freq: 1000, duration: 100, delay: 150 },
      { freq: 1200, duration: 150, delay: 300 }
    ];

    beeps.forEach(beep => {
      setTimeout(() => {
        this.playBeep(beep.freq, beep.duration, 'sine');
      }, beep.delay);
    });
  }

  /**
   * R2D2 Error sound - Negative feedback
   * Descending buzz sound
   */
  playError() {
    if (!this.enabled) return;

    // Create a buzz/error sound
    try {
      if (this.audioContext.state === 'suspended') {
        this.audioContext.resume();
      }

      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();

      // Error sound: descending frequency with square wave
      oscillator.type = 'square';
      oscillator.frequency.setValueAtTime(400, this.audioContext.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(100, this.audioContext.currentTime + 0.3);

      // Quick fade out
      gainNode.gain.setValueAtTime(this.volume, this.audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.3);

      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);

      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.3);

    } catch (error) {
      console.warn('Error playing error sound:', error);
    }
  }

  /**
   * R2D2 Warning sound - Alert
   * Two-tone warning beep
   */
  playWarning() {
    if (!this.enabled) return;

    const beeps = [
      { freq: 600, duration: 200, delay: 0 },
      { freq: 600, duration: 200, delay: 300 }
    ];

    beeps.forEach(beep => {
      setTimeout(() => {
        this.playBeep(beep.freq, beep.duration, 'triangle');
      }, beep.delay);
    });
  }

  /**
   * R2D2 Success sound - Account added/updated
   * Happy chirp
   */
  playSuccess() {
    if (!this.enabled) return;

    const beeps = [
      { freq: 1000, duration: 80, delay: 0 },
      { freq: 1200, duration: 80, delay: 100 },
      { freq: 1400, duration: 120, delay: 200 }
    ];

    beeps.forEach(beep => {
      setTimeout(() => {
        this.playBeep(beep.freq, beep.duration, 'sine');
      }, beep.delay);
    });
  }

  /**
   * R2D2 Copy sound - Code copied
   * Quick confirmation beep
   */
  playCopy() {
    if (!this.enabled) return;
    this.playBeep(1500, 50, 'sine');
  }

  /**
   * R2D2 Thinking sound - Processing
   * Low hum
   */
  playThinking() {
    if (!this.enabled) return;
    this.playBeep(200, 100, 'triangle');
  }

  /**
   * R2D2 Welcome sound - Extension opened
   * Friendly greeting
   */
  playWelcome() {
    if (!this.enabled) return;

    const beeps = [
      { freq: 800, duration: 60, delay: 0 },
      { freq: 1000, duration: 60, delay: 80 },
      { freq: 900, duration: 80, delay: 160 }
    ];

    beeps.forEach(beep => {
      setTimeout(() => {
        this.playBeep(beep.freq, beep.duration, 'sine');
      }, beep.delay);
    });
  }

  /**
   * Toggle sounds on/off
   */
  toggle() {
    this.enabled = !this.enabled;
    return this.enabled;
  }

  /**
   * Set volume (0.0 to 1.0)
   */
  setVolume(level) {
    this.volume = Math.max(0, Math.min(1, level));
  }

  /**
   * Get current status
   */
  getStatus() {
    return {
      enabled: this.enabled,
      volume: this.volume,
      supported: !!this.audioContext
    };
  }

  /**
   * Test all sounds
   */
  testAllSounds() {
    const sounds = [
      { name: 'Welcome', fn: () => this.playWelcome(), delay: 0 },
      { name: 'OK', fn: () => this.playOK(), delay: 1000 },
      { name: 'Warning', fn: () => this.playWarning(), delay: 2000 },
      { name: 'Error', fn: () => this.playError(), delay: 3000 },
      { name: 'Success', fn: () => this.playSuccess(), delay: 4000 },
      { name: 'Copy', fn: () => this.playCopy(), delay: 5000 }
    ];

    sounds.forEach(sound => {
      setTimeout(() => {
        console.log(`Playing ${sound.name} sound`);
        sound.fn();
      }, sound.delay);
    });
  }
}

// Export for use in extension
window.R2D2Sounds = R2D2Sounds;
