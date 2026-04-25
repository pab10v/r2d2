/**
 * R2D2 Offscreen Bridge
 * This script runs in a non-sandboxed offscreen document.
 * It acts as a bridge between the Service Worker (Background) and the sandboxed iframe (Sandbox).
 */

console.log('Offscreen: Bridge initialized');

const sandboxFrame = document.getElementById('sandboxFrame');

// Listen for messages from the Background (Service Worker)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target === 'offscreen') {
        console.log('Offscreen: Received message for sandbox', message.action);
        
        // Forward to the sandboxed iframe
        // We use postMessage because the sandbox cannot use chrome.runtime
        sandboxFrame.contentWindow.postMessage(message, '*');
    }
});

// Listen for messages from the Sandboxed iframe
window.addEventListener('message', (event) => {
    const message = event.data;
    
    // Validate message is from our sandbox and intended for background
    if (message && message.target === 'background') {
        console.log('Offscreen: Received response from sandbox, forwarding to background', message.action);
        
        // Forward back to the Background (Service Worker)
        chrome.runtime.sendMessage(message).catch((error) => {
            console.warn('Offscreen: Failed to forward sandbox response', error);
        });
    }
});

// Signal that the bridge is ready once the sandbox frame is loaded
sandboxFrame.onload = () => {
    console.log('Offscreen: Sandbox frame loaded, signaling READY');
    chrome.runtime.sendMessage({ target: 'background', action: 'OFFSCREEN_READY' }).catch((error) => {
        console.warn('Offscreen: Failed to send OFFSCREEN_READY signal', error);
    });
};

// Fallback in case onload already fired or doesn't fire as expected
if (sandboxFrame.contentDocument && sandboxFrame.contentDocument.readyState === 'complete') {
    chrome.runtime.sendMessage({ target: 'background', action: 'OFFSCREEN_READY' }).catch((error) => {
        console.warn('Offscreen: Failed to send OFFSCREEN_READY fallback signal', error);
    });
}
