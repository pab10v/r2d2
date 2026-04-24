/**
 * R2D2 Argon2 Sandbox
 * This script runs in a sandboxed iframe or offscreen document to allow WebAssembly execution.
 */

const handleDeriveKey = async (payload, id, source) => {
    try {
        const { password, salt } = payload;
        
        // Configuration for Argon2id (Standard for high security)
        // time: 2 iterations
        // memory: 19456 KB (19 MB)
        // parallelism: 1
        const hash = await window.argon2.hash({
            pass: password,
            salt: salt,
            time: 2,
            mem: 19456,
            hashLen: 32,
            parallelism: 1,
            type: window.argon2.ArgonType.Argon2id
        });

        const response = {
            action: 'derive_key_success',
            payload: { hash: hash.hash, encoded: hash.encoded },
            id: id,
            target: 'offscreen' // used for chrome.runtime filter
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        } else {
            chrome.runtime.sendMessage(response);
        }
    } catch (error) {
        const response = {
            action: 'derive_key_error',
            payload: { error: error.message },
            id: id,
            target: 'offscreen'
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        } else {
            chrome.runtime.sendMessage(response);
        }
    }
};

// Handle window messages (iframe in popup)
window.addEventListener('message', async (event) => {
    if (event.data && event.data.action === 'derive_key') {
        await handleDeriveKey(event.data.payload, event.data.id, 'window');
    }
});

// Handle chrome runtime messages (offscreen document)
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message) => {
        if (message.target === 'offscreen' && message.action === 'derive_key') {
            handleDeriveKey(message.payload, message.id, 'runtime');
            return true; // async
        }
    });
}
