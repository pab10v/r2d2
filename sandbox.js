/**
 * R2D2 Argon2 Sandbox
 * This script runs in a sandboxed iframe or offscreen document to allow WebAssembly execution.
 */

/**
 * Turn extension-messaging payloads into a real Uint8Array. TypedArrays often arrive as
 * plain objects with numeric keys, which are not iterable — that breaks argon2-browser's
 * `new Uint8Array([...bytes, 0])` and yields "is not iterable".
 */
function bytesFromMessagePayload(value, label) {
    if (value === null || value === undefined) {
        throw new Error(`${label} is missing`);
    }
    if (value instanceof Uint8Array) {
        return value;
    }
    if (Array.isArray(value)) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (typeof value === 'string') {
        return new TextEncoder().encode(value);
    }
    if (typeof value === 'object') {
        const keys = Object.keys(value)
            .filter((k) => /^\d+$/.test(k))
            .map(Number)
            .sort((a, b) => a - b);
        if (keys.length > 0) {
            return new Uint8Array(keys.map((k) => value[k]));
        }
    }
    throw new Error(`Invalid ${label}: expected bytes or string`);
}

const handleDeriveKey = async (payload, id, source) => {
    try {
        const { password, salt } = payload;
        console.log('Sandbox: Starting deriveKey via direct call', { id });

        const argon2 = window.Argon2Lib || window.argon2;
        if (!argon2) {
            throw new Error('Argon2 library not loaded yet');
        }

        const passBytes =
            typeof password === 'string'
                ? new TextEncoder().encode(password)
                : bytesFromMessagePayload(password, 'password');
        const saltBytes = bytesFromMessagePayload(salt, 'salt');

        const hash = await argon2.hash({
            pass: passBytes,
            salt: saltBytes,
            time: 2,
            mem: 19456,
            hashLen: 32,
            parallelism: 1,
            type: argon2.ArgonType.Argon2id
        });

        console.log('Sandbox: deriveKey success', { id });

        const response = {
            action: 'derive_key_success',
            payload: { 
                hash: Array.from(hash.hash), // Convert Uint8Array to Array for JSON
                encoded: hash.encoded 
            },
            id: id,
            target: 'background'
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        }
    } catch (error) {
        console.error('Sandbox: deriveKey error', error);
        const response = {
            action: 'derive_key_error',
            payload: { error: error.message },
            id: id,
            target: 'background'
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        }
    }
};

const handleDetectQR = async (payload, id, source) => {
    try {
        const { dataUrl } = payload;
        
        // Create an image to get dimensions
        const img = new Image();
        await new Promise((resolve, reject) => {
            img.onload = resolve;
            img.onerror = reject;
            img.src = dataUrl;
        });

        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = window.jsQR(imageData.data, imageData.width, imageData.height);

        const response = {
            action: 'detect_qr_success',
            payload: { code: code ? code.data : null },
            id: id,
            target: 'background'
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        }
    } catch (error) {
        const response = {
            action: 'detect_qr_error',
            payload: { error: error.message },
            id: id,
            target: 'background'
        };

        if (source === 'window') {
            window.parent.postMessage(response, '*');
        }
    }
};

// Handle window messages (iframe in popup)
window.addEventListener('message', async (event) => {
    if (event.data && event.data.action === 'derive_key') {
        await handleDeriveKey(event.data.payload, event.data.id, 'window');
    } else if (event.data && event.data.action === 'detect_qr') {
        await handleDetectQR(event.data.payload, event.data.id, 'window');
    }
});
