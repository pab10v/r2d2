
// Mock window.crypto for Node.js if needed or just use a small test function
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(base32) {
    const cleanBase32 = base32.toUpperCase().replace(/=/g, '');
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

function intToBytes(num) {
    const bytes = new Uint8Array(8);
    // Handle large numbers by splitting into two 32-bit parts
    const high = Math.floor(num / 0x100000000);
    const low = num % 0x100000000;
    
    bytes[0] = (high >> 24) & 0xff;
    bytes[1] = (high >> 16) & 0xff;
    bytes[2] = (high >> 8) & 0xff;
    bytes[3] = high & 0xff;
    bytes[4] = (low >> 24) & 0xff;
    bytes[5] = (low >> 16) & 0xff;
    bytes[6] = (low >> 8) & 0xff;
    bytes[7] = low & 0xff;
    return bytes;
}

// Check current implementation of intToBytes in totp.js
function intToBytesOld(num) {
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
        bytes[i] = num & 0xff;
        num >>= 8;
    }
    return bytes;
}

const testVal = 1234567890123; // Large timestamp
console.log('Old:', Array.from(intToBytesOld(testVal)));
console.log('New:', Array.from(intToBytes(testVal)));
