// encryption.js - Fixed encryption/decryption with robust error handling

// Debug logging helper
const DEBUG = true;
function debugLog(...args) {
    if (DEBUG) {
        console.log('[Encryption]', ...args);
    }
}

// --- Robust Base64 / ArrayBuffer Helpers ---
function arrayBufferToBase64(input) {
    try {
        let bytes;
        if (input instanceof ArrayBuffer) {
            bytes = new Uint8Array(input);
        } else if (ArrayBuffer.isView(input)) {
            bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        } else {
            throw new Error('Input must be ArrayBuffer or TypedArray');
        }

        let binary = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return window.btoa(binary);
    } catch (error) {
        console.error('arrayBufferToBase64 error:', error);
        throw new Error('Failed to convert ArrayBuffer to Base64: ' + (error.message || error));
    }
}

function base64ToArrayBuffer(base64) {
    try {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('base64ToArrayBuffer error:', error);
        throw new Error('Failed to convert Base64 to ArrayBuffer: ' + (error.message || error));
    }
}

// --- Browser Compatibility Check ---
function checkCryptoSupport() {
    const checks = {
        crypto: !!window.crypto,
        subtle: !!window.crypto?.subtle,
        generateKey: typeof window.crypto?.subtle?.generateKey === 'function',
        importKey: typeof window.crypto?.subtle?.importKey === 'function',
        exportKey: typeof window.crypto?.subtle?.exportKey === 'function',
        encrypt: typeof window.crypto?.subtle?.encrypt === 'function',
        decrypt: typeof window.crypto?.subtle?.decrypt === 'function'
    };

    debugLog('Crypto support check:', checks);
    const allSupported = Object.values(checks).every(v => v === true);

    if (!allSupported) {
        const unsupported = Object.entries(checks)
            .filter(([_, supported]) => !supported)
            .map(([feature, _]) => feature);
        console.error('Missing crypto features:', unsupported);
        return false;
    }
    return true;
}

// --- RSA Key Generation ---
async function generateKeyPair() {
    if (!checkCryptoSupport()) {
        throw new Error('Web Crypto API not supported in this browser');
    }

    debugLog('Generating RSA key pair...');

    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );

        debugLog('Key pair generated successfully');
        return keyPair;

    } catch (error) {
        console.error('Key generation failed:', error);
        throw new Error(`Key generation failed: ${error.message}`);
    }
}

// --- Key Export ---
async function exportKeyToBase64(key, format) {
    debugLog(`Exporting key in ${format} format...`);

    try {
        const exported = await window.crypto.subtle.exportKey(format, key);
        const base64 = arrayBufferToBase64(exported);
        debugLog(`Key exported successfully (${base64.length} chars)`);
        return base64;
    } catch (error) {
        console.error(`Export key failed (${format}):`, error);
        throw new Error(`Failed to export key: ${error.message}`);
    }
}

// --- Private Key Storage/Loading ---
async function loadPrivateKey(username) {
    debugLog(`Loading private key for user: ${username}`);

    const storageKey = `privateKey_${username}`;
    const pkcs8B64 = localStorage.getItem(storageKey);

    if (!pkcs8B64) {
        console.warn(`Private key not found for user: ${username}`);
        return null;
    }

    try {
        const pkcs8 = base64ToArrayBuffer(pkcs8B64);
        debugLog('Private key data loaded from storage (bytes):', new Uint8Array(pkcs8).length);

        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            pkcs8,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );

        debugLog('Private key imported successfully');
        return privateKey;

    } catch (error) {
        console.error('Failed to import private key:', error);
        try { localStorage.removeItem(storageKey); } catch (_) {}
        throw new Error('Private key corrupted or invalid. Please log out and log in again.');
    }
}

function storePrivateKey(username, privateKeyBase64) {
    const storageKey = `privateKey_${username}`;
    try {
        localStorage.setItem(storageKey, privateKeyBase64);
        debugLog(`Private key stored for user: ${username}`);
        return true;
    } catch (error) {
        console.error('Failed to store private key:', error);
        if (error.name === 'QuotaExceededError') {
            throw new Error('Storage quota exceeded. Please clear some browser data.');
        }
        throw new Error('Failed to store encryption key');
    }
}

// --- Public Key Import ---
async function importPublicKey(publicKeyB64) {
    debugLog('Importing public key...');

    if (!publicKeyB64) {
        console.error('Public key is empty');
        return null;
    }

    try {
        const spki = base64ToArrayBuffer(publicKeyB64);

        const publicKey = await window.crypto.subtle.importKey(
            "spki",
            spki,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );

        debugLog('Public key imported successfully');
        return publicKey;

    } catch (error) {
        console.error('Failed to import public key:', error);
        return null;
    }
}

// --- AES Session Key Generation ---
async function generateSessionKey() {
    debugLog('Generating session key...');

    try {
        const sessionKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        debugLog('Session key generated successfully');
        return sessionKey;

    } catch (error) {
        console.error('Failed to generate session key:', error);
        return null;
    }
}

// --- Session Key Encryption (RSA) ---
async function encryptSessionKey(sessionKey, recipientPublicKey) {
    debugLog('Encrypting session key...');
    try {
        const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);
        debugLog(`Session key raw length: ${rawSessionKey.byteLength}`);

        const encryptedSessionKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            recipientPublicKey,
            rawSessionKey
        );

        debugLog(`Encrypted session key length: ${encryptedSessionKey.byteLength}`);

        const result = arrayBufferToBase64(encryptedSessionKey);
        debugLog('Session key encrypted successfully (base64 length):', result.length);
        return result;
    } catch (error) {
        console.error('Failed to encrypt session key:', error);
        throw error;
    }
}

// --- Session Key Decryption (RSA) ---
async function decryptSessionKey(encryptedKeyB64, myPrivateKey) {
    debugLog('Decrypting session key...');

    try {
        const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyB64);
        debugLog(`Encrypted session key buffer length: ${new Uint8Array(encryptedKeyBuffer).byteLength}`);

        const decryptedSessionKeyBytes = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            myPrivateKey,
            encryptedKeyBuffer
        );

        debugLog(`Decrypted session key raw length: ${new Uint8Array(decryptedSessionKeyBytes).byteLength}`);

        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            decryptedSessionKeyBytes,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );

        debugLog('Session key decrypted successfully');
        return sessionKey;
    } catch (error) {
        console.error('Failed to decrypt session key:', error);
        throw error;
    }
}

// --- Message Encryption (AES-GCM) ---
async function encryptChatMessage(plaintext, key) {
    debugLog('Encrypting message...', { messageLength: plaintext.length });

    try {
        // Generate a fresh IV for each message
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedText = new TextEncoder().encode(plaintext);

        debugLog('Encryption params:', {
            ivLength: iv.byteLength,
            plaintextLength: encodedText.byteLength
        });

        const ciphertext = await window.crypto.subtle.encrypt(
            { 
                name: "AES-GCM", 
                iv: iv, 
                tagLength: 128 
            },
            key,
            encodedText
        );

        const result = {
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext)
        };

        debugLog('Message encrypted successfully', {
            ivB64Length: result.iv.length,
            ciphertextB64Length: result.ciphertext.length
        });
        
        return result;

    } catch (error) {
        console.error('AES Encryption failed:', error);
        throw new Error(`Encryption failed: ${error.message}`);
    }
}

// --- Message Decryption (AES-GCM) - FIXED ---
async function decryptChatMessage(ivB64, ciphertextB64, key) {
    debugLog('Decrypting message...', {
        ivB64Length: ivB64?.length,
        ciphertextB64Length: ciphertextB64?.length
    });

    try {
        // Validate inputs
        if (!ivB64 || !ciphertextB64) {
            throw new Error("Missing IV or ciphertext");
        }

        if (typeof ivB64 !== 'string' || typeof ciphertextB64 !== 'string') {
            throw new Error("IV and ciphertext must be base64 strings");
        }

        // Convert from base64
        const ivBuffer = base64ToArrayBuffer(ivB64);
        const ctBuffer = base64ToArrayBuffer(ciphertextB64);

        // Create clean Uint8Array views
        const ivArr = new Uint8Array(ivBuffer);
        const ctArr = new Uint8Array(ctBuffer);

        debugLog('Decryption params:', {
            ivLength: ivArr.byteLength,
            ciphertextLength: ctArr.byteLength
        });

        // Validate IV length
        if (ivArr.byteLength !== 12) {
            throw new Error(`Invalid IV length: ${ivArr.byteLength} (expected 12)`);
        }

        // Validate ciphertext length (must be at least 16 bytes for auth tag)
        if (ctArr.byteLength < 16) {
            throw new Error(`Ciphertext too short: ${ctArr.byteLength} (minimum 16)`);
        }

        // Decrypt using AES-GCM
        const decrypted = await window.crypto.subtle.decrypt(
            { 
                name: "AES-GCM", 
                iv: ivArr,
                tagLength: 128 
            },
            key,
            ctArr
        );

        const plaintext = new TextDecoder().decode(decrypted);
        debugLog('Message decrypted successfully', { 
            plaintextLength: plaintext.length,
            preview: plaintext.substring(0, 50) 
        });
        
        return plaintext;

    } catch (error) {
        console.error('AES Decryption failed:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
        
        // Provide more specific error messages
        if (error.name === 'OperationError') {
            throw new Error('Decryption failed: Invalid key or corrupted message');
        } else if (error.message.includes('Invalid IV')) {
            throw new Error('Decryption failed: Invalid initialization vector');
        } else if (error.message.includes('too short')) {
            throw new Error('Decryption failed: Message data is incomplete');
        }
        
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

// --- Initialization ---
debugLog('Encryption module loaded');
debugLog('Browser:', navigator.userAgent);
debugLog('Protocol:', window.location.protocol);
debugLog('Crypto support:', checkCryptoSupport());

if (window.location.protocol !== 'https:' &&
    window.location.hostname !== 'localhost' &&
    window.location.hostname !== '127.0.0.1') {
    console.warn('⚠️  Encryption requires HTTPS in production!');
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        generateKeyPair,
        exportKeyToBase64,
        loadPrivateKey,
        storePrivateKey,
        importPublicKey,
        encryptChatMessage,
        decryptChatMessage,
        generateSessionKey,
        encryptSessionKey,
        decryptSessionKey,
        checkCryptoSupport
    };
}