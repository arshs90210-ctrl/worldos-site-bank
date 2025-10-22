// app.js
// Enhanced Data Bank implementation for WorldOS
//
// This script introduces client‑side encryption/decryption, multiple vaults with
// per‑user isolation, policy metadata, IndexedDB‑like persistent storage via
// localStorage namespacing, export/import via Zip (using JSZip), optional QR
// receipt display, simple insight generation, and user authentication.

(function() {
    // -------------------------------------------------------------------------
    // Utility functions
    // -------------------------------------------------------------------------
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    /**
     * Compute SHA‑256 hash of a string and return hex encoded.
     * @param {string} str
     * @returns {Promise<string>}
     */
    async function sha256(str) {
        const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Compute SHA‑256 hash of an ArrayBuffer and return hex encoded.
     * @param {ArrayBuffer} buffer
     * @returns {Promise<string>}
     */
    async function hashBuffer(buffer) {
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Convert ArrayBuffer to base64 string.
     * @param {ArrayBuffer} buffer
     * @returns {string}
     */
    function bufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let b of bytes) binary += String.fromCharCode(b);
        return btoa(binary);
    }

    /**
     * Convert base64 string to ArrayBuffer.
     * @param {string} b64
     * @returns {ArrayBuffer}
     */
    function base64ToBuffer(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    /**
     * Derive an AES‑GCM key from a passphrase and salt via PBKDF2.
     * @param {string} passphrase
     * @param {Uint8Array} salt
     * @returns {Promise<CryptoKey>}
     */
    async function deriveAesKey(passphrase, salt) {
        const baseKey = await crypto.subtle.importKey(
            'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate a random Uint8Array of given length.
     * @param {number} length
     */
    function randomBytes(length) {
        const arr = new Uint8Array(length);
        crypto.getRandomValues(arr);
        return arr;
    }

    /**
     * Encrypt an ArrayBuffer with AES‑GCM derived from a passphrase.
     * Returns object with ciphertext (base64), iv (base64) and salt (base64).
     * @param {ArrayBuffer} data
     * @param {string} passphrase
     * @returns {Promise<{ciphertext:string, iv:string, salt:string}>}
     */
    async function encryptData(data, passphrase) {
        const salt = randomBytes(16);
        const key = await deriveAesKey(passphrase, salt);
        const iv = randomBytes(12);
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
        return {
            ciphertext: bufferToBase64(ciphertext),
            iv: bufferToBase64(iv.buffer),
            salt: bufferToBase64(salt.buffer)
        };
    }

    /**
     * Decrypt data encrypted with encryptData.
     * @param {string} ciphertextB64
     * @param {string} ivB64
     * @param {string} saltB64
     * @param {string} passphrase
     * @returns {Promise<ArrayBuffer>}
     */
    async function decryptData(ciphertextB64, ivB64, saltB64, passphrase) {
        const salt = new Uint8Array(base64ToBuffer(saltB64));
        const key = await deriveAesKey(passphrase, salt);
        const iv = new Uint8Array(base64ToBuffer(ivB64));
        const ciphertext = base64ToBuffer(ciphertextB64);
        try {
            const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
            return plaintext;
        } catch (err) {
            throw new Error('Decryption failed (check passphrase)');
        }
    }

    /**
     * Generate ECDSA key pair for signatures and store as JWK.
     * @returns {Promise<{publicJwk:JsonWebKey, privateJwk:JsonWebKey}>}
     */
    async function generateSigningKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        );
        const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        return { publicJwk, privateJwk };
    }

    /**
     * Sign a message (hex digest) with user's private key.
     * @param {string} digestHex
     * @param {JsonWebKey} privateJwk
     * @returns {Promise<string>} signature as base64
     */
    async function signDigest(digestHex, privateJwk) {
        // convert hex string to ArrayBuffer
        const bytes = new Uint8Array(digestHex.match(/.{2}/g).map(b => parseInt(b, 16)));
        const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
        const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, key, bytes);
        return bufferToBase64(signature);
    }

    /**
     * Verify signature on message digest.
     * @param {string} digestHex
     * @param {string} signatureB64
     * @param {JsonWebKey} publicJwk
     * @returns {Promise<boolean>}
     */
    async function verifySignature(digestHex, signatureB64, publicJwk) {
        const bytes = new Uint8Array(digestHex.match(/.{2}/g).map(b => parseInt(b, 16)));
        const signature = base64ToBuffer(signatureB64);
        const key = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        return crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, key, signature, bytes);
    }

    // -------------------------------------------------------------------------
    // User and vault management
    // -------------------------------------------------------------------------
    let currentUser = null;
    let currentUserKeys = null;

    function loadUsers() {
        return JSON.parse(localStorage.getItem('users') || '{}');
    }
    function saveUsers(users) {
        localStorage.setItem('users', JSON.stringify(users));
    }

    function loadLedger(username) {
        return JSON.parse(localStorage.getItem(`ledger_${username}`) || '[]');
    }
    function saveLedger(username, ledger) {
        localStorage.setItem(`ledger_${username}`, JSON.stringify(ledger));
    }

    /**
     * Register a new user and generate a signing key pair.
     * @param {string} username
     * @param {string} password
     */
    async function registerUser(username, password) {
        const users = loadUsers();
        if (users[username]) {
            throw new Error('User already exists');
        }
        const passwordHash = await sha256(password);
        const { publicJwk, privateJwk } = await generateSigningKeyPair();
        users[username] = { passwordHash, publicJwk, privateJwk };
        saveUsers(users);
        // Initialize empty ledger
        saveLedger(username, []);
    }

    /**
     * Login user; verify password; set globals
     * @param {string} username
     * @param {string} password
     */
    async function loginUser(username, password) {
        const users = loadUsers();
        const user = users[username];
        if (!user) throw new Error('User not found');
        const passwordHash = await sha256(password);
        if (passwordHash !== user.passwordHash) throw new Error('Incorrect password');
        currentUser = username;
        currentUserKeys = { publicJwk: user.publicJwk, privateJwk: user.privateJwk };
        return true;
    }

    // -------------------------------------------------------------------------
    // UI manipulation helpers
    // -------------------------------------------------------------------------
    function showElement(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
    }
    function hideElement(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }

    /**
     * Display a temporary toast notification to the user.
     * @param {string} message
     */
    function showToast(message) {
        let toast = document.querySelector('.toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.className = 'toast';
            document.body.appendChild(toast);
        }
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }

    /**
     * Clear and reload ledger table from storage for current user.
     */
    function renderLedger(filter = '') {
        const tableBody = document.querySelector('#ledger-table tbody');
        tableBody.innerHTML = '';
        if (!currentUser) return;
        const ledger = loadLedger(currentUser);
        ledger.forEach((record, idx) => {
            if (filter && !record.name.toLowerCase().includes(filter.toLowerCase())) return;
            appendRow(record, idx);
        });
    }

    /**
     * Append a single ledger record row to the table.
     * @param {Object} record
     * @param {number} index
     */
    function appendRow(record, index) {
        const tbody = document.querySelector('#ledger-table tbody');
        const tr = document.createElement('tr');
        // Name
        const tdName = document.createElement('td');
        tdName.textContent = record.name;
        // Timestamp
        const tdTime = document.createElement('td');
        tdTime.textContent = new Date(record.timestamp).toLocaleString();
        // PoD hash
        const tdHash = document.createElement('td');
        tdHash.textContent = record.hash;
        // QR cell
        const tdQr = document.createElement('td');
        const qrDiv = document.createElement('div');
        qrDiv.className = 'qr';
        tdQr.appendChild(qrDiv);
        // Insight cell
        const tdInsight = document.createElement('td');
        const insightBtn = document.createElement('button');
        insightBtn.textContent = 'Generate';
        insightBtn.className = 'insight-btn';
        insightBtn.addEventListener('click', () => {
            promptInsight(record);
        });
        tdInsight.appendChild(insightBtn);
        // Policy cell
        const tdPolicy = document.createElement('td');
        tdPolicy.textContent = policySummary(record.policy);

        tr.appendChild(tdName);
        tr.appendChild(tdTime);
        tr.appendChild(tdHash);
        tr.appendChild(tdQr);
        tr.appendChild(tdInsight);
        tr.appendChild(tdPolicy);
        tbody.appendChild(tr);
        // Render QR code
        loadQrLibrary().then(() => {
            if (window.QRCode) {
                new QRCode(qrDiv, {
                    text: record.hash,
                    width: 60,
                    height: 60,
                    colorDark: '#ffffff',
                    colorLight: '#0d0d11',
                    correctLevel: QRCode.CorrectLevel.M
                });
            } else {
                qrDiv.textContent = 'N/A';
            }
        });
    }

    /**
     * Summarize policy object into readable string.
     * @param {Object} policy
     */
    function policySummary(policy) {
        if (!policy) return '';
        const parts = [];
        if (policy.start || policy.end) parts.push(`${policy.start || '?'} to ${policy.end || '?'}`);
        if (policy.usage) parts.push(`Uses: ${policy.usage}`);
        if (policy.anon) parts.push(`Anon: ${policy.anon}`);
        if (policy.comp) parts.push(`Comp: ${policy.comp}`);
        return parts.join('; ');
    }

    /**
     * Load QRCode library
     */
    function loadQrLibrary() {
        return new Promise((resolve) => {
            if (window.QRCode) { resolve(); return; }
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
            script.onload = () => resolve();
            script.onerror = () => resolve();
            document.head.appendChild(script);
        });
    }

    /**
     * Dynamically load JSZip library for export/import.
     */
    function loadZipLibrary() {
        return new Promise((resolve) => {
            if (window.JSZip) { resolve(); return; }
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.7.1/jszip.min.js';
            script.onload = () => resolve();
            script.onerror = () => resolve();
            document.head.appendChild(script);
        });
    }

    /**
     * Prompt user for passphrase and decrypt file to generate insight.
     * @param {Object} record
     */
    async function promptInsight(record) {
        if (!record.ciphertext) {
            alert('No encrypted data stored for this record.');
            return;
        }
        const passphrase = prompt('Enter encryption passphrase to decrypt and generate insight:');
        if (!passphrase) return;
        try {
            const plainBuf = await decryptData(record.ciphertext, record.iv, record.salt, passphrase);
            // If file type is text, decode and compute words
            if (record.type && record.type.startsWith('text')) {
                const text = dec.decode(plainBuf);
                const words = text.trim().split(/\s+/);
                const uniqueWords = new Set(words.map(w => w.toLowerCase()));
                alert(`Insight for ${record.name}:\nCharacters: ${text.length}\nWords: ${words.length}\nUnique words: ${uniqueWords.size}`);
            } else {
                alert('Insight generation supported only for plain text files.');
            }
        } catch (err) {
            alert(err.message);
        }
    }

    /**
     * Export vault for current user as ZIP. Includes ledger JSON.
     */
    async function exportVault() {
        if (!currentUser) return;
        await loadZipLibrary();
        const zip = new JSZip();
        const ledger = loadLedger(currentUser);
        // JSON file for metadata
        zip.file('ledger.json', JSON.stringify(ledger, null, 2));
        // Add encrypted files as separate entries
        ledger.forEach((rec, idx) => {
            if (rec.ciphertext) {
                zip.file(rec.name + '.enc', rec.ciphertext);
            }
        });
        const blob = await zip.generateAsync({ type: 'blob' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `worldos_vault_${currentUser}_${Date.now()}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Import vault from a ZIP or JSON file.
     * @param {File} file
     */
    async function importVault(file) {
        await loadZipLibrary();
        const users = loadUsers();
        if (!currentUser) { alert('Login required'); return; }
        if (file.name.endsWith('.json')) {
            // simple JSON import
            const text = await file.text();
            const data = JSON.parse(text);
            if (!Array.isArray(data)) {
                alert('Invalid JSON format'); return;
            }
            const existing = loadLedger(currentUser);
            const combined = existing.concat(data);
            saveLedger(currentUser, combined);
            renderLedger();
            showToast('Imported JSON vault');
        } else if (file.name.endsWith('.zip')) {
            const zip = await JSZip.loadAsync(file);
            const ledgerFile = zip.file('ledger.json');
            if (!ledgerFile) { alert('Invalid vault: missing ledger.json'); return; }
            const ledgerJson = await ledgerFile.async('string');
            const importedLedger = JSON.parse(ledgerJson);
            const existing = loadLedger(currentUser);
            const combined = existing.concat(importedLedger);
            saveLedger(currentUser, combined);
            renderLedger();
            showToast('Vault imported successfully ✅');
        } else {
            alert('Unsupported file type');
        }
    }

    // -------------------------------------------------------------------------
    // Event binding
    // -------------------------------------------------------------------------
    document.addEventListener('DOMContentLoaded', () => {
        // Elements
        const loginBtn = document.getElementById('login-btn');
        const registerBtn = document.getElementById('register-btn');
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        const authStatus = document.getElementById('auth-status');
        const depositForm = document.getElementById('deposit-form');
        const fileInput = document.getElementById('data-file');
        const passphraseInput = document.getElementById('passphrase');
        const exportBtn = document.getElementById('export-btn');
        const importInput = document.getElementById('import-file');
        const searchInput = document.getElementById('search-ledger');

        // Login event
        loginBtn.addEventListener('click', async () => {
            const user = usernameInput.value.trim();
            const pass = passwordInput.value;
            if (!user || !pass) {
                authStatus.textContent = 'Please enter username and password.';
                return;
            }
            try {
                await loginUser(user, pass);
                authStatus.textContent = `Logged in as ${user}`;
                usernameInput.value = '';
                passwordInput.value = '';
                // reveal vault interface
                showElement('vault-interface');
                showElement('ledger-interface');
                renderLedger();
            } catch (err) {
                authStatus.textContent = err.message;
            }
        });

        // Register event
        registerBtn.addEventListener('click', async () => {
            const user = usernameInput.value.trim();
            const pass = passwordInput.value;
            if (!user || !pass) {
                authStatus.textContent = 'Please enter username and password.';
                return;
            }
            try {
                await registerUser(user, pass);
                authStatus.textContent = 'Registration successful! Please log in.';
                usernameInput.value = '';
                passwordInput.value = '';
            } catch (err) {
                authStatus.textContent = err.message;
            }
        });

        // Deposit form submission
        depositForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!currentUser) {
                alert('Please log in first.');
                return;
            }
            const file = fileInput.files[0];
            const passphrase = passphraseInput.value;
            if (!file || !passphrase) {
                alert('Please select a file and enter a passphrase.');
                return;
            }
            // Collect policy values
            const policy = {
                start: document.getElementById('policy-start').value,
                end: document.getElementById('policy-end').value,
                usage: document.getElementById('policy-usage').value,
                anon: document.getElementById('policy-anon').value,
                comp: document.getElementById('policy-comp').value
            };
            try {
                const arrayBuffer = await file.arrayBuffer();
                const hashHex = await hashBuffer(arrayBuffer);
                // sign digest
                let signatureB64 = '';
                if (currentUserKeys && currentUserKeys.privateJwk) {
                    signatureB64 = await signDigest(hashHex, currentUserKeys.privateJwk);
                }
                // encrypt data
                const encResult = await encryptData(arrayBuffer, passphrase);
                const record = {
                    name: file.name,
                    timestamp: new Date().toISOString(),
                    hash: hashHex,
                    ciphertext: encResult.ciphertext,
                    iv: encResult.iv,
                    salt: encResult.salt,
                    type: file.type,
                    signature: signatureB64,
                    policy: policy
                };
                const ledger = loadLedger(currentUser);
                ledger.push(record);
                saveLedger(currentUser, ledger);
                renderLedger(searchInput.value);
                showToast('File deposited. Proof recorded ✅');
                // reset fields
                fileInput.value = '';
                passphraseInput.value = '';
            } catch (err) {
                alert('Error processing file: ' + err.message);
            }
        });

        // Export vault
        exportBtn.addEventListener('click', exportVault);
        // Import vault
        importInput.addEventListener('change', (ev) => {
            const file = ev.target.files[0];
            if (file) importVault(file);
            ev.target.value = '';
        });
        // Search ledger filter
        searchInput.addEventListener('input', (ev) => {
            renderLedger(ev.target.value);
        });
    });
})();