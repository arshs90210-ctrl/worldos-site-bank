// app.js
// Client‑side script to implement the Data Bank demo functionality.
//
// This script runs entirely in the browser. It enables users to deposit
// files into their personal vault (stored via localStorage), generates
// a SHA‑256 Proof of Deposit (PoD) hash using the Web Crypto API, and
// renders a ledger of all deposits. No data leaves the user’s device.

/**
 * Compute a SHA‑256 hash of an ArrayBuffer and return a hex string.
 * @param {ArrayBuffer} buffer
 * @returns {Promise<string>}
 */
async function hashBuffer(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = new Uint8Array(hashBuffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Dynamically load the QRCode library from a CDN. If offline, QR generation will simply not occur.
function loadQrLibrary() {
    return new Promise((resolve) => {
        if (window.QRCode) {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
        script.onload = () => resolve();
        script.onerror = () => resolve();
        document.head.appendChild(script);
    });
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
 * Store a record in localStorage and update the ledger table.
 * @param {{name:string,timestamp:string,hash:string,data:string,type:string}} record
 */
function addRecord(record) {
    const ledger = JSON.parse(localStorage.getItem('ledger') || '[]');
    ledger.push(record);
    localStorage.setItem('ledger', JSON.stringify(ledger));
    appendRow(record, ledger.length - 1);
}

/**
 * Append a row to the ledger table in the DOM.
 * @param {{name:string,timestamp:string,hash:string,data?:string,type?:string}} record
 * @param {number} index
 */
function appendRow(record, index) {
    const tbody = document.querySelector('#ledger-table tbody');
    const tr = document.createElement('tr');
    const timestamp = new Date(record.timestamp);
    // File name cell
    const tdName = document.createElement('td');
    tdName.textContent = record.name;
    // Timestamp cell
    const tdTime = document.createElement('td');
    tdTime.textContent = timestamp.toLocaleString();
    // Hash cell
    const tdHash = document.createElement('td');
    tdHash.textContent = record.hash;
    // QR cell
    const tdQr = document.createElement('td');
    const qrDiv = document.createElement('div');
    qrDiv.className = 'qr';
    tdQr.appendChild(qrDiv);
    // Insight cell
    const tdInsight = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'Generate';
    btn.className = 'insight-btn';
    btn.addEventListener('click', () => generateInsight(record));
    tdInsight.appendChild(btn);
    tr.appendChild(tdName);
    tr.appendChild(tdTime);
    tr.appendChild(tdHash);
    tr.appendChild(tdQr);
    tr.appendChild(tdInsight);
    tbody.appendChild(tr);
    // Attempt to render QR code after library loads
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
 * Load existing ledger entries from localStorage and render them.
 */
function loadLedger() {
    const ledger = JSON.parse(localStorage.getItem('ledger') || '[]');
    ledger.forEach((rec, idx) => appendRow(rec, idx));
}

/**
 * Generate a simple insight for a record. For text files, count words and characters.
 * @param {{name:string,data?:string,type?:string}} record
 */
function generateInsight(record) {
    if (!record.data) {
        alert('No file content stored for this record.');
        return;
    }
    // Attempt to decode base64 to string if text
    if (record.type && record.type.startsWith('text')) {
        try {
            const binaryString = atob(record.data.split(',')[1]);
            const text = decodeURIComponent(binaryString.split('').map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
            const words = text.trim().split(/\s+/);
            const uniqueWords = new Set(words.map(w => w.toLowerCase()));
            alert(`Insight for ${record.name}:\nCharacters: ${text.length}\nWords: ${words.length}\nUnique words: ${uniqueWords.size}`);
        } catch (e) {
            alert('Unable to generate insight for this file type.');
        }
    } else {
        alert('Insight generation is supported only for text files.');
    }
}

/**
 * Export the entire ledger as a JSON bundle and trigger download.
 */
function exportVault() {
    const ledger = JSON.parse(localStorage.getItem('ledger') || '[]');
    const dataStr = JSON.stringify({ ledger });
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `worldos_vault_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Import a vault JSON file and merge with existing ledger.
 * @param {File} file
 */
async function importVault(file) {
    try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (!parsed.ledger || !Array.isArray(parsed.ledger)) throw new Error('Invalid vault format');
        const existing = JSON.parse(localStorage.getItem('ledger') || '[]');
        const combined = existing.concat(parsed.ledger);
        localStorage.setItem('ledger', JSON.stringify(combined));
        // Clear current table and reload
        const tbody = document.querySelector('#ledger-table tbody');
        tbody.innerHTML = '';
        loadLedger();
        showToast('Vault imported successfully ✅');
    } catch (err) {
        alert('Failed to import vault: ' + err.message);
    }
}

// Event listener for deposit form and additional controls
document.addEventListener('DOMContentLoaded', () => {
    // Populate ledger on page load
    loadLedger();
    const form = document.getElementById('deposit-form');
    const fileInput = document.getElementById('data-file');
    const exportBtn = document.getElementById('export-btn');
    const importFile = document.getElementById('import-file');
    form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;
        try {
            const arrayBuffer = await file.arrayBuffer();
            const hash = await hashBuffer(arrayBuffer);
            // Read as data URL for export/import and insight
            const reader = new FileReader();
            reader.onload = function(evt) {
                const record = {
                    name: file.name,
                    timestamp: new Date().toISOString(),
                    hash: hash,
                    data: evt.target.result,
                    type: file.type
                };
                addRecord(record);
                showToast('File deposited. Proof recorded ✅');
            };
            reader.readAsDataURL(file);
            // reset file input
            fileInput.value = '';
        } catch (err) {
            console.error(err);
            alert('An error occurred while processing your file.');
        }
    });
    exportBtn.addEventListener('click', exportVault);
    importFile.addEventListener('change', (e) => {
        const f = e.target.files[0];
        if (f) importVault(f);
        // reset input
        e.target.value = '';
    });
});