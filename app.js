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

/**
 * Store a record in localStorage and update the ledger table.
 * @param {{name:string,timestamp:string,hash:string}} record
 */
function addRecord(record) {
    const ledger = JSON.parse(localStorage.getItem('ledger') || '[]');
    ledger.push(record);
    localStorage.setItem('ledger', JSON.stringify(ledger));
    appendRow(record);
}

/**
 * Append a row to the ledger table in the DOM.
 * @param {{name:string,timestamp:string,hash:string}} record
 */
function appendRow(record) {
    const tbody = document.querySelector('#ledger-table tbody');
    const tr = document.createElement('tr');
    const timestamp = new Date(record.timestamp);
    tr.innerHTML = `<td>${record.name}</td><td>${timestamp.toLocaleString()}</td><td>${record.hash}</td>`;
    tbody.appendChild(tr);
}

/**
 * Load existing ledger entries from localStorage and render them.
 */
function loadLedger() {
    const ledger = JSON.parse(localStorage.getItem('ledger') || '[]');
    ledger.forEach(rec => appendRow(rec));
}

// Event listener for deposit form
document.addEventListener('DOMContentLoaded', () => {
    // Populate ledger on page load
    loadLedger();
    const form = document.getElementById('deposit-form');
    const fileInput = document.getElementById('data-file');
    form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;
        try {
            const arrayBuffer = await file.arrayBuffer();
            const hash = await hashBuffer(arrayBuffer);
            const record = {
                name: file.name,
                timestamp: new Date().toISOString(),
                hash
            };
            addRecord(record);
            // reset file input
            fileInput.value = '';
        } catch (err) {
            console.error(err);
            alert('An error occurred while processing your file.');
        }
    });
});