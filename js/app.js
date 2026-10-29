// --- KONSTANTY ---
const APP_VERSION = '2.4';
const APP_ID = `PKI-Lab-v${APP_VERSION}`;
const DB_SCHEMA_VERSION = '3';

function updateAppVersionBadge() {
  const badge = document.getElementById('app-version-badge');
  if (badge) badge.textContent = `v${APP_VERSION}`;
  const mobileBadge = document.getElementById('mobile-version-badge');
  if (mobileBadge) mobileBadge.textContent = `v${APP_VERSION}`;
}
updateAppVersionBadge();

// ---- INITIALIZATION & STATE ----
let store = [];
let idCounter = 1;

function reconstructItem(item) {
  let certObj = null;
  let keyObj = null;
  
  try { 
    certObj = forge.pki.certificateFromPem(item.certPem); 
  } catch (e) { 
    console.warn('Fallback: Záchranné parsování certifikátu (nepodporovaný algoritmus ECC/Ed25519)', e);
    // Pokud node-forge selže, vytvoříme manuálně strukturovaný mock objekt
    try {
      const msg = forge.pem.decode(item.certPem)[0];
      const asn = forge.asn1.fromDer(msg.body);
      certObj = forge.pki.createCertificate();
      
      const tbs = asn.value[0]; // TBSCertificate sekce
      let snIdx = 0; 
      // X509v3 certifikáty obsahují volitelnou verzi posouvající indexy (tagClass CONTEXT_SPECIFIC)
      if (tbs.value[0] && tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) {
        snIdx = 1;
      }
      
      // Manuální vytažení nezbytných X.509 dat pro správné fungování UI a vydávání
      certObj.serialNumber = forge.util.bytesToHex(tbs.value[snIdx].value);
      // Obaleno do pole { attributes: ... } aby prošlo volání .subject.attributes
      certObj.issuer = { attributes: forge.pki.RDNAttributesAsArray(tbs.value[snIdx + 2]) };
      certObj.subject = { attributes: forge.pki.RDNAttributesAsArray(tbs.value[snIdx + 4]) };
      certObj.publicKey = { rawAsn1: tbs.value[snIdx + 5], isDummy: true };
    } catch (fallbackErr) {
      console.error('Fatální chyba při manuálním parsování PEM:', fallbackErr);
    }
  }

  if (item.keyPem) {
    try {
      if (item.algo === 'ED25519' && item.edSeedHex) {
        const seed = forge.util.hexToBytes(item.edSeedHex);
        keyObj = forge.pki.ed25519.generateKeyPair({ seed }).privateKey;
      } else {
        keyObj = forge.pki.privateKeyFromPem(item.keyPem);
      }
    } catch (e) {
      keyObj = { isDummy: true };
    }
  }
  // Záchrana serialHex pro ECC certifikáty: forge může vracet certObj.serialNumber
  // jako prázdný řetězec nebo undefined kvůli odlišnému SPKI parsování
  let serialHex = item.serialHex || null;
  if (!serialHex && item.certPem) {
    // Pokud nemáme serialHex z metadat, extrahujeme přímo z DER
    // (funkce extractSerialFromPem je definována níže v kódu)
    // Toto se zavolá v inicializaci po načtení ze store; funkce je dostupná
    try {
      const msg = forge.pem.decode(item.certPem)[0];
      const asn = forge.asn1.fromDer(msg.body);
      const tbs = asn.value[0];
      if (tbs && tbs.value) {
        let snIdx = 0;
        if (tbs.value[0] && tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) snIdx = 1;
        const snAsn = tbs.value[snIdx];
        if (snAsn && snAsn.type === forge.asn1.Type.INTEGER) {
          let hex = '';
          for (let i = 0; i < snAsn.value.length; i++) {
            hex += snAsn.value.charCodeAt(i).toString(16).padStart(2, '0');
          }
          if (hex) serialHex = hex;
        }
      }
    } catch (e) { /* ignorujeme chyby parsování */ }
  }
  return {
    ...item,
    serialHex: serialHex || item.serialHex || null,
    revoked: !!item.revoked,
    revocationDate: item.revocationDate || null,
    certObj,
    keyObj
  };
}

function serializeStore() {
  return store.map(item => ({
    id: item.id, type: item.type, name: item.name, issuerId: item.issuerId,
    crossTargetId: item.crossTargetId || null, algo: item.algo || 'RSA',
    edSeedHex: item.edSeedHex || null, serialHex: item.serialHex || null,
    revoked: !!item.revoked,
    revocationDate: item.revocationDate || null, certPem: item.certPem,
    keyPem: item.keyPem || null
  }));
}

function saveItem(item) {
  store.push(item);
  syncStore();
  updateCaSelects();
  if (typeof updateKeyringStats === 'function') updateKeyringStats();
}

function initStorage() {
  updateAppVersionBadge();
  initLanguage();
  const saved = localStorage.getItem('pki_store_v' + DB_SCHEMA_VERSION);
  const toggle = document.getElementById('toggle-ls');
  const alertBox = document.getElementById('ls-alert');

  if (saved) {
    try {
      const data = JSON.parse(saved); 
      idCounter = data.idCounter || 1;
      store = data.store.map(reconstructItem);
      toggle.checked = true;
      alertBox.style.display = 'flex';
    } catch (e) {
      console.error("Chyba načtení LocalStorage", e);
    }
  }
  updateCaSelects();
  renderKeyring();
}

function toggleStorage() {
  const checked = document.getElementById('toggle-ls').checked;
  document.getElementById('ls-alert').style.display = checked ? 'flex' : 'none';
  syncStore();
  showToast(checked ? t('toast_ls_on') : t('toast_ls_off'), 'info');
}

function syncStore() {
  if (document.getElementById('toggle-ls').checked) {
    localStorage.setItem('pki_store_v' + DB_SCHEMA_VERSION, JSON.stringify({ idCounter, store: serializeStore() }));
  } else {
    localStorage.removeItem('pki_store_v' + DB_SCHEMA_VERSION);
  }
}

function clearStore() {
  if (confirm(t('confirm_clear_store'))) {
    store = [];
    idCounter = 1;
    syncStore();
    updateCaSelects();
    renderKeyring();
    showToast(t('toast_store_cleared'), 'info');
  }
}

async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const keyMat = await window.crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function exportEncryptedWorkspace() {
  if (store.length === 0) return showToast(t('toast_export_empty'), 'error');
  const password = prompt(t('prompt_export_pass'));
  if (!password) return;

  try {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveAesKey(password, salt);

    const payload = JSON.stringify({ idCounter, store: serializeStore(), exportedAt: new Date().toISOString() });
    const encryptedBuf = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload)
    );

    // Bezpečná konverze Uint8Array na hex bez rizika přetečení zásobníku
    // (String.fromCharCode(...largeArray) může selhat při velkých payload)
    const uint8ToHex = (arr) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    const backupObj = {
      app: APP_ID,
      cipher: 'AES-256-GCM-PBKDF2',
      salt: uint8ToHex(salt),
      iv: uint8ToHex(iv), 
      data: uint8ToHex(new Uint8Array(encryptedBuf))
    };

    downloadFile(`pki_workspace_backup_${new Date().toISOString().slice(0,10)}.json`, JSON.stringify(backupObj, null, 2));
    showToast(t('toast_export_success'), 'success');
  } catch (err) {
    showToast(t('toast_export_error', { err: err.message }), 'error');
  }
}

function hexToUint8(hex) {
  const bytes = forge.util.hexToBytes(hex);
  const arr = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
  return arr;
}

async function importEncryptedWorkspace(event) {
  const fileInput = event.target;
  const file = fileInput.files && fileInput.files[0];
  if (!file) return;

  try {
    const fileContent = await (file.text ? file.text() : new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('File read error'));
      reader.readAsText(file);
    }));

    let parsed;
    try {
      parsed = JSON.parse(fileContent);
    } catch (e) {
      showToast(t('toast_restore_invalid_json'), 'error');
      fileInput.value = '';
      return;
    }

    // 1. Ověření existence povinných polí (salt, iv, data)
    if (!parsed || typeof parsed !== 'object' || !parsed.salt || !parsed.iv || !parsed.data) {
      showToast(t('toast_restore_invalid_format'), 'error');
      fileInput.value = '';
      return;
    }

    // 2. Kontrola pole app a verze
    if (parsed.app !== APP_ID) {
      const appName = parsed.app || t('app_version_unknown');
      const warnMsg = t('confirm_app_version_mismatch', { app: appName, expected: APP_ID });
      const proceed = confirm(warnMsg);
      if (!proceed) {
        fileInput.value = '';
        return;
      }
    }

    // 3. Zadání hesla
    const password = prompt(t('prompt_import_pass', { name: file.name }));
    if (!password) {
      fileInput.value = '';
      return;
    }

    // 4. Dešifrování (PBKDF2 + AES-GCM)
    const salt = hexToUint8(parsed.salt);
    const iv = hexToUint8(parsed.iv);
    const cipherBytes = hexToUint8(parsed.data);

    const aesKey = await deriveAesKey(password, salt);
    const plainBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherBytes);
    const decoded = JSON.parse(new TextDecoder().decode(plainBuf));

    idCounter = decoded.idCounter || 1;
    store = decoded.store.map(reconstructItem);
    syncStore();
    updateCaSelects();
    renderKeyring();
    showToast(t('toast_restore_success', { count: store.length }), 'success');
  } catch (err) {
    showToast(t('toast_restore_error'), 'error');
  } finally {
    fileInput.value = '';
  }
}

window.onload = initStorage;

