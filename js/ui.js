let currentModalRawPem = '';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'loose',
  flowchart: { curve: 'basis' }
});

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const icon = type === 'success' ? '✓' : (type === 'error' ? '⚠️' : 'ℹ️');
  toast.innerHTML = `<span>${icon}</span><div>${message}</div>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = '0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function highlightPem(pemText) {
  const safe = escapeHtml(pemText.trim());
  return safe
    .replace(/(-----BEGIN [^-]+-----)/g, '<span class="pem-header">$1</span>')
    .replace(/(-----END [^-]+-----)/g, '<span class="pem-footer">$1</span>');
}

function viewPemModal(id, mode) {
  const item = store.find(i => i.id === id);
  if (!item) return;
  let raw = '';
  let title = '';
  if (mode === 'cert') {
    raw = item.certPem;
    title = t('modal_title_cert', { name: item.name });
  } else if (mode === 'key') {
    if (!item.keyPem) return showToast(t('toast_no_privkey'), 'error');
    raw = item.keyPem;
    title = t('modal_title_key', { name: item.name });
  }
  currentModalRawPem = raw;
  document.getElementById('pem-modal-title').innerText = title;
  document.getElementById('pem-modal-viewer').innerHTML = highlightPem(raw);
  document.getElementById('pem-modal').classList.add('open');
}

function closePemModal() { document.getElementById('pem-modal').classList.remove('open'); }

function copyModalPem() {
  navigator.clipboard.writeText(currentModalRawPem).then(() => {
    showToast(t('toast_pem_copied'), 'success');
  });
}

function copyTextById(elementId, msg) {
  const val = document.getElementById(elementId).value;
  if (!val) return;
  navigator.clipboard.writeText(val).then(() => {
    showToast(msg || t('toast_copied'), 'success');
  });
}

function handleDragOver(e, zone) { e.preventDefault(); zone.classList.add('dragover'); }
function handleDragLeave(zone) { zone.classList.remove('dragover'); }
function handleDrop(e, zone, targetTextareaId, callback) {
  e.preventDefault();
  zone.classList.remove('dragover');
  if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    readFileToTextarea(e.dataTransfer.files[0], targetTextareaId, callback);
  }
}
function handleFileSelect(e, targetTextareaId, callback) {
  if (e.target.files && e.target.files.length > 0) {
    readFileToTextarea(e.target.files[0], targetTextareaId, callback);
  }
}
function readFileToTextarea(file, targetTextareaId, callback) {
  const reader = new FileReader();
  reader.onload = (ev) => {
    document.getElementById(targetTextareaId).value = ev.target.result;
    showToast(t('toast_file_loaded', { name: file.name }), 'success');
    if (typeof callback === 'function') callback();
  };
  reader.readAsText(file);
}

function nav(panelId, btnEl) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  if (!btnEl) {
    btnEl = document.querySelector(`.nav-btn[onclick*="nav('${panelId}'"]`);
  }
  if (btnEl) {
    btnEl.classList.add('active');
    btnEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  }
  document.getElementById('panel-' + panelId).classList.add('active');
  if (panelId === 'keyring') renderKeyring();
  if (panelId === 'graph') renderGraph();
}

function updateCaSelects() {
  const cas = store.filter(item => (item.type === 'root' || item.type === 'inter' || item.type === 'cross') && !item.revoked && item.keyPem);
  const selects = document.querySelectorAll('.ca-select');
  selects.forEach(select => {
    const currentVal = select.value;
    select.innerHTML = cas.length ? '' : `<option value="">${t('ca_select_empty')}</option>`;
    cas.forEach(ca => {
      const opt = document.createElement('option');
      opt.value = ca.id;
      opt.innerText = `[${ca.type.toUpperCase()}] ${ca.name} (${ca.algo || 'RSA'})`;
      select.appendChild(opt);
    });
    if (currentVal && cas.find(c => c.id == currentVal)) select.value = currentVal;
  });
}

async function renderGraph() {
  const box = document.getElementById('mermaid-box');
  if (store.length === 0) {
    box.innerHTML = `<p style="color: var(--muted); font-style: italic;">${t('graph_empty')}</p>`;
    return;
  }

  let def = 'graph TD\n';
  def += '  classDef root fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;\n';
  def += '  classDef inter fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fcd34d;\n';
  def += '  classDef cross fill:#2e1065,stroke:#8b5cf6,stroke-width:2px,color:#ddd6fe;\n';
  def += '  classDef leaf fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#86efac;\n';
  def += '  classDef revoked fill:#1f2937,stroke:#ef4444,stroke-dasharray: 5 5,color:#9ca3af;\n';

  store.forEach(item => {
    const cleanName = item.name.replace(/["[\]()]/g, '');
    const statusTag = item.revoked ? ' [REVOKED]' : '';
    const nodeLabel = `"${cleanName}${statusTag}<br/><small>${item.type.toUpperCase()} | ${item.algo || 'RSA'}</small>"`;
    const cls = item.revoked ? 'revoked' : item.type;
    def += `  N${item.id}[${nodeLabel}]:::${cls}\n`;
  });

  store.forEach(item => {
    if (item.issuerId && item.issuerId !== item.id) {
      const parentExists = store.some(i => i.id === item.issuerId);
      if (parentExists) {
        const edgeLabel = item.type === 'cross' ? '|Cross-Signed|' : `|${t('graph_edge_signed')}|`;
        def += `  N${item.issuerId} -->${edgeLabel} N${item.id}\n`;
      }
    }
    if (item.type === 'cross' && item.crossTargetId) {
      const targetExists = store.some(i => i.id === item.crossTargetId);
      if (targetExists) {
        def += `  N${item.id} -.->|${t('graph_edge_shares_key')}| N${item.crossTargetId}\n`;
      }
    }
  });

  try {
    const { svg } = await mermaid.render('pki-mermaid-svg-' + Date.now(), def);
    box.innerHTML = svg;
  } catch (err) {
    box.innerHTML = `<p style="color:var(--danger)">${t('graph_render_error')}${err.message}</p>`;
  }
}

function applyLeafTemplate() {
  const tpl = document.getElementById('l-template').value;
  const algo = document.getElementById('l-algo');
  const days = document.getElementById('l-days');
  const s = document.getElementById('eku-server');
  const c = document.getElementById('eku-client');
  const e = document.getElementById('eku-email');
  const code = document.getElementById('eku-code');

  s.checked = c.checked = e.checked = code.checked = false;

  if (tpl === 'openvpn_srv') {
    algo.value = 'RSA-2048'; days.value = 825; s.checked = true;
    document.getElementById('l-cn').value = 'vpn.moje-sit.cz';
  } else if (tpl === 'ipsec_cli') {
    algo.value = 'ECDSA-P-256'; days.value = 365; c.checked = true;
    document.getElementById('l-cn').value = 'klient-mobil-01';
  } else if (tpl === 'docker_reg') {
    algo.value = 'RSA-3072'; days.value = 398; s.checked = true; c.checked = true;
    document.getElementById('l-cn').value = 'registry.interni.local';
  } else if (tpl === 'mqtt_iot') {
    algo.value = 'ECDSA-P-256'; days.value = 1095; s.checked = true; c.checked = true;
    document.getElementById('l-cn').value = 'mqtt.home.local';
  } else if (tpl === 'codesign') {
    algo.value = 'RSA-4096'; days.value = 365; code.checked = true;
    document.getElementById('l-cn').value = 'CyberCorp Release Signing';
  } else {
    algo.value = 'RSA-2048'; days.value = 398; s.checked = true;
  }
  showToast(t('toast_template_applied'), 'info');
}

function downloadGeneratedCsr(type) {
  if (type === 'csr') {
    const content = document.getElementById('cg-out-csr').value;
    if (!content) return;
    downloadFile(`${lastGeneratedCsrName}.csr`, content);
    showToast(t('toast_csr_downloaded', { name: lastGeneratedCsrName }), 'success');
  } else if (type === 'key') {
    const content = document.getElementById('cg-out-key').value;
    if (!content) return;
    downloadFile(`${lastGeneratedCsrName}.key`, content);
    showToast(t('toast_key_downloaded', { name: lastGeneratedCsrName }), 'success');
  }
}

function sendGeneratedCsrToSign() {
  const csrPem = document.getElementById('cg-out-csr').value;
  if (!csrPem) return;
  document.getElementById('csr-pem').value = csrPem;
  nav('csr');
  parseCsrInput();
}

function sendGeneratedCsrToDecoder() {
  const csrPem = document.getElementById('cg-out-csr').value;
  if (!csrPem) return;
  document.getElementById('dec-pem').value = csrPem;
  nav('decoder');
  decodePem();
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

function downloadItemFile(id, ext) {
  const item = store.find(i => i.id === id);
  if (!item) return;
  const safeName = item.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  if (ext === 'crt') downloadFile(`${safeName}.crt`, item.certPem);
  else if (ext === 'key' && item.keyPem) downloadFile(`${safeName}.key`, item.keyPem);
}

function downloadChain(id) {
  let current = store.find(i => i.id === id);
  let chain = current.certPem;
  const visited = new Set([current.id]);
  while (current && current.issuerId && !visited.has(current.issuerId)) {
    visited.add(current.issuerId);
    current = store.find(i => i.id === current.issuerId);
    if (current) chain += '\n' + current.certPem;
  }
  const safeName = store.find(i => i.id === id).name.replace(/[^a-zA-Z0-9._-]/g, '_');
  downloadFile(safeName + '_chain.pem', chain);
  showToast(t('toast_chain_downloaded'), 'success');
}

function renderKeyring() {
  const list = document.getElementById('keyring-list');
  if (store.length === 0) {
    list.innerHTML = `<p style="color: var(--muted); font-style: italic;">${t('keyring_empty')}</p>`;
    return;
  }

  list.innerHTML = '';
  store.slice().reverse().forEach(item => {
    let badge = '';
    if (item.type === 'root') badge = '<span class="badge root">ROOT CA</span>';
    else if (item.type === 'inter') badge = '<span class="badge inter">SUB CA</span>';
    else if (item.type === 'cross') badge = '<span class="badge inter" style="background:#4c1d95; color:#ddd6fe;">CROSS CA</span>';
    else badge = '<span class="badge leaf">LEAF</span>';

    const algoBadge = `<span class="badge algo">${item.algo || 'RSA'}</span>`;
    const revBadge = item.revoked ? `<span class="badge revoked">${t('badge_revoked')}</span>` : '';
    const issuerName = item.issuerId === item.id ? 'Self-Signed' : (store.find(i => i.id === item.issuerId)?.name || t('issuer_external'));
    const isCA = item.type === 'root' || item.type === 'inter' || item.type === 'cross';

    list.innerHTML += `
      <div class="keyring-item type-${item.type === 'cross' ? 'inter' : item.type} ${item.revoked ? 'revoked' : ''}">
        <div class="keyring-info">
          <strong>${badge}${algoBadge}${revBadge} ${escapeHtml(item.name)}</strong>
          <span>${t('keyring_issuer')} ${escapeHtml(issuerName)}<br>${t('keyring_serial')} <span style="font-family: monospace; font-size: 11px; color: #94a3b8;">${getItemSerialDisplay(item)}</span></span>
        </div>
        <div class="action-group">
          <button class="btn-sm" onclick="viewPemModal(${item.id}, 'cert')" title="${t('keyring_btn_view_title')}">${t('keyring_btn_view')}</button>
          <button class="btn-sm" onclick="downloadItemFile(${item.id}, 'crt')">.CRT</button>
          ${item.keyPem ? `<button class="btn-sm" onclick="downloadItemFile(${item.id}, 'key')">.KEY</button>` : ''}
          ${item.type !== 'root' ? `<button class="btn-sm" onclick="downloadChain(${item.id})">CHAIN</button>` : ''}
          ${item.keyObj && !item.keyObj.isDummy && item.algo !== 'ED25519' && !item.algo.startsWith('ECDSA') ? `<button class="btn-sm special" onclick="downloadP12(${item.id})">📦 .P12</button>` : ''}
          ${isCA && item.keyPem ? `<button class="btn-sm warn" onclick="downloadCRL(${item.id})" title="${t('keyring_btn_crl_title')}">📜 CRL</button>` : ''}
          ${!item.revoked ? `<button class="btn-sm rev" onclick="revokeCert(${item.id})" title="${t('keyring_btn_revoke_title')}">${t('keyring_btn_revoke')}</button>` : ''}
        </div>
      </div>
    `;
  });
}

