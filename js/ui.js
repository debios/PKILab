let currentModalRawPem = '';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'loose',
  flowchart: { curve: 'linear', htmlLabels: true }
});

const UI_ICONS = {
  success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  error: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>`,
  info: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
  eye: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`,
  download: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>`,
  key: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>`,
  chain: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  archive: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>`,
  fileWarning: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`,
  ban: `<svg class="icon-14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>`,
  emptyKeyring: `<svg class="icon-20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
};

function toggleMobileMenu() {
  const sidebar = document.getElementById('app-sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const openIcon = document.getElementById('icon-menu-open');
  const closeIcon = document.getElementById('icon-menu-close');
  if (!sidebar) return;

  const isOpen = sidebar.classList.toggle('mobile-open');
  if (backdrop) backdrop.classList.toggle('open', isOpen);
  if (toggleBtn) toggleBtn.setAttribute('aria-expanded', String(isOpen));
  if (openIcon && closeIcon) {
    openIcon.style.display = isOpen ? 'none' : 'block';
    closeIcon.style.display = isOpen ? 'block' : 'none';
  }
}

function closeMobileMenu() {
  const sidebar = document.getElementById('app-sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const openIcon = document.getElementById('icon-menu-open');
  const closeIcon = document.getElementById('icon-menu-close');
  if (sidebar) sidebar.classList.remove('mobile-open');
  if (backdrop) backdrop.classList.remove('open');
  if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
  if (openIcon && closeIcon) {
    openIcon.style.display = 'block';
    closeIcon.style.display = 'none';
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const iconSvg = type === 'success' ? UI_ICONS.success : (type === 'error' ? UI_ICONS.error : UI_ICONS.info);
  toast.innerHTML = `${iconSvg}<div>${message}</div>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(6px)';
    toast.style.transition = '0.2s ease';
    setTimeout(() => toast.remove(), 200);
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
  }
  const targetPanel = document.getElementById('panel-' + panelId);
  if (targetPanel) targetPanel.classList.add('active');
  closeMobileMenu();
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
    box.innerHTML = `
      <div class="keyring-empty-state" style="border:none; background:transparent;">
        ${UI_ICONS.emptyKeyring}
        <span>${t('graph_empty')}</span>
      </div>`;
    return;
  }

  let def = 'graph TD\n';
  def += '  classDef root fill:#18181b,stroke:#ef4444,stroke-width:1.5px,color:#fafafa;\n';
  def += '  classDef inter fill:#18181b,stroke:#f59e0b,stroke-width:1.5px,color:#fafafa;\n';
  def += '  classDef cross fill:#18181b,stroke:#3b82f6,stroke-width:1.5px,color:#fafafa;\n';
  def += '  classDef leaf fill:#18181b,stroke:#10b981,stroke-width:1.5px,color:#fafafa;\n';
  def += '  classDef revoked fill:#09090b,stroke:#52525b,stroke-dasharray: 4 4,color:#71717a;\n';

  store.forEach(item => {
    const cleanName = item.name.replace(/["[\]()]/g, '');
    const statusTag = item.revoked ? ' [REVOKED]' : '';
    const nodeLabel = `"${cleanName}${statusTag}<br/><small>${item.type.toUpperCase()} · ${item.algo || 'RSA'}</small>"`;
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
    box.innerHTML = `<p style="color:var(--danger)">${t('graph_render_error')}${escapeHtml(err.message)}</p>`;
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

function updateKeyringStats() {
  const totalEl = document.getElementById('stat-val-total');
  const caEl = document.getElementById('stat-val-ca');
  const leafEl = document.getElementById('stat-val-leaf');
  const revEl = document.getElementById('stat-val-revoked');
  if (!totalEl) return;

  const total = store.length;
  const activeCa = store.filter(i => (i.type === 'root' || i.type === 'inter' || i.type === 'cross') && !i.revoked).length;
  const activeLeaf = store.filter(i => i.type === 'leaf' && !i.revoked).length;
  const revokedCount = store.filter(i => i.revoked).length;

  totalEl.textContent = String(total);
  caEl.textContent = String(activeCa);
  leafEl.textContent = String(activeLeaf);
  revEl.textContent = String(revokedCount);
}

function renderKeyring() {
  updateKeyringStats();
  const list = document.getElementById('keyring-list');
  if (store.length === 0) {
    list.innerHTML = `
      <div class="keyring-empty-state">
        ${UI_ICONS.emptyKeyring}
        <span>${t('keyring_empty')}</span>
      </div>`;
    return;
  }

  list.innerHTML = '';
  store.slice().reverse().forEach(item => {
    let badge = '';
    if (item.type === 'root') badge = '<span class="badge root">ROOT CA</span>';
    else if (item.type === 'inter') badge = '<span class="badge inter">SUB CA</span>';
    else if (item.type === 'cross') badge = '<span class="badge cross">CROSS CA</span>';
    else badge = '<span class="badge leaf">LEAF</span>';

    const algoBadge = `<span class="badge algo">${escapeHtml(item.algo || 'RSA')}</span>`;
    const revBadge = item.revoked ? `<span class="badge revoked">${t('badge_revoked')}</span>` : '';
    const issuerName = item.issuerId === item.id ? 'Self-Signed' : (store.find(i => i.id === item.issuerId)?.name || t('issuer_external'));
    const isCA = item.type === 'root' || item.type === 'inter' || item.type === 'cross';

    list.innerHTML += `
      <div class="keyring-item type-${item.type === 'cross' ? 'inter' : item.type} ${item.revoked ? 'revoked' : ''}">
        <div class="keyring-info">
          <div class="keyring-title-row">
            ${badge}${algoBadge}${revBadge}
            <span class="keyring-name">${escapeHtml(item.name)}</span>
          </div>
          <div class="keyring-meta">
            <span class="keyring-meta-item">${t('keyring_issuer')} <strong style="color: var(--text-secondary); font-weight: 500;">${escapeHtml(issuerName)}</strong></span>
            <span class="keyring-meta-item">${t('keyring_serial')} <code class="keyring-serial">${getItemSerialDisplay(item)}</code></span>
          </div>
        </div>
        <div class="action-group">
          <button class="btn-sm" onclick="viewPemModal(${item.id}, 'cert')" title="${t('keyring_btn_view_title')}">${UI_ICONS.eye}<span>${t('keyring_btn_view')}</span></button>
          <button class="btn-sm" onclick="downloadItemFile(${item.id}, 'crt')">${UI_ICONS.download}<span>.CRT</span></button>
          ${item.keyPem ? `<button class="btn-sm" onclick="downloadItemFile(${item.id}, 'key')">${UI_ICONS.key}<span>.KEY</span></button>` : ''}
          ${item.type !== 'root' ? `<button class="btn-sm" onclick="downloadChain(${item.id})">${UI_ICONS.chain}<span>CHAIN</span></button>` : ''}
          ${item.keyObj && !item.keyObj.isDummy && item.algo !== 'ED25519' && !item.algo.startsWith('ECDSA') ? `<button class="btn-sm special" onclick="downloadP12(${item.id})">${UI_ICONS.archive}<span>.P12</span></button>` : ''}
          ${isCA && item.keyPem ? `<button class="btn-sm warn" onclick="downloadCRL(${item.id})" title="${t('keyring_btn_crl_title')}">${UI_ICONS.fileWarning}<span>CRL</span></button>` : ''}
          ${!item.revoked ? `<button class="btn-sm rev" onclick="revokeCert(${item.id})" title="${t('keyring_btn_revoke_title')}">${UI_ICONS.ban}<span>${t('keyring_btn_revoke')}</span></button>` : ''}
        </div>
      </div>
    `;
  });
}
