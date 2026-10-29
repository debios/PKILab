let lastGeneratedCsrName = 'server';
let parsedCsrObj = null;

// Ošetření diakritiky (UTF-8) v X.509 atributech dle RFC 5280
function prepareX509Attributes(rawAttrs) {
  return rawAttrs.filter(a => a && a.value && String(a.value).trim() !== '').map(a => {
    const valStr = String(a.value).trim();
    const isAscii = /^[\x00-\x7F]*$/.test(valStr);
    if (!isAscii) {
      return {
        ...a,
        value: forge.util.encodeUtf8(valStr),
        valueTagClass: forge.asn1.Type.UTF8
      };
    }
    return { ...a, value: valStr };
  });
}

function decodeX509AttrValue(val) {
  if (!val) return '';
  try { return forge.util.decodeUtf8(val); } catch (e) { return val; }
}

// Detekce algoritmu z veřejného klíče (pro CSR a Import)
function detectPublicKeyAlgo(pubKey, suffix = '') {
  if (!pubKey) return 'UNKNOWN' + suffix;
  if (pubKey.n && typeof pubKey.n.bitLength === 'function') {
    return `RSA-${pubKey.n.bitLength()}${suffix}`;
  }
  if (pubKey.rawAsn1) {
    try {
      const derHex = forge.asn1.toDer(pubKey.rawAsn1).toHex();
      // OID 1.3.101.112 (Ed25519) = 06 03 2b 65 70
      if (derHex.includes('06032b6570')) return 'ED25519' + suffix;
      // OID 1.3.132.0.34 (secp384r1 / P-384) = 06 05 2b 81 04 00 22
      if (derHex.includes('06052b81040022')) return 'ECDSA-P-384' + suffix;
      // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256) = 06 08 2a 86 48 ce 3d 03 01 07
      if (derHex.includes('06082a8648ce3d030107')) return 'ECDSA-P-256' + suffix;
    } catch (e) {}
    return 'ECC' + suffix;
  }
  return 'RSA' + suffix;
}

function arrayBufferToPem(buffer, label) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  const base64 = window.btoa(binary).replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

async function generateKeyMaterial(algoSpec) {
  const pki = forge.pki;
  const asn1 = forge.asn1;
  
  // ED25519 (RFC 8410 SubjectPublicKeyInfo & PKCS#8 PrivateKeyInfo ASN.1)
  if (algoSpec === 'ED25519') {
    const seedBytes = forge.random.getBytesSync(32);
    const edKeys = pki.ed25519.generateKeyPair({ seed: seedBytes });
    const seedHex = forge.util.bytesToHex(seedBytes);
    
    // Standardní RFC 8410 PKCS#8 OneAsymmetricKey zabalení 32B seedu
    const pkcs8Asn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00'),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('1.3.101.112').getBytes())
      ]),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
        asn1.toDer(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, seedBytes)).getBytes()
      )
    ]);
    const pkcs8Der = asn1.toDer(pkcs8Asn1).getBytes();
    const standardPem = forge.pem.encode({ type: 'PRIVATE KEY', body: pkcs8Der });
    
    const pubBytesStr = forge.util.createBuffer(edKeys.publicKey).getBytes();
    const spkiAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('1.3.101.112').getBytes())
      ]),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, '\x00' + pubBytesStr)
    ]);

    return {
      algo: 'ED25519',
      publicKey: { rawAsn1: spkiAsn1, isDummy: true },
      privateKey: edKeys.privateKey,
      keyPem: standardPem,
      edSeedHex: seedHex
    };
  }

  // ECDSA (P-256, P-384) přes WebCrypto API
  if (algoSpec.startsWith('ECDSA-')) {
    if (!window.crypto || !window.crypto.subtle) throw new Error('WebCrypto API není k dispozici. Aplikace musí běžet přes HTTPS (nebo na localhost).');
    const curve = algoSpec.replace('ECDSA-', '');
    
    const webKey = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: curve },
      true, ["sign", "verify"]
    );
    
    const pkcs8Buf = await window.crypto.subtle.exportKey('pkcs8', webKey.privateKey);
    const spkiBuf = await window.crypto.subtle.exportKey('spki', webKey.publicKey);
    const keyPem = arrayBufferToPem(pkcs8Buf, 'PRIVATE KEY');

    const spkiBytes = new Uint8Array(spkiBuf);
    let spkiBinStr = '';
    for (let i = 0; i < spkiBytes.length; i++) spkiBinStr += String.fromCharCode(spkiBytes[i]);
    const spkiAsn1 = asn1.fromDer(forge.util.createBuffer(spkiBinStr));
    
    return {
      algo: algoSpec,
      publicKey: { rawAsn1: spkiAsn1, isDummy: true },
      privateKey: { isDummy: true },
      keyPem: keyPem
    };
  }

  // RSA
  const bits = parseInt(algoSpec.split('-')[1]) || 2048;
  if (window.crypto && window.crypto.subtle) {
    try {
      const webKey = await window.crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['sign', 'verify']
      );
      const pkcs8Buf = await window.crypto.subtle.exportKey('pkcs8', webKey.privateKey);
      const spkiBuf = await window.crypto.subtle.exportKey('spki', webKey.publicKey);
      return {
        algo: `RSA-${bits}`,
        publicKey: pki.publicKeyFromPem(arrayBufferToPem(spkiBuf, 'PUBLIC KEY')),
        privateKey: pki.privateKeyFromPem(arrayBufferToPem(pkcs8Buf, 'PRIVATE KEY')),
        keyPem: arrayBufferToPem(pkcs8Buf, 'PRIVATE KEY')
      };
    } catch (e) { console.warn("WebCrypto fallback na Forge RSA", e); }
  }

  return new Promise((resolve, reject) => {
    pki.rsa.generateKeyPair({ bits, workers: -1 }, (err, keys) => {
      if (err) return reject(err);
      resolve({
        algo: `RSA-${bits}`, publicKey: keys.publicKey, privateKey: keys.privateKey,
        keyPem: pki.privateKeyToPem(keys.privateKey)
      });
    });
  });
}

// RFC 5280 §4.1.2.2: Serial number — 20 oktetů (160 bitů) kryptografické náhody
// MSB musí být 0 (kladné INTEGER bez DER sign-extension bajtu)
function generateSerialNumber() {
  const bytes = new Uint8Array(20);
  window.crypto.getRandomValues(bytes);
  // Zajistíme kladné číslo: vynulujeme nejvyšší bit (0x80), nastavíme bit 0x40
  bytes[0] = (bytes[0] & 0x7f) | 0x40;
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Formátuje hex sériové číslo pro zobrazení (XX:XX:XX:...)
function formatSerialHex(hexStr) {
  if (!hexStr) return 'N/A';
  const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
  if (!clean) return 'N/A';
  // Skupiny po 2 znacích oddělené dvojtečkou
  return clean.match(/.{1,2}/g).join(':').toUpperCase();
}

// Záchranné přečtení sériového čísla přímo z DER/ASN.1 (pro ECC certifikáty
// kde forge.pki.certificateFromPem může vracet certObj.serialNumber jako prázdný
// řetězec nebo undefined kvůli odlišnému SPKI parsování)
function extractSerialFromPem(certPem) {
  try {
    const msg = forge.pem.decode(certPem)[0];
    const asn1 = forge.asn1.fromDer(msg.body);
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... } }
    // TBSCertificate ::= SEQUENCE { version [0], serialNumber INTEGER, ... }
    const tbs = asn1.value[0]; // TBSCertificate
    if (!tbs || !tbs.value) return null;
    let snIdx = 0;
    // Přeskočíme volitelné [0] EXPLICIT version (tag 0xa0)
    if (tbs.value[0] && tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) {
      snIdx = 1;
    }
    const snAsn1 = tbs.value[snIdx];
    if (!snAsn1 || snAsn1.type !== forge.asn1.Type.INTEGER) return null;
    // Převod binárního obsahu INTEGER na hex
    let hex = '';
    for (let i = 0; i < snAsn1.value.length; i++) {
      hex += snAsn1.value.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex || null;
  } catch (e) {
    return null;
  }
}

// Vrátí zobrazitelné sériové číslo pro položku klíčenky
function getItemSerialDisplay(item) {
  // Priorita 1: uložená metadata serialHex (přesná hodnota z generování)
  if (item.serialHex) return formatSerialHex(item.serialHex);
  // Priorita 2: certObj.serialNumber naplněno forge parserem
  const sn = item.certObj && item.certObj.serialNumber;
  if (sn && typeof sn === 'string' && sn.replace(/[^0-9a-fA-F]/g,'').length > 0) {
    return formatSerialHex(sn);
  }
  // Priorita 3: záchranné parsování z PEM (kritické pro ECC certifikáty)
  if (item.certPem) {
    const extracted = extractSerialFromPem(item.certPem);
    if (extracted) return formatSerialHex(extracted);
  }
  return 'N/A';
}

function createBaseCert(publicKey, validityDays) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  const sn = generateSerialNumber();
  cert.serialNumber = sn;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + validityDays);
  // Vrátíme i serialHex pro uložení do store
  cert._serialHex = sn;
  return cert;
}

// ---- RFC 5280 & CA/B FORUM: AUTHORITY KEY IDENTIFIER (AKI) PRO NE-ROOT CERTIFIKÁTY ----
// Generuje striktně standardní AKI rozšíření pro Intermediate CA a koncové (Leaf / CSR / Cross) certifikáty:
// 1. keyIdentifier MUSÍ být binární SHA-1 hash o délce přesně 20 bajtů (160 bitů) SPKI vystavující CA.
//    Pokud je k dispozici 40znakový hex string (z SKI vystavitele), převede se pomocí forge.util.hexToBytes().
// 2. critical MUSÍ být explicitně false.
// 3. Rozšíření NESMÍ obsahovat authorityCertIssuer ani authorityCertSerialNumber (v DER způsobují Apple Keychain chybu).
function createAuthorityKeyIdentifier(issuerCert) {
  if (!issuerCert) {
    throw new Error('Nelze vytvořit Authority Key Identifier bez certifikátu vystavitele.');
  }

  let keyBytes = null;

  // A) Zkusíme získat Subject Key Identifier z rozšíření vystavujícího certifikátu
  if (typeof issuerCert.getExtension === 'function') {
    const skiExt = issuerCert.getExtension('subjectKeyIdentifier');
    if (skiExt && skiExt.subjectKeyIdentifier) {
      const val = skiExt.subjectKeyIdentifier;
      if (typeof val === 'string') {
        const clean = val.replace(/[^0-9a-fA-F]/g, '');
        if (clean.length === 40) {
          keyBytes = forge.util.hexToBytes(clean);
        } else if (val.length === 20) {
          keyBytes = val;
        }
      } else if (val && typeof val.getBytes === 'function') {
        const b = val.getBytes();
        if (b.length === 20) keyBytes = b;
      }
    }
  }

  // B) Pokud SKI v rozšířeních chybí, spočteme 20bajtový SHA-1 hash SPKI klíče vystavitele (RFC 5280 §4.2.1.2)
  if (!keyBytes || keyBytes.length !== 20) {
    if (typeof issuerCert.generateSubjectKeyIdentifier === 'function') {
      try {
        const skiBuf = issuerCert.generateSubjectKeyIdentifier();
        if (skiBuf && typeof skiBuf.getBytes === 'function') {
          const b = skiBuf.getBytes();
          if (b.length === 20) keyBytes = b;
        }
      } catch (e) {
        /* fallback */
      }
    }
  }

  // C) Fallback přes forge.pki.getPublicKeyFingerprint
  if (!keyBytes || keyBytes.length !== 20) {
    if (issuerCert.publicKey) {
      try {
        const fp = forge.pki.getPublicKeyFingerprint(issuerCert.publicKey, {
          type: 'SubjectPublicKeyInfo',
          encoding: 'binary'
        });
        if (fp && fp.length === 20) {
          keyBytes = fp;
        } else if (typeof fp === 'string') {
          const clean = fp.replace(/[^0-9a-fA-F]/g, '');
          if (clean.length === 40) keyBytes = forge.util.hexToBytes(clean);
        }
      } catch (e) {
        /* fallback */
      }
    }
  }

  // D) Striktní ověření délky: přesně 20 bajtů (160 bitů)
  if (!keyBytes || keyBytes.length !== 20) {
    throw new Error(`Neplatná délka Authority Key Identifier: očekáváno přesně 20 bajtů (160 bitů SHA-1), získáno ${keyBytes ? keyBytes.length : 0} bajtů.`);
  }

  return {
    name: 'authorityKeyIdentifier',
    critical: false,
    keyIdentifier: keyBytes
  };
}

// ---- NATIVNÍ ECDSA PODPIS POMOCÍ WEBCRYPTO ----
async function signEcdsaWebCrypto(tbsDerString, keyPem, curve) {
  const hashAlg = curve === 'P-384' ? 'SHA-384' : 'SHA-256';
  
  const b64 = keyPem.replace(/(-----(BEGIN|END).*-----|\s)/g, '');
  const bin = window.atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  
  const cryptoKey = await window.crypto.subtle.importKey(
    'pkcs8', buf.buffer,
    { name: 'ECDSA', namedCurve: curve },
    false, ['sign']
  );

  const tbsBuf = new Uint8Array(tbsDerString.length);
  for (let i = 0; i < tbsDerString.length; i++) tbsBuf[i] = tbsDerString.charCodeAt(i);

  const rawSig = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: hashAlg } },
    cryptoKey,
    tbsBuf
  );

  // Převod IEEE P1363 (R|S) podpisu do X.509 ASN.1 SEQUENCE (INTEGER r, INTEGER s)
  const sigBytes = new Uint8Array(rawSig);
  const half = sigBytes.length / 2;
  const rBytes = sigBytes.subarray(0, half);
  const sBytes = sigBytes.subarray(half);
  
  const toDerIntBytes = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let slice = bytes.subarray(i);
    let str = '';
    if (slice[0] & 0x80) str += '\x00';
    for (let j = 0; j < slice.length; j++) str += String.fromCharCode(slice[j]);
    return str;
  };

  const asn1 = forge.asn1;
  const sigAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, toDerIntBytes(rBytes)),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, toDerIntBytes(sBytes))
  ]);

  return forge.asn1.toDer(sigAsn1).getBytes();
}

// ---- PODPIS X.509 CERTIFIKÁTU (RSA, ECDSA, Ed25519) ----
async function signCertificateWithIssuer(cert, issuerItem, isSelfSigned = false) {
  const issuerAlgo = issuerItem.algo || 'RSA-2048';
  const issuerKeyObj = isSelfSigned ? issuerItem.privateKey : issuerItem.keyObj;
  const issuerKeyPem = issuerItem.keyPem;

  if (issuerAlgo === 'ED25519') {
    const oid = '1.3.101.112';
    cert.signatureOid = oid;
    cert.signatureParameters = undefined;
    cert.siginfo = cert.siginfo || {};
    cert.siginfo.algorithmOid = oid;
    cert.siginfo.parameters = undefined;

    cert.tbsCertificate = forge.pki.getTBSCertificate(cert);
    const tbsDer = forge.asn1.toDer(cert.tbsCertificate).getBytes();
    const sigUint8 = forge.pki.ed25519.sign({
      message: tbsDer,
      encoding: 'binary',
      privateKey: issuerKeyObj
    });
    cert.signature = forge.util.createBuffer(sigUint8).getBytes();
  } else if (issuerAlgo.startsWith('ECDSA-')) {
    const curve = issuerAlgo.replace('ECDSA-', '');
    const oid = curve === 'P-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2';
    
    cert.signatureOid = oid;
    cert.signatureParameters = undefined;
    cert.siginfo = cert.siginfo || {};
    cert.siginfo.algorithmOid = oid;
    cert.siginfo.parameters = undefined;
    
    cert.tbsCertificate = forge.pki.getTBSCertificate(cert);
    const tbsDer = forge.asn1.toDer(cert.tbsCertificate).getBytes();
    
    cert.signature = await signEcdsaWebCrypto(tbsDer, issuerKeyPem, curve);
  } else {
    cert.sign(issuerKeyObj, forge.md.sha256.create());
  }
}

// ---- PODPIS PKCS#10 CSR ŽÁDOSTI VLASTNÍM KLÍČEM (RSA, ECDSA, Ed25519) ----
async function signCsrWithKeyMaterial(csr, keyMat) {
  const algo = keyMat.algo || 'RSA-2048';
  if (algo === 'ED25519') {
    const oid = '1.3.101.112';
    csr.signatureOid = oid;
    csr.signatureParameters = undefined;
    csr.siginfo = csr.siginfo || {};
    csr.siginfo.algorithmOid = oid;
    csr.siginfo.parameters = undefined;

    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);
    const tbsDer = forge.asn1.toDer(csr.certificationRequestInfo).getBytes();
    const sigUint8 = forge.pki.ed25519.sign({
      message: tbsDer,
      encoding: 'binary',
      privateKey: keyMat.privateKey
    });
    csr.signature = forge.util.createBuffer(sigUint8).getBytes();
  } else if (algo.startsWith('ECDSA-')) {
    const curve = algo.replace('ECDSA-', '');
    const oid = curve === 'P-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2';

    csr.signatureOid = oid;
    csr.signatureParameters = undefined;
    csr.siginfo = csr.siginfo || {};
    csr.siginfo.algorithmOid = oid;
    csr.siginfo.parameters = undefined;

    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);
    const tbsDer = forge.asn1.toDer(csr.certificationRequestInfo).getBytes();
    csr.signature = await signEcdsaWebCrypto(tbsDer, keyMat.keyPem, curve);
  } else {
    csr.sign(keyMat.privateKey, forge.md.sha256.create());
  }
}

// ---- BEZPEČNÉ PARSOVÁNÍ CSR (Podpora RSA i ECC/Ed25519 žádostí) ----
function safeCertificationRequestFromPem(pem) {
  try {
    return forge.pki.certificationRequestFromPem(pem);
  } catch (err) {
    const msg = forge.pem.decode(pem)[0];
    if (!msg.type.includes('CERTIFICATE REQUEST')) throw err;
    const obj = forge.asn1.fromDer(msg.body);
    const origCreateCsr = forge.pki.createCertificationRequest;
    forge.pki.createCertificationRequest = function() {
      const c = origCreateCsr();
      c.verify = function() { return true; };
      return c;
    };
    try {
      return forge.pki.certificationRequestFromAsn1(obj);
    } finally {
      forge.pki.createCertificationRequest = origCreateCsr;
    }
  }
}

async function generateRoot() {
  const btn = document.getElementById('btn-gen-root');
  btn.disabled = true;
  const algo = document.getElementById('r-algo').value;
  showToast(t('toast_root_generating', { algo }), 'info');

  try {
    const cn = document.getElementById('r-cn').value.trim() || 'Root CA';
    const years = parseInt(document.getElementById('r-years').value) || 10;
    const keyMat = await generateKeyMaterial(algo);
    const cert = createBaseCert(keyMat.publicKey, years * 365);

    const attrs = prepareX509Attributes([
      { name: 'commonName', value: cn },
      { name: 'organizationName', value: document.getElementById('r-o').value },
      { name: 'organizationalUnitName', value: document.getElementById('r-ou').value },
      { name: 'countryName', value: document.getElementById('r-c').value },
      { name: 'localityName', value: document.getElementById('r-l').value }
    ]);

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // RFC 5280 §4.2.1.9: basicConstraints critical=TRUE, cA=TRUE pro Root CA
    // RFC 5280 §4.2.1.3: keyUsage critical=TRUE s keyCertSign a cRLSign
    // RFC 5280 §4.2.1.2: subjectKeyIdentifier (metoda 1: SHA-1 hash SPKI bit-string)
    // RFC 5280 & CA/B Forum: Self-signed Root CA NESMÍ obsahovat authorityKeyIdentifier (pouze subjectKeyIdentifier)
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' }
    ]);

    await signCertificateWithIssuer(cert, keyMat, true);

    const id = idCounter++;
    saveItem({
      id, type: 'root', name: cn, issuerId: id,
      algo: keyMat.algo, edSeedHex: keyMat.edSeedHex || null,
      serialHex: cert._serialHex,
      revoked: false, revocationDate: null,
      certObj: cert, keyObj: keyMat.privateKey,
      certPem: forge.pki.certificateToPem(cert), keyPem: keyMat.keyPem
    });

    showToast(t('toast_root_created', { name: cn, algo: keyMat.algo }), 'success');
  } catch (err) {
    showToast(t('toast_root_error', { err: err.message }), 'error');
  } finally {
    btn.disabled = false;
  }
}

async function generateInter() {
  const issuerId = parseInt(document.getElementById('i-issuer').value);
  if (!issuerId) return showToast(t('toast_select_issuer'), 'error');
  const issuer = store.find(i => i.id === issuerId);

  const btn = document.getElementById('btn-gen-inter');
  btn.disabled = true;
  const algo = document.getElementById('i-algo').value;
  showToast(t('toast_inter_generating', { algo }), 'info');

  try {
    const cn = document.getElementById('i-cn').value.trim() || 'Intermediate CA';
    const pathLen = parseInt(document.getElementById('i-pathlen').value);
    const years = parseInt(document.getElementById('i-years').value) || 5;

    const keyMat = await generateKeyMaterial(algo);
    const cert = createBaseCert(keyMat.publicKey, years * 365);

    cert.setSubject(prepareX509Attributes([{ name: 'commonName', value: cn }]));
    cert.setIssuer(issuer.certObj.subject.attributes);

    const basicCons = { name: 'basicConstraints', cA: true, critical: true };
    if (!isNaN(pathLen) && pathLen >= 0) basicCons.pathLenConstraint = pathLen;

    // RFC 5280 §4.2.1.1: authorityKeyIdentifier = 20bajtový binární SHA-1 hash klíče vystavující CA
    // RFC 5280 §4.2.1.2: subjectKeyIdentifier pro tuto Intermediate CA
    const akiExt = createAuthorityKeyIdentifier(issuer.certObj);

    cert.setExtensions([
      basicCons,
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' },
      akiExt
    ]);

    await signCertificateWithIssuer(cert, issuer);

    saveItem({
      id: idCounter++, type: 'inter', name: cn, issuerId: issuer.id,
      algo: keyMat.algo, edSeedHex: keyMat.edSeedHex || null,
      serialHex: cert._serialHex,
      revoked: false, revocationDate: null,
      certObj: cert, keyObj: keyMat.privateKey,
      certPem: forge.pki.certificateToPem(cert), keyPem: keyMat.keyPem
    });

    showToast(t('toast_inter_created', { name: cn, issuer: issuer.name }), 'success');
  } catch (err) {
    showToast(t('toast_error', { err: err.message }), 'error');
  } finally {
    btn.disabled = false;
  }
}

function parseSanString(rawSans) {
  return rawSans.split(',').map(s => s.trim()).filter(Boolean).map(item => {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(item) ? { type: 7, ip: item } : { type: 2, value: item };
  });
}

async function generateLeaf() {
  const issuerId = parseInt(document.getElementById('l-issuer').value);
  if (!issuerId) return showToast(t('toast_select_issuer'), 'error');
  const issuer = store.find(i => i.id === issuerId);

  const btn = document.getElementById('btn-gen-leaf');
  btn.disabled = true;
  const algo = document.getElementById('l-algo').value;
  showToast(t('toast_leaf_generating', { algo }), 'info');

  try {
    const cn = document.getElementById('l-cn').value.trim() || 'leaf.local';
    const days = parseInt(document.getElementById('l-days').value) || 398;
    const keyMat = await generateKeyMaterial(algo);
    const cert = createBaseCert(keyMat.publicKey, days);

    cert.setSubject(prepareX509Attributes([{ name: 'commonName', value: cn }]));
    cert.setIssuer(issuer.certObj.subject.attributes);

    const altNames = parseSanString(document.getElementById('l-san').value);
    const ekuObj = { name: 'extKeyUsage', critical: false };
    if (document.getElementById('eku-server').checked) ekuObj.serverAuth = true;
    if (document.getElementById('eku-client').checked) ekuObj.clientAuth = true;
    if (document.getElementById('eku-email').checked) ekuObj.emailProtection = true;
    if (document.getElementById('eku-code').checked) ekuObj.codeSigning = true;

    const isRSA = keyMat.algo.startsWith('RSA');
    const isCodeSign = document.getElementById('eku-code').checked;
    // RFC 5280 + CA/Browser Forum: keyUsage critical=TRUE
    // Code Signing vyžaduje digitalSignature + nonRepudiation (CA/BF CS BRs)
    const kuObj = { name: 'keyUsage', digitalSignature: true, critical: true };
    if (isRSA) kuObj.keyEncipherment = true;
    if (isCodeSign) kuObj.nonRepudiation = true;

    // RFC 5280 §4.2.1.1: authorityKeyIdentifier = 20bajtový binární SHA-1 hash klíče vystavující CA
    const akiExt = createAuthorityKeyIdentifier(issuer.certObj);

    const exts = [
      { name: 'basicConstraints', cA: false, critical: true },
      kuObj,
      ekuObj,
      { name: 'subjectKeyIdentifier' },
      akiExt
    ];
    if (altNames.length > 0) exts.push({ name: 'subjectAltName', altNames });
    cert.setExtensions(exts);

    await signCertificateWithIssuer(cert, issuer);

    saveItem({
      id: idCounter++, type: 'leaf', name: cn, issuerId: issuer.id,
      algo: keyMat.algo, edSeedHex: keyMat.edSeedHex || null,
      serialHex: cert._serialHex,
      revoked: false, revocationDate: null,
      certObj: cert, keyObj: keyMat.privateKey,
      certPem: forge.pki.certificateToPem(cert), keyPem: keyMat.keyPem
    });

    showToast(t('toast_leaf_created', { name: cn }), 'success');
  } catch (err) {
    showToast(t('toast_error', { err: err.message }), 'error');
  } finally {
    btn.disabled = false;
  }
}

// ---- VYTVOŘENÍ CSR A PRIVÁTNÍHO KLÍČE ----
async function generateCsr() {
  const btn = document.getElementById('btn-gen-csr');
  btn.disabled = true;
  const algo = document.getElementById('cg-algo').value;
  showToast(t('toast_csr_generating', { algo }), 'info');

  try {
    const cn = document.getElementById('cg-cn').value.trim() || 'server.local';
    lastGeneratedCsrName = cn.replace(/[^a-zA-Z0-9._-]/g, '_') || 'server';

    // 1. Vygenerování páru klíčů
    const keyMat = await generateKeyMaterial(algo);

    // 2. Sestavení CSR objektu
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keyMat.publicKey;

    // 3. Přiřazení atributů a SAN rozšíření
    const subjectAttrs = prepareX509Attributes([
      { name: 'commonName', value: cn },
      { name: 'organizationName', value: document.getElementById('cg-o').value },
      { name: 'organizationalUnitName', value: document.getElementById('cg-ou').value },
      { name: 'countryName', value: document.getElementById('cg-c').value },
      { name: 'localityName', value: document.getElementById('cg-l').value }
    ]);
    csr.setSubject(subjectAttrs);

    const altNames = parseSanString(document.getElementById('cg-san').value);
    if (altNames.length > 0) {
      csr.setAttributes([
        {
          name: 'extensionRequest',
          extensions: [
            { name: 'subjectAltName', altNames }
          ]
        }
      ]);
    }

    // 4. Podepsání žádosti vlastním nově vzniklým privátním klíčem
    await signCsrWithKeyMaterial(csr, keyMat);

    // 5. Výstup: Serverový privátní klíč (.key) a žádost o podpis (.csr)
    const csrPem = forge.pki.certificationRequestToPem(csr);
    const keyPem = keyMat.keyPem;

    document.getElementById('cg-out-csr').value = csrPem;
    document.getElementById('cg-out-key').value = keyPem;
    document.getElementById('cg-output-box').style.display = 'block';

    showToast(t('toast_csr_created', { name: cn, algo: keyMat.algo }), 'success');
  } catch (err) {
    showToast(t('toast_csr_error', { err: err.message }), 'error');
  } finally {
    btn.disabled = false;
  }
}

// ---- PARSOVÁNÍ A PODPIS CSR ----
function parseCsrInput() {
  const pem = document.getElementById('csr-pem').value.trim();
  const box = document.getElementById('csr-review-box');
  if (!pem.includes('BEGIN CERTIFICATE REQUEST') && !pem.includes('BEGIN NEW CERTIFICATE REQUEST')) {
    box.style.display = 'none';
    return;
  }
  try {
    const csr = safeCertificationRequestFromPem(pem);
    parsedCsrObj = csr;
    const cnAttr = csr.subject.getField('CN');
    document.getElementById('csr-cn').value = cnAttr ? decodeX509AttrValue(cnAttr.value) : 'csr-klient.local';

    let sanList = [];
    const extReq = csr.getAttribute({ name: 'extensionRequest' });
    if (extReq && extReq.extensions) {
      const sanExt = extReq.extensions.find(e => e.name === 'subjectAltName');
      if (sanExt && sanExt.altNames) {
        sanList = sanExt.altNames.map(n => n.type === 7 ? n.ip : n.value);
      }
    }
    document.getElementById('csr-san').value = sanList.join(', ');
    box.style.display = 'block';
    showToast(t('toast_csr_loaded'), 'success');
  } catch (e) {
    box.style.display = 'none';
    showToast(t('toast_csr_parse_error', { err: e.message }), 'error');
  }
}

async function signCsrRequest() {
  if (!parsedCsrObj) return showToast(t('toast_csr_insert_first'), 'error');
  const issuerId = parseInt(document.getElementById('csr-issuer').value);
  if (!issuerId) return showToast(t('toast_select_issuer'), 'error');
  const issuer = store.find(i => i.id === issuerId);

  try {
    // Ověření podpisu CSR žádosti před vydáním certifikátu (Proof of Possession)
    // Pro RSA klíče: plné kryptografické ověření; pro ECC/Ed25519: forge nemá nativní verify
    if (parsedCsrObj.publicKey && !parsedCsrObj.publicKey.isDummy) {
      try {
        const sigValid = parsedCsrObj.verify();
        if (!sigValid) {
          return showToast(t('toast_csr_verify_failed'), 'error');
        }
      } catch (verifyErr) {
        // ECC/Ed25519 CSR — forge verify() vyhazuje výjimku, logujeme ale pokračujeme
        console.warn('CSR verify() selhal (pravděpodobně ne-RSA klíč):', verifyErr.message);
      }
    }

    const cn = document.getElementById('csr-cn').value.trim() || 'csr-signed.local';
    const days = parseInt(document.getElementById('csr-days').value) || 398;
    const cert = createBaseCert(parsedCsrObj.publicKey, days);

    const otherAttrs = parsedCsrObj.subject.attributes.filter(a => a.shortName !== 'CN' && a.name !== 'commonName');
    const cnPrepared = prepareX509Attributes([{ name: 'commonName', value: cn }]);
    cert.setSubject([...cnPrepared, ...otherAttrs]);
    cert.setIssuer(issuer.certObj.subject.attributes);

    const altNames = parseSanString(document.getElementById('csr-san').value);
    const ekuObj = { name: 'extKeyUsage', critical: false };
    if (document.getElementById('csr-eku-server').checked) ekuObj.serverAuth = true;
    if (document.getElementById('csr-eku-client').checked) ekuObj.clientAuth = true;
    if (document.getElementById('csr-eku-email').checked) ekuObj.emailProtection = true;
    if (document.getElementById('csr-eku-code').checked) ekuObj.codeSigning = true;

    const isRsaPublicKey = !!(parsedCsrObj.publicKey && parsedCsrObj.publicKey.n);
    const isCodeSign = document.getElementById('csr-eku-code').checked;
    const kuObj = { name: 'keyUsage', digitalSignature: true, critical: true };
    if (isRsaPublicKey) kuObj.keyEncipherment = true;
    if (isCodeSign) kuObj.nonRepudiation = true;

    // RFC 5280 §4.2.1.1: authorityKeyIdentifier = 20bajtový binární SHA-1 hash klíče vystavující CA
    const akiExt = createAuthorityKeyIdentifier(issuer.certObj);

    const exts = [
      { name: 'basicConstraints', cA: false, critical: true },
      kuObj,
      ekuObj,
      { name: 'subjectKeyIdentifier' },
      akiExt
    ];
    if (altNames.length > 0) exts.push({ name: 'subjectAltName', altNames });
    cert.setExtensions(exts);

    await signCertificateWithIssuer(cert, issuer);

    const detectedAlgo = detectPublicKeyAlgo(parsedCsrObj.publicKey, '-CSR');

    saveItem({
      id: idCounter++, type: 'leaf', name: `[CSR] ${cn}`, issuerId: issuer.id,
      algo: detectedAlgo, edSeedHex: null,
      serialHex: cert._serialHex,
      revoked: false, revocationDate: null,
      certObj: cert, keyObj: null,
      certPem: forge.pki.certificateToPem(cert), keyPem: null
    });

    showToast(t('toast_csr_signed', { name: cn }), 'success');
  } catch (err) {
    showToast(t('toast_csr_sign_error', { err: err.message }), 'error');
  }
}

async function crossSign() {
  const targetId = parseInt(document.getElementById('c-target').value);
  const issuerId = parseInt(document.getElementById('c-issuer').value);
  if (!targetId || !issuerId) return showToast(t('toast_cross_select_both'), 'error');
  if (targetId === issuerId) return showToast(t('toast_cross_same_error'), 'error');

  const target = store.find(i => i.id === targetId);
  const issuer = store.find(i => i.id === issuerId);

  try {
    const years = parseInt(document.getElementById('c-years').value) || 3;
    const cert = createBaseCert(target.certObj.publicKey, years * 365);

    cert.setSubject(target.certObj.subject.attributes);
    cert.setIssuer(issuer.certObj.subject.attributes);

    // RFC 5280 §4.2.1.1: AKI = 20bajtový binární SHA-1 hash klíče podepisující CA; Cross-signed cert zachovává veřejný klíč cíle
    const akiExt = createAuthorityKeyIdentifier(issuer.certObj);

    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' },
      akiExt
    ]);

    await signCertificateWithIssuer(cert, issuer);

    saveItem({
      id: idCounter++, type: 'cross', name: `[Cross] ${target.name}`, issuerId: issuer.id, crossTargetId: target.id,
      algo: target.algo || 'RSA', edSeedHex: target.edSeedHex || null,
      serialHex: cert._serialHex,
      revoked: false, revocationDate: null,
      certObj: cert, keyObj: target.keyObj,
      certPem: forge.pki.certificateToPem(cert), keyPem: target.keyPem
    });

    showToast(t('toast_cross_created', { target: target.name, issuer: issuer.name }), 'success');
  } catch (err) {
    showToast(t('toast_cross_error', { err: err.message }), 'error');
  }
}

function revokeCert(id) {
  const item = store.find(i => i.id === id);
  if (!item || item.revoked) return;
  if (!confirm(t('confirm_revoke', { name: item.name }))) return;

  item.revoked = true;
  item.revocationDate = new Date().toISOString();
  syncStore();
  updateCaSelects();
  renderKeyring();
  showToast(t('toast_revoked', { name: item.name }), 'info');
}

function dateToUtcTimeAsn1(date) {
  const asn1 = forge.asn1;
  const pad = n => (n < 10 ? '0' + n : '' + n);
  const str = pad(date.getUTCFullYear() % 100) + pad(date.getUTCMonth() + 1) + pad(date.getUTCDate()) +
              pad(date.getUTCHours()) + pad(date.getUTCMinutes()) + pad(date.getUTCSeconds()) + 'Z';
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false, str);
}

async function downloadCRL(caId) {
  const ca = store.find(i => i.id === caId);
  if (!ca || !ca.keyPem) return showToast(t('toast_crl_no_key'), 'error');

  try {
    const revokedChildren = store.filter(i => i.issuerId === ca.id && i.id !== ca.id && i.revoked);

    const asn1 = forge.asn1;
    const pki = forge.pki;
    const now = new Date();
    const next = new Date(now.getTime() + 30 * 86400000);
    
    const isEcdsa = ca.algo && ca.algo.startsWith('ECDSA-');
    const curve = isEcdsa ? ca.algo.replace('ECDSA-', '') : null;
    
    const sigOid = ca.algo === 'ED25519' ? '1.3.101.112' : 
                   isEcdsa ? (curve === 'P-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2') :
                   pki.oids.sha256WithRSAEncryption;
    
    const algParams = (isEcdsa || ca.algo === 'ED25519') ? [] : [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')];
    const algId = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(sigOid).getBytes()),
      ...algParams
    ]);

    const revokedSeqItems = revokedChildren.map(rc => {
      // Priorita: uložené serialHex → certObj.serialNumber → DER extrakce (jako u klíčenky)
      let hexSerial = rc.serialHex || rc.certObj?.serialNumber || '';
      hexSerial = hexSerial.replace(/[^0-9a-fA-F]/g, '');
      if (!hexSerial) {
        // Záchranné parsování z PEM
        try {
          const msg = forge.pem.decode(rc.certPem)[0];
          const asn = forge.asn1.fromDer(msg.body);
          const tbs = asn.value[0];
          if (tbs && tbs.value) {
            let snIdx = 0;
            if (tbs.value[0] && tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) snIdx = 1;
            const snAsn = tbs.value[snIdx];
            if (snAsn && snAsn.type === forge.asn1.Type.INTEGER) {
              for (let i = 0; i < snAsn.value.length; i++) {
                hexSerial += snAsn.value.charCodeAt(i).toString(16).padStart(2, '0');
              }
            }
          }
        } catch (e) { hexSerial = '01'; }
      }
      if (hexSerial.length % 2 !== 0) hexSerial = '0' + hexSerial;
      const serialBytes = forge.util.hexToBytes(hexSerial);
      const revDate = rc.revocationDate ? new Date(rc.revocationDate) : now;
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, serialBytes),
        dateToUtcTimeAsn1(revDate)
      ]);
    });

    const tbsFields = [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x01'),
      algId, pki.distinguishedNameToAsn1(ca.certObj.subject),
      dateToUtcTimeAsn1(now), dateToUtcTimeAsn1(next)
    ];
    if (revokedSeqItems.length > 0) {
      tbsFields.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, revokedSeqItems));
    }

    const tbsCertList = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, tbsFields);
    const tbsDerBytes = asn1.toDer(tbsCertList).getBytes();

    let signatureBytes;
    if (ca.algo === 'ED25519') {
      const sigUint8 = pki.ed25519.sign({ message: tbsDerBytes, encoding: 'binary', privateKey: ca.keyObj });
      signatureBytes = forge.util.createBuffer(sigUint8).getBytes();
    } else if (isEcdsa) {
      signatureBytes = await signEcdsaWebCrypto(tbsDerBytes, ca.keyPem, curve);
    } else {
      const md = forge.md.sha256.create();
      md.update(tbsDerBytes);
      signatureBytes = ca.keyObj.sign(md);
    }

    const crlAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      tbsCertList, algId, asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, '\x00' + signatureBytes)
    ]);

    const crlPem = forge.pem.encode({ type: 'X509 CRL', body: asn1.toDer(crlAsn1).getBytes() });
    downloadFile(ca.name.replace(/\s+/g, '_') + '.crl.pem', crlPem);
    showToast(t('toast_crl_downloaded', { name: ca.name, count: revokedChildren.length }), 'success');
    
  } catch (err) {
    showToast(t('toast_crl_error', { err: err.message }), 'error');
  }
}

function importExternalPem() {
  const raw = document.getElementById('imp-pem').value.trim();
  if (!raw) return showToast(t('toast_imp_insert'), 'error');

  const certMatch = raw.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  if (!certMatch) return showToast(t('toast_imp_no_cert'), 'error');

  // Regex pokrývá PKCS#8 (PRIVATE KEY), tradiční RSA (RSA PRIVATE KEY),
  // tradiční EC (EC PRIVATE KEY) i šifrované (ENCRYPTED PRIVATE KEY)
  const keyMatch = raw.match(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/);

  try {
    const certPem = certMatch[0];
    const keyPem = keyMatch ? keyMatch[0] : null;
    const certObj = forge.pki.certificateFromPem(certPem);
    const detectedAlgo = detectPublicKeyAlgo(certObj.publicKey);
    let keyObj = null;
    let edSeedHex = null;

    if (keyPem) {
      if (detectedAlgo === 'ED25519') {
        const msg = forge.pem.decode(keyPem)[0];
        const seedBytes = msg.body.length >= 32 ? msg.body.slice(msg.body.length - 32) : msg.body;
        edSeedHex = forge.util.bytesToHex(seedBytes);
        keyObj = forge.pki.ed25519.generateKeyPair({ seed: seedBytes }).privateKey;
      } else {
        try { keyObj = forge.pki.privateKeyFromPem(keyPem); } catch (e) { keyObj = { isDummy: true }; }
      }
    }

    const rawCn = certObj.subject.getField('CN')?.value;
    const cn = rawCn ? decodeX509AttrValue(rawCn) : t('import_default_cn');
    const rawIssuerCn = certObj.issuer.getField('CN')?.value;
    const issuerCn = rawIssuerCn ? decodeX509AttrValue(rawIssuerCn) : '';
    const bc = certObj.getExtension('basicConstraints');
    const isCA = bc && bc.cA;

    let type = 'leaf';
    let issuerId = null;

    if (isCA && cn === issuerCn) type = 'root';
    else if (isCA) type = 'inter';

    const parentCa = store.find(i => i.name === issuerCn || decodeX509AttrValue(i.certObj?.subject?.getField('CN')?.value) === issuerCn);
    const newId = idCounter++;
    issuerId = (type === 'root') ? newId : (parentCa ? parentCa.id : newId);

    // Extrahujeme serialHex z DER pro spolehlivé zobrazení i u ECC certifikátů
    let importedSerialHex = null;
    try {
      const msg = forge.pem.decode(certPem)[0];
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
          importedSerialHex = hex || null;
        }
      }
    } catch (e) { /* ignorujeme */ }

    saveItem({
      id: newId, type, name: cn, issuerId,
      algo: detectedAlgo || (keyObj ? 'EXT-KEY' : 'EXT-PEM'),
      edSeedHex, serialHex: importedSerialHex,
      revoked: false, revocationDate: null,
      certObj, keyObj, certPem, keyPem
    });

    document.getElementById('imp-pem').value = '';
    showToast(t('toast_imp_success', { name: cn, algo: detectedAlgo }), 'success');
  } catch (err) {
    showToast(t('toast_imp_error', { err: err.message }), 'error');
  }
}

function downloadP12(id) {
  const item = store.find(i => i.id === id);
  if (!item.keyObj || item.algo === 'ED25519' || item.algo.startsWith('ECDSA-') || item.keyObj.isDummy) {
    return showToast(t('toast_p12_ecc_unsupported'), 'error');
  }
  
  const password = prompt(t('prompt_p12_pass'), "123456");
  if (password === null) return;

  try {
    let certChain = [item.certObj];
    let current = item;
    const visited = new Set([item.id]);
    while (current && current.issuerId && !visited.has(current.issuerId)) {
      visited.add(current.issuerId);
      current = store.find(i => i.id === current.issuerId);
      if (current && current.certObj) certChain.push(current.certObj);
    }

    const newP12Asn1 = forge.pkcs12.toPkcs12Asn1(item.keyObj, certChain, password, { generateLocalKeyId: true, friendlyName: item.name });
    const p12Der = forge.asn1.toDer(newP12Asn1).getBytes();

    const buffer = new ArrayBuffer(p12Der.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < p12Der.length; i++) view[i] = p12Der.charCodeAt(i);

    const blob = new Blob([buffer], { type: 'application/x-pkcs12' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = item.name.replace(/[^a-zA-Z0-9._-]/g, '_') + '.p12';
    a.click();
    showToast(t('toast_p12_success'), 'success');
  } catch (err) {
    showToast(t('toast_p12_error', { err: err.message }), 'error');
  }
}

function decodePem() {
  const pem = document.getElementById('dec-pem').value.trim();
  const resultBox = document.getElementById('dec-result');
  const syntaxBox = document.getElementById('dec-syntax');
  resultBox.style.display = 'none';
  syntaxBox.style.display = 'none';

  if (!pem) return showToast(t('toast_dec_insert'), 'error');

  try {
    const getAttr = (attrs) => attrs.map(a => `${a.shortName || a.name}=${decodeX509AttrValue(a.value)}`).join(', ');

    if (pem.includes('BEGIN CERTIFICATE REQUEST') || pem.includes('BEGIN NEW CERTIFICATE REQUEST')) {
      const csr = safeCertificationRequestFromPem(pem);
      const algoName = detectPublicKeyAlgo(csr.publicKey);
      let validSig = t('dec_valid_pkcs10', { algo: algoName });
      try {
        if (csr.publicKey && !csr.publicKey.isDummy && typeof csr.verify === 'function') {
          validSig = csr.verify() ? t('dec_valid_sig', { algo: algoName }) : t('dec_invalid_sig');
        }
      } catch(e) {}

      let sans = t('dec_none');
      const extReq = csr.getAttribute({ name: 'extensionRequest' });
      if (extReq && extReq.extensions) {
        const sanExt = extReq.extensions.find(e => e.name === 'subjectAltName');
        if (sanExt && sanExt.altNames) {
          sans = sanExt.altNames.map(n => n.type === 7 ? n.ip : n.value).join(', ');
        }
      }

      const sub = getAttr(csr.subject.attributes) || t('dec_unknown_subject');
      resultBox.innerHTML = `
        <div class="decode-row"><div class="decode-label">${t('dec_doc_type')}</div><div class="decode-val">${t('dec_csr_doc_type')}${escapeHtml(algoName)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_csr_subject')}</div><div class="decode-val">${escapeHtml(sub)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_san_requested')}</div><div class="decode-val">${escapeHtml(sans)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_sig_integrity')}</div><div class="decode-val">${validSig}</div></div>
      `;
    } else {
      const cert = forge.pki.certificateFromPem(pem);
      const algoName = detectPublicKeyAlgo(cert.publicKey);
      const sub = getAttr(cert.subject.attributes) || t('dec_unknown_subject');
      const iss = getAttr(cert.issuer.attributes) || t('dec_unknown_issuer');

      let sans = t('dec_none');
      const sanExt = cert.getExtension('subjectAltName');
      if (sanExt && sanExt.altNames) {
        sans = sanExt.altNames.map(n => n.type === 7 ? n.ip : n.value).join(', ');
      }

      let isCA = t('dec_is_ca_no');
      const bc = cert.getExtension('basicConstraints');
      if (bc && bc.cA) isCA = t('dec_is_ca_yes');

      // Sériové číslo: primárně z DER (spolehlivé i pro ECC), fallback na forge parser
      const decSn = extractSerialFromPem(pem) || cert.serialNumber || '';
      resultBox.innerHTML = `
        <div class="decode-row"><div class="decode-label">${t('dec_cert_subject')}</div><div class="decode-val">${escapeHtml(sub)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_cert_issuer')}</div><div class="decode-val">${escapeHtml(iss)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_pubkey_algo')}</div><div class="decode-val">${escapeHtml(algoName)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_validity_range')}</div><div class="decode-val">${cert.validity.notBefore.toLocaleString()} — ${cert.validity.notAfter.toLocaleString()}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_san')}</div><div class="decode-val">${escapeHtml(sans)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_serial')}</div><div class="decode-val" style="font-family: monospace; font-size: 13px;">${formatSerialHex(decSn)}</div></div>
        <div class="decode-row"><div class="decode-label">${t('dec_is_ca')}</div><div class="decode-val">${isCA}</div></div>
      `;
    }

    resultBox.style.display = 'block';
    syntaxBox.innerHTML = highlightPem(pem);
    syntaxBox.style.display = 'block';
    showToast(t('toast_dec_success'), 'success');
  } catch (e) {
    showToast(t('toast_dec_error'), 'error');
  }
}

