// --- HLOUBKOVÝ PATCH PRO NODE-FORGE 1.3.1 (Plná podpora RSA, ECDSA P-256/P-384 a Ed25519 v X.509 a PKCS#10 CSR) ---
if (window.forge && forge.pki) {
  // 1. Parsování SubjectPublicKeyInfo (RSA + fallback pro ECDSA/Ed25519)
  const origPubFrom = forge.pki.publicKeyFromAsn1;
  if (origPubFrom) {
    forge.pki.publicKeyFromAsn1 = function(obj) {
      try {
        return origPubFrom(obj);
      } catch (e) {
        return { rawAsn1: obj, isDummy: true };
      }
    };
    if (forge.pki.rsa) forge.pki.rsa.publicKeyFromAsn1 = forge.pki.publicKeyFromAsn1;
  }

  // 2. Parsování PrivateKeyInfo (RSA + fallback pro ECDSA/Ed25519)
  const origPrivFrom = forge.pki.privateKeyFromAsn1;
  if (origPrivFrom) {
    forge.pki.privateKeyFromAsn1 = function(obj) {
      try {
        return origPrivFrom(obj);
      } catch (e) {
        return { rawAsn1: obj, isDummy: true };
      }
    };
    if (forge.pki.rsa) forge.pki.rsa.privateKeyFromAsn1 = forge.pki.privateKeyFromAsn1;
  }

  // 3. Serializace veřejného a privátního klíče do ASN.1
  const origPubTo = forge.pki.publicKeyToAsn1;
  if (origPubTo) {
    forge.pki.publicKeyToAsn1 = function(key) {
      if (key && key.rawAsn1) return key.rawAsn1;
      return origPubTo(key);
    };
    if (forge.pki.rsa) forge.pki.rsa.publicKeyToAsn1 = forge.pki.publicKeyToAsn1;
  }

  const origPrivTo = forge.pki.privateKeyToAsn1;
  if (origPrivTo) {
    forge.pki.privateKeyToAsn1 = function(key) {
      if (key && key.rawAsn1) return key.rawAsn1;
      return origPrivTo(key);
    };
    if (forge.pki.rsa) forge.pki.rsa.privateKeyToAsn1 = forge.pki.privateKeyToAsn1;
  }

  // 4. Ochrana pro publicKeyToRSAPublicKey (v node-forge je na forge.pki.publicKeyToRSAPublicKey)
  const origToRsaPub = forge.pki.publicKeyToRSAPublicKey || (forge.pki.rsa && forge.pki.rsa.publicKeyToRSAPublicKey);
  if (origToRsaPub) {
    forge.pki.publicKeyToRSAPublicKey = function(key) {
      if (key && key.rawAsn1) return key.rawAsn1;
      return origToRsaPub(key);
    };
    if (forge.pki.rsa) forge.pki.rsa.publicKeyToRSAPublicKey = forge.pki.publicKeyToRSAPublicKey;
  }

  // 5. Výpočet SHA-1 SubjectKeyIdentifier (RFC 5280 sekce 4.2.1.2) pro RSA i ECC/Ed25519
  const origGetFp = forge.pki.getPublicKeyFingerprint;
  if (origGetFp) {
    forge.pki.getPublicKeyFingerprint = function(key, options) {
      if (key && key.rawAsn1) {
        options = options || {};
        const md = options.md || forge.md.sha1.create();
        let bytes = '';
        if (key.rawAsn1.value && key.rawAsn1.value[1] && typeof key.rawAsn1.value[1].value === 'string') {
          bytes = key.rawAsn1.value[1].value.slice(1);
        } else {
          bytes = forge.asn1.toDer(key.rawAsn1).getBytes();
        }
        md.update(bytes);
        const out = md.digest();
        if (options.encoding === 'hex') {
          const hex = out.toHex();
          return options.delimiter ? hex.match(/.{2}/g).join(options.delimiter) : hex;
        }
        if (options.encoding === 'binary') return out.getBytes();
        return out;
      }
      return origGetFp(key, options);
    };
  }

  // 6. RFC 5758 & RFC 8410: ECDSA a Ed25519 nesmí mít v AlgorithmIdentifier připojený NULL parametr
  const NO_PARAM_SIG_OIDS = new Set([
    '1.2.840.10045.4.3.2', // ecdsa-with-SHA256
    '1.2.840.10045.4.3.3', // ecdsa-with-SHA384
    '1.3.101.112'          // Ed25519
  ]);

  // V node-forge 1.3.1 se metoda jmenuje getTBSCertificate (s velkým TBS!)
  const origGetTBS = forge.pki.getTBSCertificate;
  if (origGetTBS) {
    forge.pki.getTBSCertificate = forge.pki.getTbsCertificate = function(cert) {
      const tbs = origGetTBS(cert);
      if (cert && cert.siginfo && NO_PARAM_SIG_OIDS.has(cert.siginfo.algorithmOid)) {
        for (let i = 0; i < tbs.value.length; i++) {
          const node = tbs.value[i];
          if (node && node.type === forge.asn1.Type.SEQUENCE && node.value && node.value.length === 2 &&
              node.value[0].type === forge.asn1.Type.OID && node.value[1].type === forge.asn1.Type.NULL) {
            node.value.pop();
            break;
          }
        }
      }
      return tbs;
    };
  }

  const origCertToAsn1 = forge.pki.certificateToAsn1;
  if (origCertToAsn1) {
    forge.pki.certificateToAsn1 = function(cert) {
      const certAsn1 = origCertToAsn1(cert);
      if (cert && certAsn1 && NO_PARAM_SIG_OIDS.has(cert.signatureOid)) {
        const sigAlgNode = certAsn1.value[1];
        if (sigAlgNode && sigAlgNode.value && sigAlgNode.value.length === 2 &&
            sigAlgNode.value[1].type === forge.asn1.Type.NULL) {
          sigAlgNode.value.pop();
        }
      }
      return certAsn1;
    };
  }

  const origCsrToAsn1 = forge.pki.certificationRequestToAsn1;
  if (origCsrToAsn1) {
    forge.pki.certificationRequestToAsn1 = function(csr) {
      const csrAsn1 = origCsrToAsn1(csr);
      if (csr && csrAsn1 && NO_PARAM_SIG_OIDS.has(csr.signatureOid)) {
        const sigAlgNode = csrAsn1.value[1];
        if (sigAlgNode && sigAlgNode.value && sigAlgNode.value.length === 2 &&
            sigAlgNode.value[1].type === forge.asn1.Type.NULL) {
          sigAlgNode.value.pop();
        }
      }
      return csrAsn1;
    };
  }

  // 7. RFC 5280 & Apple Keychain ochrana pro Authority Key Identifier (AKI)
  // - keyIdentifier MUSÍ být přesně 20 bajtů binárních dat (160bitový SHA-1 hash), nikoliv 40 ASCII znaků hex
  // - critical MUSÍ být explicitně false
  // - Rozšíření NESMÍ obsahovat authorityCertIssuer ani authorityCertSerialNumber (v DER způsobují Apple Keychain chybu)
  const sanitizeAkiExtension = function(ext) {
    if (!ext || (ext.name !== 'authorityKeyIdentifier' && ext.id !== '2.5.29.35')) return;
    ext.critical = false;
    delete ext.authorityCertIssuer;
    delete ext.authorityCertSerialNumber;
    delete ext.serialNumber;
    if (typeof ext.keyIdentifier === 'string') {
      const cleanHex = ext.keyIdentifier.replace(/[^0-9a-fA-F]/g, '');
      if (cleanHex.length === 40 && ext.keyIdentifier.length === 40) {
        ext.keyIdentifier = forge.util.hexToBytes(cleanHex);
      }
    }
  };

  const origExtToAsn1 = forge.pki.certificateExtensionToAsn1;
  if (origExtToAsn1) {
    forge.pki.certificateExtensionToAsn1 = function(ext) {
      sanitizeAkiExtension(ext);
      return origExtToAsn1(ext);
    };
  }

  const origExtsToAsn1 = forge.pki.certificateExtensionsToAsn1;
  if (origExtsToAsn1) {
    forge.pki.certificateExtensionsToAsn1 = function(exts) {
      if (Array.isArray(exts)) {
        for (let i = 0; i < exts.length; i++) {
          sanitizeAkiExtension(exts[i]);
        }
      }
      return origExtsToAsn1(exts);
    };
  }
}

