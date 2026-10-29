// ---- I18N LOCALIZATION SYSTEM ----
const I18N = {
  cs: {
    // Navigace
    nav_keyring: "Správce klíčů",
    nav_graph: "Graf důvěry",
    nav_root: "Root CA",
    nav_inter: "Intermediate CA",
    nav_leaf: "Koncový certifikát",
    nav_csr_gen: "Vytvořit CSR",
    nav_csr: "Podepsat CSR",
    nav_cross: "Cross-Signing",
    nav_decoder: "Dekodér",
    nav_import: "Import / Záloha",

    // Sekce navigace
    nav_sec_overview: "Přehled",
    nav_sec_pki: "Vydávání certifikátů",
    nav_sec_tools: "Nástroje a správa",

    // Statistiky klíčenky
    stat_total: "Celkem položek",
    stat_ca: "Aktivní autority (CA)",
    stat_leaf: "Koncové certifikáty",
    stat_revoked: "Zneplatněné (CRL)",

    // Panel: Klíčenka
    keyring_title: "Virtuální klíčenka",
    keyring_desc: "Hlavní přehled vygenerovaných a importovaných autorit, certifikátů a klíčů.",
    keyring_alert_strong: "Lokální ukládání je aktivní",
    keyring_alert_desc: "Privátní klíče se ukládají v plaintextu do paměti tohoto prohlížeče. Pro bezpečný přenos na jiné zařízení využijte <em>Šifrovaný export zálohy</em>.",
    keyring_toggle_ls: "Ukládat klíčenku trvale v prohlížeči (LocalStorage)",
    keyring_btn_export: "Export zálohy (.json)",
    keyring_btn_clear: "Smazat vše",
    keyring_empty: "Zatím nebyly vygenerovány ani importovány žádné certifikáty.",
    keyring_issuer: "Vystavitel:",
    keyring_serial: "Sériové č.:",
    keyring_btn_view: "Zobrazit",
    keyring_btn_view_title: "Zobrazit zvýrazněný PEM",
    keyring_btn_crl_title: "Stáhnout podepsaný seznam zneplatněných certifikátů",
    keyring_btn_revoke: "Zrušit",
    keyring_btn_revoke_title: "Zneplatnit certifikát",
    badge_revoked: "REVOKOVÁNO",
    issuer_external: "Externí / Neznámý",

    // Panel: Graf
    graph_title: "Grafický pavouk (Chain of Trust)",
    graph_desc: "Vizuální reprezentace hierarchie vašich certifikátů. Křížové podpisy (Cross-Signed) se zobrazují přerušovanou čarou směrem k cílové autoritě.",
    graph_badge_leaf: "Koncový (Leaf)",
    graph_badge_revoked: "Zneplatněný (Revoked)",
    graph_empty: "Klíčenka je prázdná. Vygenerujte nejprve Root CA.",
    graph_edge_signed: "Podepsal",
    graph_edge_shares_key: "Sdílí veřejný klíč s",
    graph_render_error: "Chyba vykreslení grafu: ",

    // Panel: Root CA
    root_title: "Generátor Root CA",
    root_desc: "Nejvyšší kořenová autorita (Self-Signed). Bez ní nelze podepisovat další certifikáty.",
    field_cn: "Common Name (CN)",
    root_cn_help: "Hlavní název autority, který se zobrazí v prohlížeči uživatele.",
    field_org: "Organizace (O)",
    field_ou: "Org. jednotka (OU)",
    placeholder_not_used: "nepoužívá se",
    placeholder_optional: "Volitelné",
    field_country: "Země (C)",
    placeholder_country: "Dvoupísmenný ISO kód (CZ)",
    field_city: "Město / Lokalita (L)",
    field_algo: "Algoritmus klíče",
    algo_rsa_2048: "RSA 2048 (Rychlé, vysoká kompatibilita)",
    algo_rsa_3072: "RSA 3072 (Vyšší bezpečnost)",
    algo_rsa_4096: "RSA 4096 (Maximální bezpečnost)",
    algo_ecdsa_p256: "ECDSA P-256 (Moderní, rychlé, standard pro TLS)",
    algo_ecdsa_p384: "ECDSA P-384 (Vysoká bezpečnost)",
    algo_ed25519: "ECC Ed25519 (Velmi rychlé, moderní, horší kompatibilita)",
    root_algo_help: "Pro novou Root CA se dnes doporučuje RSA 4096, ECDSA P-384 nebo Ed25519.",
    field_validity_years: "Platnost (roky)",
    root_validity_help: "Kořenová autorita se obvykle vystavuje na velmi dlouhou dobu (10-20 let).",
    btn_gen_root: "Vygenerovat Root CA",

    // Panel: Intermediate CA
    inter_title: "Generátor Intermediate CA",
    inter_desc: "Podřízená autorita pro běžné (denní) vydávání certifikátů. Zvyšuje bezpečnost – Root CA může zůstat uložena offline.",
    field_issuer_ca: "Vystavitel (Existující CA)",
    inter_issuer_help: "Vyberte rodičovskou autoritu, která tuto Intermediate CA podepíše.",
    field_pathlen: "Max. hloubka řetězu (PathLenConstraint)",
    inter_pathlen_help: "Určuje, kolik podřízených CA může tato autorita vydat. Hodnota \"0\" znamená, že může vydávat pouze koncové (Leaf) certifikáty.",
    btn_gen_inter: "Vytvořit a podepsat Intermediate CA",

    // Panel: Leaf
    leaf_title: "Koncový certifikát (Leaf)",
    leaf_desc: "Koncový certifikát pro HTTPS weby, VPN servery, kontejnery, IoT zařízení nebo identifikaci uživatele.",
    leaf_template_label: "Rychlá šablona profilu",
    tpl_custom: "-- Vlastní nastavení (Výchozí HTTPS web) --",
    tpl_openvpn: "OpenVPN Server (Server Auth, RSA 2048, 825 dní)",
    tpl_ipsec: "IPsec / mTLS Klient (Client Auth, ECDSA P-256, 365 dní)",
    tpl_docker: "Docker Registry (Server + Client Auth, RSA 3072, 398 dní)",
    tpl_mqtt: "Smart Home MQTT Node (Server + Client, ECDSA P-256, 1095 dní)",
    tpl_codesign: "Code Signing (Podpis kódu a balíčků, RSA 4096, 365 dní)",
    leaf_template_help: "Vyberte šablonu pro automatické předvyplnění hodnot níže.",
    field_issuer_short: "Vystavitel (CA)",
    field_cn_leaf: "Common Name (CN) / Hlavní identifikátor",
    field_san: "Subject Alt Names (SAN)",
    leaf_san_help: "Domény nebo IP adresy oddělené čárkou. Moderní prohlížeče (Chrome/Edge) vyžadují platný SAN, jinak certifikát odmítnou.",
    algo_p256_common: "ECDSA P-256 (Moderní, běžné)",
    field_validity_days: "Platnost (dny)",
    leaf_validity_help: "Maximum pro veřejné HTTPS weby je dnes 398 dní.",
    field_eku: "Povolený účel použití (EKU)",
    eku_server: "Server Auth (HTTPS / TLS Server)",
    eku_client: "Client Auth (mTLS / VPN Klient)",
    eku_email: "Email Protection (S/MIME)",
    eku_code: "Code Signing (Podpis SW)",
    leaf_eku_help: "Definuje, k jakému účelu smí operační systém tento certifikát technicky použít. (Pozn.: Key Usage atribut 'Key Encipherment' je vyžadován a nastavován pouze u RSA klíčů, pro ECDSA/Ed25519 se aplikuje čistý Digital Signature).",
    btn_gen_leaf: "Vystavit koncový certifikát",

    // Panel: CSR Generátor
    csr_gen_title: "Generátor žádosti o certifikát (CSR)",
    csr_gen_desc: "Vygenerujte nový privátní klíč a odpovídající žádost o podpis (PKCS#10 CSR) pro externí certifikační autoritu nebo pro otestování v sekci Podepsat CSR.",
    field_cn_csr_gen: "Common Name (CN) / Hlavní doména",
    csr_gen_cn_help: "Plně kvalifikované doménové jméno (FQDN) serveru nebo jméno subjektu.",
    csr_gen_san_help: "Všechny domény a IP adresy (oddělené čárkou), pro které má budoucí certifikát platit.",
    csr_gen_algo_help: "Vybere kryptografický algoritmus, kterým se vygeneruje pár klíčů a následně podepíše samotná CSR žádost.",
    btn_gen_csr: "Vygenerovat klíč a CSR žádost",
    cg_out_heading: "Výstup: Vygenerované soubory",
    cg_out_desc: "Privátní klíč (<code>.key</code>) uložte bezpečně na váš server. Soubor žádosti (<code>.csr</code>) předejte certifikační autoritě k podpisu.",
    btn_send_csr_sign: "Rovnou přenést k podpisu do sekce Podepsat CSR",
    btn_send_csr_dec: "Zkontrolovat v Dekodéru",
    label_out_csr: "Žádost o podpis (.CSR)",
    label_out_key: "Serverový privátní klíč (.KEY)",
    btn_copy: "Kopírovat",
    btn_dl_csr: "Stáhnout .CSR",
    btn_dl_key: "Stáhnout .KEY",

    // Panel: Podepsat CSR
    csr_sign_title: "Podepsání žádosti o certifikát (CSR)",
    csr_sign_desc: "Podepište certifikát pro zařízení, ke kterému nemáte (nebo nesmíte mít) privátní klíč. Zařízení vám dodá pouze soubor <code>.csr</code>.",
    drop_csr: "Přetáhněte soubor .csr nebo .pem sem",
    drop_or_browse: "nebo klikněte pro výběr z disku",
    label_csr_pem: "Obsah CSR žádosti (PEM formát)",
    csr_review_title: "Revize atributů před podpisem",
    field_sign_by_ca: "Podepsat autoritou (CA)",
    field_cn_from_csr: "Common Name (CN) z CSR",
    field_new_validity_days: "Nová platnost (dny)",
    placeholder_csr_san: "Domény nebo IP adresy oddělené čárkou",
    csr_san_help: "Vyčteno ze žádosti. Můžete zde přidat nebo smazat domény, které certifikátu skutečně povolíte.",
    field_csr_eku: "Účel použití (EKU)",
    btn_sign_csr: "Zpracovat CSR a vystavit certifikát",

    // Panel: Cross-Signing
    cross_title: "Cross-Signing (Křížové podepsání)",
    cross_desc: "Křížové podepsání umožní zachovat původní klíč autority, ale zajistí jí důvěru přes jinou, existující (např. starší) Root CA. Slouží často pro plynulý přechod na nové klíče, aniž by stará zařízení ztratila důvěru.",
    field_target_ca: "Cílová CA (Komu zachovat identitu)",
    field_new_issuer: "Nový Vystavitel (Kdo poskytne podpis)",
    field_new_validity_years: "Nová platnost (roky)",
    btn_gen_cross: "Vytvořit křížový podpis",

    // Panel: Dekodér
    decoder_title: "Inspektor Certifikátů & CSR",
    decoder_desc: "Rychlý náhled do obsahu libovolného certifikátu nebo žádosti. Veškeré dekódování probíhá čistě lokálně ve vašem prohlížeči, data se nikam neposílají.",
    drop_decoder: "Přetáhněte soubor .crt, .pem nebo .csr sem",
    drop_decoder_click: "nebo klikněte pro výběr",
    label_dec_pem: "PEM Certifikát nebo CSR k dekódování",
    btn_decode: "Dekódovat a rozebrat obsah",
    dec_doc_type: "Typ dokumentu",
    dec_csr_doc_type: "PKCS#10 Žádost o certifikát (CSR) — ",
    dec_csr_subject: "Subjekt (Žadatel)",
    dec_san_requested: "Požadované domény a IP (SAN)",
    dec_sig_integrity: "Integrita podpisu",
    dec_valid_pkcs10: "Platná struktura PKCS#10 ({algo})",
    dec_valid_sig: "Platný podpis žádosti ({algo})",
    dec_invalid_sig: "Neplatný podpis",
    dec_cert_subject: "Subjekt (Komu patří)",
    dec_cert_issuer: "Vystavitel (Kdo jej vydal)",
    dec_pubkey_algo: "Algoritmus veřejného klíče",
    dec_validity_range: "Platnost Od — Do",
    dec_san: "Domény a IP (SAN)",
    dec_serial: "Sériové číslo (HEX)",
    dec_is_ca: "Je Autorita (CA)?",
    dec_is_ca_no: "Ne (End-Entity / Leaf)",
    dec_is_ca_yes: "Ano (Certifikační Autorita)",
    dec_none: "Žádné",
    dec_unknown_subject: "Neznámý subjekt",
    dec_unknown_issuer: "Neznámý vystavitel",

    // Panel: Import & Záloha
    import_title: "Import PEM & Šifrovaná záloha klíčenky",
    import_desc: "Přidejte existující certifikáty (např. od Let's Encrypt nebo vaší firemní autority) do aplikace, nebo zálohujte celý aktuální stav rozpracovaného projektu.",
    import_h4_1: "1. Import externího PEM certifikátu a klíče",
    drop_imp: "Přetáhněte soubor .pem, .crt nebo .key sem",
    drop_imp_hint: "(lze vložit i spojený certifikát s privátním klíčem najednou)",
    label_imp_content: "Obsah souboru (PEM blok)",
    btn_imp_cert: "Importovat certifikát do klíčenky",
    import_h4_2: "2. Šifrovaná záloha celé aplikace",
    import_backup_desc: "Stáhněte kompletní strom klíčenky do jednoho <code>.json</code> souboru chráněného silným heslem (šifrováno lokálně pomocí AES-256-GCM). Lze následně otevřít na libovolném jiném zařízení. <b>Import ze zálohy nahradí veškerá dosavadní uložená data!</b>",
    btn_export_ws: "Exportovat zálohu",
    btn_restore_ws: "Obnovit ze zálohy",

    // Modal
    modal_preview_title: "Náhled PEM",
    modal_btn_copy: "Kopírovat kód",
    modal_btn_close: "Zavřít",
    modal_title_cert: "Certifikát: {name}",
    modal_title_key: "Privátní klíč: {name}",

    // Toasty a dialogy
    toast_no_privkey: "Tento certifikát nemá uložený privátní klíč.",
    toast_pem_copied: "PEM blok zkopírován do schránky!",
    toast_copied: "Zkopírováno do schránky!",
    toast_csr_copied: "CSR zkopírováno do schránky!",
    toast_key_copied: "Privátní klíč zkopírován do schránky!",
    toast_file_loaded: "Soubor \"{name}\" úspěšně načten.",
    toast_ls_on: "Trvalé ukládání do LocalStorage zapnuto.",
    toast_ls_off: "LocalStorage vymazán a vypnut.",
    confirm_clear_store: "Opravdu smazat celou klíčenku? Ztratíte všechny certifikáty a privátní klíče.",
    toast_store_cleared: "Klíčenka byla kompletně vymazána.",
    ca_select_empty: "-- Nejprve vytvořte platnou CA s klíčem --",
    toast_root_generating: "Generuji klíče ({algo}) a sestavuji Root CA...",
    toast_root_created: "Root CA \"{name}\" ({algo}) úspěšně vygenerována!",
    toast_root_error: "Chyba při generování Root CA: {err}",
    toast_select_issuer: "Nejprve vyberte vystavující CA!",
    toast_inter_generating: "Generuji Intermediate CA ({algo})...",
    toast_inter_created: "Intermediate CA \"{name}\" podepsána autoritou {issuer}!",
    toast_error: "Chyba: {err}",
    toast_template_applied: "Šablona profilu předvyplněna.",
    toast_leaf_generating: "Vystavuji koncový certifikát ({algo})...",
    toast_leaf_created: "Koncový certifikát \"{name}\" úspěšně vystaven!",
    toast_csr_generating: "Generuji pár klíčů ({algo}) a sestavuji CSR...",
    toast_csr_created: "CSR žádost a privátní klíč ({algo}) pro \"{name}\" byly úspěšně vygenerovány!",
    toast_csr_error: "Chyba při generování CSR: {err}",
    toast_csr_downloaded: "Soubor {name}.csr stažen.",
    toast_key_downloaded: "Privátní klíč {name}.key stažen.",
    toast_csr_loaded: "CSR žádost úspěšně načtena k revizi.",
    toast_csr_parse_error: "Nelze naparsovat CSR: {err}",
    toast_csr_insert_first: "Nejprve vložte platné CSR!",
    toast_csr_verify_failed: "CSR má neplatný vlastní podpis (Proof of Possession selhává)! Certifikát nevydán.",
    toast_csr_signed: "Certifikát z CSR \"{name}\" byl podepsán a uložen do klíčenky!",
    toast_csr_sign_error: "Chyba při podepisování CSR: {err}",
    toast_cross_select_both: "Vyberte cílovou CA a nového vystavitele!",
    toast_cross_same_error: "Cílová CA a Vystavitel nesmí být stejní!",
    toast_cross_created: "Autorita \"{target}\" křížově podepsána vystavitelem \"{issuer}\"!",
    toast_cross_error: "Chyba Cross-Signingu: {err}",
    confirm_revoke: "Opravdu zneplatnit (revokovat) certifikát \"{name}\"?",
    toast_revoked: "Certifikát \"{name}\" byl zneplatněn.",
    toast_crl_no_key: "CA nemá privátní klíč pro podpis CRL!",
    toast_crl_downloaded: "CRL seznam pro \"{name}\" stažen ({count} zneplatněných certifikátů).",
    toast_crl_error: "Chyba při generování CRL: {err}",
    toast_imp_insert: "Vložte PEM certifikát (a volitelně klíč)!",
    toast_imp_no_cert: "V textu nebyl nalezen blok -----BEGIN CERTIFICATE-----!",
    import_default_cn: "Importovaný Certifikát",
    toast_imp_success: "Certifikát \"{name}\" ({algo}) úspěšně importován do klíčenky!",
    toast_imp_error: "Chyba při importu PEM: {err}",
    toast_export_empty: "Klíčenka je prázdná, není co exportovat.",
    prompt_export_pass: "Zadejte silné heslo pro zašifrování zálohy klíčenky (AES-256-GCM):",
    toast_export_success: "Zašifrovaná záloha klíčenky byla úspěšně stažena!",
    toast_export_error: "Chyba při šifrování zálohy: {err}",
    prompt_import_pass: "Zadejte heslo pro dešifrování souboru \"{name}\":",
    toast_restore_success: "Klíčenka úspěšně obnovena ({count} položek)!",
    toast_restore_error: "Chyba obnovy: Nesprávné heslo nebo poškozený soubor.",
    toast_restore_invalid_format: "Neplatný formát zálohy: Soubor neobsahuje povinná pole (salt, iv, data).",
    toast_restore_invalid_json: "Chyba při čtení zálohy: Soubor není platný JSON.",
    confirm_app_version_mismatch: "Upozornění: Soubor pochází z jiné verze nebo aplikace ('{app}'). Aktuálně používáte: '{expected}'. Chcete přesto pokračovat v importu?",
    app_version_unknown: "Neznámá",
    toast_chain_downloaded: "Celý řetězec důvěry (Chain PEM) byl stažen.",
    toast_p12_ecc_unsupported: "Export PKCS#12 pro ECC klíče není lokálně podporován. Použijte stažené .CRT a .KEY soubory.",
    prompt_p12_pass: "Zadejte heslo pro exportovaný .p12 (.pfx) kontejner:",
    toast_p12_success: "Kontejner PKCS#12 (.p12) úspěšně vygenerován.",
    toast_p12_error: "Chyba při exportu P12: {err}",
    toast_dec_insert: "Vložte nebo přetáhněte PEM soubor!",
    toast_dec_success: "PEM blok úspěšně dekódován.",
    toast_dec_error: "Chyba dekódování: Ujistěte se, že jde o platný PEM certifikát nebo CSR."
  },
  en: {
    // Navigation
    nav_keyring: "Key Manager",
    nav_graph: "Trust Graph",
    nav_root: "Root CA",
    nav_inter: "Intermediate CA",
    nav_leaf: "Leaf Certificate",
    nav_csr_gen: "Create CSR",
    nav_csr: "Sign CSR",
    nav_cross: "Cross-Signing",
    nav_decoder: "Decoder",
    nav_import: "Import / Backup",

    // Navigation sections
    nav_sec_overview: "Overview",
    nav_sec_pki: "Certificate Issuance",
    nav_sec_tools: "Tools & Operations",

    // Keyring stats
    stat_total: "Total Items",
    stat_ca: "Active Authorities (CA)",
    stat_leaf: "End-Entity Leafs",
    stat_revoked: "Revoked (CRL)",

    // Panel: Keyring
    keyring_title: "Virtual Keyring",
    keyring_desc: "Main overview of generated and imported authorities, certificates, and keys.",
    keyring_alert_strong: "Local storage is active",
    keyring_alert_desc: "Private keys are stored in plaintext directly in this browser's memory. For secure transfer to another device, use <em>Encrypted Backup Export</em>.",
    keyring_toggle_ls: "Store keyring permanently in browser (LocalStorage)",
    keyring_btn_export: "Export Backup (.json)",
    keyring_btn_clear: "Clear All",
    keyring_empty: "No certificates have been generated or imported yet.",
    keyring_issuer: "Issuer:",
    keyring_serial: "Serial No.:",
    keyring_btn_view: "View",
    keyring_btn_view_title: "View highlighted PEM",
    keyring_btn_crl_title: "Download signed Certificate Revocation List",
    keyring_btn_revoke: "Revoke",
    keyring_btn_revoke_title: "Revoke certificate",
    badge_revoked: "REVOKED",
    issuer_external: "External / Unknown",

    // Panel: Trust Graph
    graph_title: "Trust Graph (Chain of Trust)",
    graph_desc: "Visual representation of your certificate hierarchy. Cross-signatures are displayed with a dashed line towards the target authority.",
    graph_badge_leaf: "End-Entity (Leaf)",
    graph_badge_revoked: "Revoked",
    graph_empty: "Keyring is empty. Please generate a Root CA first.",
    graph_edge_signed: "Signed",
    graph_edge_shares_key: "Shares public key with",
    graph_render_error: "Graph rendering error: ",

    // Panel: Root CA
    root_title: "Root CA Generator",
    root_desc: "Top-level root authority (Self-Signed). Required to sign subordinate certificates.",
    field_cn: "Common Name (CN)",
    root_cn_help: "Main authority name displayed in the user's browser.",
    field_org: "Organization (O)",
    field_ou: "Organizational Unit (OU)",
    placeholder_not_used: "not used",
    placeholder_optional: "Optional",
    field_country: "Country (C)",
    placeholder_country: "Two-letter ISO code",
    field_city: "City / Region (L)",
    field_algo: "Key Algorithm",
    algo_rsa_2048: "RSA 2048 (Fast, legacy standard, universal compatibility)",
    algo_rsa_3072: "RSA 3072 (Higher security)",
    algo_rsa_4096: "RSA 4096 (Very high security)",
    algo_ecdsa_p256: "ECDSA P-256 (Modern, fast, web standard)",
    algo_ecdsa_p384: "ECDSA P-384 (Modern, very high security)",
    algo_ed25519: "ECC Ed25519 (Extremely fast, modern, worse compatibility)",
    root_algo_help: "For a new Root CA, RSA 4096, ECDSA P-384 or Ed25519 is recommended today.",
    field_validity_years: "Validity (years)",
    root_validity_help: "Root authority is usually issued for a very long period (10-20 years).",
    btn_gen_root: "Generate Root CA",

    // Panel: Intermediate CA
    inter_title: "Intermediate CA Generator",
    inter_desc: "Subordinate authority for day-to-day certificate issuance. Enhances security – Root CA can remain stored offline.",
    field_issuer_ca: "Issuer (Existing CA)",
    inter_issuer_help: "Select the parent authority that will sign this Intermediate CA.",
    field_pathlen: "Max Path Depth (PathLenConstraint)",
    inter_pathlen_help: "Specifies how many subordinate CAs this authority can issue. Value \"0\" means it can only issue leaf certificates.",
    btn_gen_inter: "Create and Sign Intermediate CA",

    // Panel: Leaf
    leaf_title: "Leaf Certificate (End-Entity)",
    leaf_desc: "End-entity certificate for HTTPS websites, VPN servers, containers, IoT devices, or user identification.",
    leaf_template_label: "Quick Profile Template",
    tpl_custom: "-- Custom Settings (Default HTTPS Web) --",
    tpl_openvpn: "OpenVPN Server (Server Auth, RSA 2048, 825 days)",
    tpl_ipsec: "IPsec / mTLS Client (Client Auth, ECDSA P-256, 365 days)",
    tpl_docker: "Docker Registry (Server + Client Auth, RSA 3072, 398 days)",
    tpl_mqtt: "Smart Home MQTT Node (Server + Client, ECDSA P-256, 1095 days)",
    tpl_codesign: "Code Signing (Code and package signing, RSA 4096, 365 days)",
    leaf_template_help: "Select a template to auto-populate the values below.",
    field_issuer_short: "Issuer (CA)",
    field_cn_leaf: "Common Name (CN) / Primary Identifier",
    field_san: "Subject Alt Names (SAN)",
    leaf_san_help: "Comma-separated domains or IP addresses. Modern browsers require valid SAN, otherwise the certificate will be rejected.",
    algo_p256_common: "ECDSA P-256 (Modern, common)",
    field_validity_days: "Validity (days)",
    leaf_validity_help: "The maximum validity for public HTTPS websites is currently 398 days.",
    field_eku: "Allowed Purpose of Use (EKU)",
    eku_server: "Server Auth (HTTPS / TLS Server)",
    eku_client: "Client Auth (mTLS / VPN Client)",
    eku_email: "Email Protection (S/MIME)",
    eku_code: "Code Signing (Software Signing)",
    leaf_eku_help: "Defines what purpose the operating system technically permits this certificate for. (Note: Key Usage attribute 'Key Encipherment' is only required and configured for RSA keys; for ECDSA/Ed25519 only Digital Signature applies).",
    btn_gen_leaf: "Issue Leaf Certificate",

    // Panel: CSR Generator
    csr_gen_title: "Certificate Signing Request (CSR) Generator",
    csr_gen_desc: "Generate a new private key and corresponding signing request (PKCS#10 CSR) for an external CA or to test in the Sign CSR section.",
    field_cn_csr_gen: "Common Name (CN) / Main Domain",
    csr_gen_cn_help: "Fully qualified domain name (FQDN) of the server or subject name.",
    csr_gen_san_help: "All domains and IP addresses (comma-separated) for which the certificate should be valid.",
    csr_gen_algo_help: "Selects cryptographic algorithm used to generate key pair and sign the CSR request itself.",
    btn_gen_csr: "Generate Key and CSR Request",
    cg_out_heading: "Output: Generated Files",
    cg_out_desc: "Store private key (<code>.key</code>) securely on your server. Submit request file (<code>.csr</code>) to certificate authority for signing.",
    btn_send_csr_sign: "Transfer directly to Sign CSR section",
    btn_send_csr_dec: "Inspect in Decoder",
    label_out_csr: "Signing Request (.CSR)",
    label_out_key: "Server Private Key (.KEY)",
    btn_copy: "Copy",
    btn_dl_csr: "Download .CSR",
    btn_dl_key: "Download .KEY",

    // Panel: Sign CSR
    csr_sign_title: "Certificate Signing Request (CSR) Signing",
    csr_sign_desc: "Sign a certificate for a device when you do not (or must not) possess the private key. The device only provides a <code>.csr</code> file.",
    drop_csr: "Drag & drop .csr or .pem file here",
    drop_or_browse: "or click to browse from disk",
    label_csr_pem: "CSR Request Content (PEM format)",
    csr_review_title: "Attribute Review Before Signing",
    field_sign_by_ca: "Sign with Authority (CA)",
    field_cn_from_csr: "Common Name (CN) from CSR",
    field_new_validity_days: "New Validity (days)",
    placeholder_csr_san: "Comma-separated domains or IP addresses",
    csr_san_help: "Extracted from request. You can add or remove domains that will actually be permitted for the certificate.",
    field_csr_eku: "Purpose of Use (EKU)",
    btn_sign_csr: "Process CSR and Issue Certificate",

    // Panel: Cross-Signing
    cross_title: "Cross-Signing",
    cross_desc: "Cross-signing preserves the original authority key while establishing trust through another existing (e.g. older) Root CA. Frequently used for smooth migration to new keys without breaking trust on legacy devices.",
    field_target_ca: "Target CA (Identity to preserve)",
    field_new_issuer: "New Issuer (Signer)",
    field_new_validity_years: "New Validity (years)",
    btn_gen_cross: "Create Cross-Signature",

    // Panel: Decoder
    decoder_title: "Certificate & CSR Inspector",
    decoder_desc: "Quick inspection of any certificate or request. All decoding happens strictly locally in your browser; no data is transmitted.",
    drop_decoder: "Drag & drop .crt, .pem, or .csr file here",
    drop_decoder_click: "or click to browse",
    label_dec_pem: "PEM Certificate or CSR to Decode",
    btn_decode: "Decode and Inspect Content",
    dec_doc_type: "Document Type",
    dec_csr_doc_type: "PKCS#10 Certificate Request (CSR) — ",
    dec_csr_subject: "Subject (Applicant)",
    dec_san_requested: "Requested Domains and IPs (SAN)",
    dec_sig_integrity: "Signature Integrity",
    dec_valid_pkcs10: "Valid PKCS#10 structure ({algo})",
    dec_valid_sig: "Valid request signature ({algo})",
    dec_invalid_sig: "Invalid signature",
    dec_cert_subject: "Subject (Owner)",
    dec_cert_issuer: "Issuer (Issued by)",
    dec_pubkey_algo: "Public Key Algorithm",
    dec_validity_range: "Validity From — To",
    dec_san: "Domains and IPs (SAN)",
    dec_serial: "Serial Number (HEX)",
    dec_is_ca: "Is Certificate Authority (CA)?",
    dec_is_ca_no: "No (End-Entity / Leaf)",
    dec_is_ca_yes: "Yes (Certificate Authority)",
    dec_none: "None",
    dec_unknown_subject: "Unknown subject",
    dec_unknown_issuer: "Unknown issuer",

    // Panel: Import & Backup
    import_title: "PEM Import & Encrypted Keyring Backup",
    import_desc: "Add existing certificates (e.g. Let's Encrypt or corporate CA) to the application, or back up the current project state.",
    import_h4_1: "1. Import External PEM Certificate and Key",
    drop_imp: "Drag & drop .pem, .crt, or .key file here",
    drop_imp_hint: "(combined certificate and private key can also be dropped)",
    label_imp_content: "File Content (PEM block)",
    btn_imp_cert: "Import Certificate to Keyring",
    import_h4_2: "2. Encrypted Workspace Backup",
    import_backup_desc: "Download complete keyring tree into a single password-protected <code>.json</code> file (encrypted locally using AES-256-GCM). Can subsequently be opened on any other device. <b>Importing from a backup will replace all currently saved data!</b>",
    btn_export_ws: "Export Backup",
    btn_restore_ws: "Restore Backup",

    // Modal
    modal_preview_title: "PEM Preview",
    modal_btn_copy: "Copy Code",
    modal_btn_close: "Close",
    modal_title_cert: "Certificate: {name}",
    modal_title_key: "Private Key: {name}",

    // Toasts & Dialogs
    toast_no_privkey: "This certificate does not have a stored private key.",
    toast_pem_copied: "PEM block copied to clipboard!",
    toast_copied: "Copied to clipboard!",
    toast_csr_copied: "CSR copied to clipboard!",
    toast_key_copied: "Private key copied to clipboard!",
    toast_file_loaded: "File \"{name}\" successfully loaded.",
    toast_ls_on: "Permanent LocalStorage persistence enabled.",
    toast_ls_off: "LocalStorage cleared and disabled.",
    confirm_clear_store: "Really delete entire keyring? You will lose all certificates and private keys.",
    toast_store_cleared: "Keyring has been completely wiped.",
    ca_select_empty: "-- Please create a valid CA with private key first --",
    toast_root_generating: "Generating keys ({algo}) and building Root CA...",
    toast_root_created: "Root CA \"{name}\" ({algo}) successfully generated!",
    toast_root_error: "Error generating Root CA: {err}",
    toast_select_issuer: "Please select issuing CA first!",
    toast_inter_generating: "Generating Intermediate CA ({algo})...",
    toast_inter_created: "Intermediate CA \"{name}\" signed by authority {issuer}!",
    toast_error: "Error: {err}",
    toast_template_applied: "Profile template prefilled.",
    toast_leaf_generating: "Issuing leaf certificate ({algo})...",
    toast_leaf_created: "Leaf certificate \"{name}\" successfully issued!",
    toast_csr_generating: "Generating key pair ({algo}) and building CSR...",
    toast_csr_created: "CSR request and private key ({algo}) for \"{name}\" were successfully generated!",
    toast_csr_error: "Error generating CSR: {err}",
    toast_csr_downloaded: "File {name}.csr downloaded.",
    toast_key_downloaded: "Private key {name}.key downloaded.",
    toast_csr_loaded: "CSR request successfully loaded for review.",
    toast_csr_parse_error: "Cannot parse CSR: {err}",
    toast_csr_insert_first: "Please insert valid CSR first!",
    toast_csr_verify_failed: "CSR has invalid self-signature (Proof of Possession failed)! Certificate not issued.",
    toast_csr_signed: "Certificate from CSR \"{name}\" was signed and saved to keyring!",
    toast_csr_sign_error: "Error signing CSR: {err}",
    toast_cross_select_both: "Please select target CA and new issuer!",
    toast_cross_same_error: "Target CA and Issuer cannot be the same!",
    toast_cross_created: "Authority \"{target}\" cross-signed by issuer \"{issuer}\"!",
    toast_cross_error: "Cross-signing error: {err}",
    confirm_revoke: "Really revoke certificate \"{name}\"?",
    toast_revoked: "Certificate \"{name}\" was revoked.",
    toast_crl_no_key: "CA has no private key to sign CRL!",
    toast_crl_downloaded: "CRL for \"{name}\" downloaded ({count} revoked certificates).",
    toast_crl_error: "Error generating CRL: {err}",
    toast_imp_insert: "Please insert PEM certificate (and optional key)!",
    toast_imp_no_cert: "Block -----BEGIN CERTIFICATE----- was not found in text!",
    import_default_cn: "Imported Certificate",
    toast_imp_success: "Certificate \"{name}\" ({algo}) successfully imported to keyring!",
    toast_imp_error: "Error importing PEM: {err}",
    toast_export_empty: "Keyring is empty, nothing to export.",
    prompt_export_pass: "Enter a strong password to encrypt keyring backup (AES-256-GCM):",
    toast_export_success: "Encrypted keyring backup successfully downloaded!",
    toast_export_error: "Error encrypting backup: {err}",
    prompt_import_pass: "Enter password to decrypt file \"{name}\":",
    toast_restore_success: "Keyring successfully restored ({count} items)!",
    toast_restore_error: "Restore error: Incorrect password or corrupted file.",
    toast_restore_invalid_format: "Invalid backup format: File is missing required fields (salt, iv, data).",
    toast_restore_invalid_json: "Error reading backup: File is not valid JSON.",
    confirm_app_version_mismatch: "Warning: The file comes from a different version or application ('{app}'). You are using: '{expected}'. Do you still want to proceed with the import?",
    app_version_unknown: "Unknown",
    toast_chain_downloaded: "Complete trust chain (Chain PEM) downloaded.",
    toast_p12_ecc_unsupported: "PKCS#12 export for ECC keys is not locally supported. Use downloaded .CRT and .KEY files.",
    prompt_p12_pass: "Enter password for exported .p12 (.pfx) container:",
    toast_p12_success: "PKCS#12 (.p12) container successfully generated.",
    toast_p12_error: "Error exporting P12: {err}",
    toast_dec_insert: "Please paste or drop a PEM file!",
    toast_dec_success: "PEM block successfully decoded.",
    toast_dec_error: "Decoding error: Ensure this is a valid PEM certificate or CSR."
  }
};

let currentLang = 'cs';

function t(key, params) {
  const dict = I18N[currentLang] || I18N['cs'] || {};
  let str = dict[key] !== undefined ? dict[key] : ((I18N['cs'] && I18N['cs'][key]) !== undefined ? I18N['cs'][key] : key);
  if (params && typeof params === 'object') {
    for (const k in params) {
      str = str.replace(new RegExp(`\\{${k}\\}`, 'g'), params[k]);
    }
  }
  return str;
}

function setLanguage(lang) {
  if (!I18N[lang]) lang = 'cs';
  currentLang = lang;
  try {
    localStorage.setItem('pki_lang', lang);
  } catch (e) {}

  document.documentElement.lang = lang;

  const csOpt = document.getElementById('lang-opt-cs');
  const enOpt = document.getElementById('lang-opt-en');
  if (csOpt && enOpt) {
    if (lang === 'cs') {
      csOpt.classList.add('active');
      enOpt.classList.remove('active');
    } else {
      csOpt.classList.remove('active');
      enOpt.classList.add('active');
    }
  }

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const val = t(key);
    if (val !== undefined) {
      if (val.includes('<') && val.includes('>')) {
        el.innerHTML = val;
      } else {
        el.textContent = val;
      }
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    const val = t(key);
    if (val !== undefined) el.placeholder = val;
  });

  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    const val = t(key);
    if (val !== undefined) el.title = val;
  });

  updateCaSelects();
  renderKeyring();
  const activePanel = document.querySelector('.panel.active');
  if (activePanel && activePanel.id === 'panel-graph') {
    renderGraph();
  }
  if (activePanel && activePanel.id === 'panel-decoder') {
    const resultBox = document.getElementById('dec-result');
    if (resultBox && resultBox.style.display !== 'none') {
      decodePem();
    }
  }
}

function toggleLanguage() {
  setLanguage(currentLang === 'cs' ? 'en' : 'cs');
}

function initLanguage() {
  let savedLang = 'cs';
  try {
    savedLang = localStorage.getItem('pki_lang') || 'cs';
  } catch (e) {}
  setLanguage(savedLang);
}
