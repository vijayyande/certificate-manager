"use strict";

const SYSTEM_MANAGED_OIDS = [
    "2.5.29.14",
    "2.5.29.15",
    "2.5.29.17",
    "2.5.29.19",
    "2.5.29.31",
    "2.5.29.37",
    "1.3.6.1.5.5.7.1.1"
];

const App = {
    token: null,
    user: null,
    roles: [],
    activeCaList: [],
    allCaList: [],
    cryptoCatalog: [],

    init() {
        const saved = localStorage.getItem("cm-auth");
        if (saved) {
            try {
                const data = JSON.parse(saved);
                this.token = data.token;
                this.user = data.user;
                document.getElementById("currentUser").textContent = this.user;
                this.showApp();
                this.loadCurrentUser().then(() => this.refreshAll());
            } catch (e) {
                this.showLogin();
            }
        } else {
            this.showLogin();
        }
        this.bindEvents();
        this.loadCryptoCatalog();
    },

    async loadCurrentUser() {
        try {
            const me = await this.api("/api/me");
            this.roles = me.roles || [];
        } catch (e) {
            this.roles = [];
        }
        this.applyRoleVisibility();
    },

    applyRoleVisibility() {
        const isAdmin = this.roles.includes("ADMIN");
        document.querySelectorAll(".settings-link, .cas-link, .profiles-link, .audit-link, .users-link").forEach(el =>
            el.classList.toggle("hidden", !isAdmin));
        const newCaBtn = document.getElementById("newCaBtn");
        if (newCaBtn) {
            newCaBtn.classList.toggle("hidden", !isAdmin);
        }
        const blocked = [];
        if (!isAdmin) {
            blocked.push("tab-settings", "tab-cas", "tab-profiles", "tab-audit", "tab-users");
        }
        const activeTab = document.querySelector(".tab.active");
        if (activeTab && blocked.includes(activeTab.id)) {
            document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            document.querySelector('.nav-link[data-tab="dashboard"]').classList.add("active");
            document.getElementById("tab-dashboard").classList.add("active");
        }
    },

    authHeader() {
        return this.token ? { "Authorization": "Basic " + this.token } : {};
    },

    async api(path, options = {}) {
        const res = await fetch(path, {
            ...options,
            headers: { "Content-Type": "application/json", ...this.authHeader(), ...(options.headers || {}) }
        });
        const contentType = res.headers.get("content-type") || "";
        if (!res.ok) {
            let msg = "Request failed (" + res.status + ")";
            try {
                const data = await res.json();
                msg = data.message || msg;
            } catch (e) { /* ignore */ }
            if (res.status === 401) {
                this.logout();
            }
            throw new Error(msg);
        }
        if (contentType.includes("application/json")) {
            return await res.json();
        }
        return await res.text();
    },

    showLogin() {
        document.getElementById("loginOverlay").classList.remove("hidden");
        document.getElementById("app").classList.add("hidden");
    },

    showApp() {
        document.getElementById("loginOverlay").classList.add("hidden");
        document.getElementById("app").classList.remove("hidden");
    },

    logout() {
        localStorage.removeItem("cm-auth");
        this.token = null;
        this.user = null;
        this.roles = [];
        this.showLogin();
    },

    setTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem("cm-theme", theme);
        this.updateThemeButton();
    },

    updateThemeButton() {
        const theme = document.documentElement.getAttribute("data-theme") || "dark";
        const btn = document.getElementById("themeToggle");
        if (btn) btn.textContent = theme === "light" ? "\u263E Dark mode" : "\u263D Light mode";
    },

    async login(user, pass) {
        this.token = btoa(user + ":" + pass);
        this.user = user;
        await this.api("/api/info");
        await this.loadCurrentUser();
        localStorage.setItem("cm-auth", JSON.stringify({ token: this.token, user: this.user }));
        document.getElementById("currentUser").textContent = user;
        this.showApp();
        this.refreshAll();
    },

    toast(message, type = "success") {
        const el = document.getElementById("toast");
        el.textContent = message;
        el.className = "toast " + type;
        el.classList.remove("hidden");
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => el.classList.add("hidden"), 3500);
    },

    refreshAll() {
        this.loadDashboard();
        this.loadCas();
        this.loadProfiles();
        this.loadCertificates();
        this.loadCrlHistory();
    },

    /* ---------- Dashboard ---------- */
    async loadDashboard() {
        try {
            const data = await this.api("/api/info");
            const c = data.counts;
            const cards = [
                { label: "Active CAs", value: c.casActive, cls: "primary" },
                { label: "Issued Certificates", value: c.certificatesIssued, cls: "success" },
                { label: "Pending Certificates", value: c.certificatesPending, cls: "warning" },
                { label: "Revoked Certificates", value: c.certificatesRevoked, cls: "danger" },
                { label: "Suspended Certificates", value: c.certificatesSuspended, cls: "warning" },
                { label: "Total Certificates", value: c.certificatesTotal, cls: "" },
                { label: "Total CAs", value: c.casTotal, cls: "" }
            ];
            document.getElementById("dashboardCards").innerHTML = cards.map(k =>
                `<div class="card ${k.cls}"><div class="value">${k.value}</div><div class="label">${k.label}</div></div>`
            ).join("");
            const cfg = data.config;
            document.getElementById("configList").innerHTML = [
                ["CRL distribution point base", cfg.crlUrlBase + "{caId}"],
                ["OCSP responder URL", cfg.ocspUrl]
            ].map(([k, v]) => `<div><span>${k}</span><span>${v}</span></div>`).join("");
        } catch (e) {
            this.toast(e.message, "error");
        }
    },

    /* ---------- CAs ---------- */
    async loadCas() {
        if (!this.roles.includes("ADMIN")) return;
        try {
            const list = await this.api("/api/ca");
            this.allCaList = list;
            const rows = list.map(ca => {
                const statusBadge = `<span class="badge ${ca.status}">${ca.status}</span>`;
                const typeBadge = `<span class="badge ${ca.caType}">${ca.caType}</span>`;
                const storageBadge = ca.keyStorage === "PKCS11"
                    ? `<span class="badge PKCS11" title="${escapeHtml(ca.pkcs11Alias || "token alias")}">PKCS11</span>`
                    : `<span class="badge DATABASE">Database</span>`;
                return `<tr>
                    <td>${ca.id}</td>
                    <td><strong>${escapeHtml(ca.name)}</strong></td>
                    <td>${typeBadge}</td>
                    <td>${statusBadge}</td>
                    <td>${storageBadge}</td>
                    <td title="${escapeHtml(ca.subjectDn)}">${escapeHtml(truncate(ca.subjectDn, 32))}</td>
                    <td>${ca.validTo ? fmtDate(ca.validTo) : "-"}</td>
                    <td class="actions">
                        ${ca.certificatePem ? `<button class="btn btn-sm" onclick="App.viewPem('CA certificate: ${escapeHtml(ca.name)}', '${ca.id}', 'ca')">View cert</button>` : ""}
                        ${ca.status === "ISSUED" ? `<button class="btn btn-sm btn-warning" onclick="App.suspendCa(${ca.id})">Suspend</button>
                            <button class="btn btn-sm btn-danger" onclick="App.revokeCa(${ca.id})">Revoke</button>` : ""}
                        ${ca.status === "SUSPENDED" ? `<button class="btn btn-sm btn-success" onclick="App.resumeCa(${ca.id})">Resume</button>` : ""}
                    </td>
                </tr>`;
            }).join("");
            document.getElementById("caTableBody").innerHTML = rows || emptyRow(8);
        } catch (e) {
            this.toast(e.message, "error");
        }
    },

    async viewPem(title, id, kind) {
        try {
            let pem;
            if (kind === "ca") {
                pem = await this.api("/api/ca/" + id + "/certificate.pem");
            } else {
                pem = await this.api("/api/certificates/" + id + "/pem");
            }
            document.getElementById("pemModalTitle").textContent = title;
            document.getElementById("pemContent").textContent = pem;
            this.openModal("pemModal");
        } catch (e) {
            this.toast(e.message, "error");
        }
    },

    async revokeCa(id) {
        const by = prompt("Revoke CA " + id + "? Enter your name:");
        if (!by) return;
        try {
            await this.api("/api/ca/" + id + "/revoke", { method: "POST", body: JSON.stringify({ reason: "Revoked by " + by, by: by }) });
            this.toast("CA revoked");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async suspendCa(id) {
        if (!confirm("Suspend CA " + id + "?")) return;
        try {
            await this.api("/api/ca/" + id + "/suspend", { method: "POST", body: "{}" });
            this.toast("CA suspended");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async resumeCa(id) {
        if (!confirm("Resume CA " + id + "?")) return;
        try {
            await this.api("/api/ca/" + id + "/resume", { method: "POST", body: "{}" });
            this.toast("CA resumed");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async submitCa() {
        const parentId = document.getElementById("caParent").value || null;
        const payload = {
            name: document.getElementById("caName").value.trim(),
            subjectDn: document.getElementById("caSubjectDn").value.trim(),
            caType: document.getElementById("caType").value,
            keyAlgorithm: document.getElementById("caKeyAlg").value,
            keySize: parseInt(document.getElementById("caKeySize").value),
            validityDays: parseInt(document.getElementById("caValidity").value),
            keyStorage: document.getElementById("caKeyStorage").value,
            requestedBy: this.user
        };
        if (payload.keyStorage === "PKCS11") {
            payload.pkcs11Alias = document.getElementById("caPkcs11Alias").value.trim() || null;
        }
        if (payload.caType === "INTERMEDIATE") {
            payload.parentCaId = parentId;
        }
        if (!payload.name || !payload.subjectDn) {
            this.toast("Name and Subject DN are required", "error");
            return;
        }
        try {
            await this.api("/api/ca", { method: "POST", body: JSON.stringify(payload) });
            this.closeModal("caModal");
            this.toast("CA created and activated");
            this.loadCas();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async setupCaKeyStorage() {
        document.getElementById("caPkcs11Alias").value = "";
        try {
            const s = await this.api("/api/pkcs11");
            document.getElementById("caKeyStorage").value = s.keyStorageDefault || "DATABASE";
        } catch (e) {
            document.getElementById("caKeyStorage").value = "DATABASE";
        }
        this.toggleCaPkcs11Alias();
    },

    toggleCaPkcs11Alias() {
        const pkcs11 = document.getElementById("caKeyStorage").value === "PKCS11";
        document.getElementById("caPkcs11AliasGroup").classList.toggle("hidden", !pkcs11);
    },

    /* ---------- Certificates ---------- */
    async loadCertificates() {
        try {
            const params = new URLSearchParams();
            const q = document.getElementById("certSearch").value.trim();
            const status = document.getElementById("certSearchStatus").value;
            const caId = document.getElementById("certSearchCa").value;
            if (q) params.set("q", q);
            if (status) params.set("status", status);
            if (caId) params.set("caId", caId);
            const query = params.toString();
            const list = await this.api("/api/certificates" + (query ? "?" + query : ""));
            const canManage = this.roles.includes("ADMIN");
            const rows = list.map(c => {
                const statusBadge = `<span class="badge ${c.status}">${c.status}</span>`;
                const storageBadge = c.keyStorage === "PKCS11"
                    ? `<span class="badge pkcs11">PKCS#11</span>` : `<span class="badge issued">Database</span>`;
                return `<tr>
                    <td>${c.id}</td>
                    <td><strong>${escapeHtml(c.commonName)}</strong></td>
                    <td>${statusBadge}</td>
                    <td>${c.profileName ? escapeHtml(c.profileName) : "-"}</td>
                    <td>${storageBadge}</td>
                    <td class="mono">${c.serialNumber ? serialHex(c.serialNumber) : "-"}</td>
                    <td>${c.issuerCaId ?? "-"}</td>
                    <td>${c.validTo ? fmtDate(c.validTo) : "-"}</td>
                    <td class="actions">
                        <button class="btn btn-sm" onclick="App.viewCertDetails(${c.id})">Details</button>
                        ${c.certificatePem ? `<button class="btn btn-sm" onclick="App.viewPem('Certificate: ${escapeHtml(c.commonName)}', '${c.id}', 'cert')">View cert</button> <button class="btn btn-sm" onclick="App.downloadCert(${c.id})">Download</button>` : ""}
                        ${(c.status === "ISSUED" && c.privateKeyAvailable && c.requestedBy === this.user) ? `<button class="btn btn-sm" onclick="App.downloadKey(${c.id})">Key</button>` : ""}
                        ${(canManage && (c.status === "ISSUED" || c.status === "SUSPENDED")) ? `<button class="btn btn-sm btn-danger" onclick="App.revokeCert(${c.id})">Revoke</button>` : ""}
                        ${(canManage && c.status === "ISSUED") ? `<button class="btn btn-sm btn-warning" onclick="App.suspendCert(${c.id})">Suspend</button>` : ""}
                        ${(canManage && c.status === "SUSPENDED") ? `<button class="btn btn-sm btn-success" onclick="App.resumeCert(${c.id})">Resume</button>` : ""}
                    </td>
                </tr>`;
            }).join("");
            document.getElementById("certTableBody").innerHTML = rows || emptyRow(9);
        } catch (e) {
            this.toast(e.message, "error");
        }
    },

    async viewCertDetails(id) {
        try {
            const c = await this.api("/api/certificates/" + id);
            const rows = [
                ["ID", c.id],
                ["Common name", c.commonName],
                ["Status", c.status],
                ["Subject DN", c.subjectDn],
                ["Serial", c.serialNumber],
                ["Issuing CA", c.issuerCaId ?? "-"],
                ["Profile", c.profileName || "-"],
                ["CA profile", c.caProfile ? "Yes" : "No"],
                ["Key storage", c.keyStorage],
                ["Key algorithm", c.keyAlgorithm ? c.keyAlgorithm + (c.keySize ? " (" + c.keySize + ")" : "") : "-"],
                ["Signature algorithm", c.signatureAlgorithm || "-"],
                ["Requested by", c.requestedBy || "-"],
                ["Created", fmtDate(c.createdAt)],
                ["Issued", fmtDate(c.issuedAt)],
                ["Valid from", fmtDate(c.validFrom)],
                ["Valid to", fmtDate(c.validTo)],
                ["Revoked", c.revokedAt ? fmtDate(c.revokedAt) + (c.revocationReason ? " (" + c.revocationReason + ")" : "") : "-"],
                ["Suspended", c.suspendedAt ? fmtDate(c.suspendedAt) : "-"],
                ["Key usage", (c.keyUsage || []).join(", ") || "-"],
                ["Extended key usage", (c.extendedKeyUsage || []).join(", ") || "-"],
                ["Custom extensions", (c.additionalExtensions || []).map(e => `${e.oid}: ${e.value}`).join(", ") || "-"]
            ];
            document.getElementById("certDetailsTitle").textContent =
                "Certificate / request #" + c.id + " - " + c.commonName;
            document.getElementById("certDetailsBody").innerHTML = rows
                .map(([k, v]) => `<div class="detail-row"><span class="detail-key">${escapeHtml(k)}</span><span class="detail-val">${escapeHtml(String(v))}</span></div>`)
                .join("");
            this.openModal("certDetailsModal");
        } catch (e) {
            this.toast(e.message, "error");
        }
    },

    async revokeCert(id) {
        const reason = prompt("Revoke certificate " + id + "?\nReason (KEY_COMPROMISE, SUPERSEDED, CESSATION_OF_OPERATION, ...):", "SUPERSEDED");
        if (!reason) return;
        try {
            await this.api("/api/certificates/" + id + "/revoke", { method: "POST", body: JSON.stringify({ reason: reason }) });
            this.toast("Certificate revoked");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async suspendCert(id) {
        if (!confirm("Suspend certificate " + id + "?")) return;
        try {
            await this.api("/api/certificates/" + id + "/suspend", { method: "POST" });
            this.toast("Certificate suspended");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async resumeCert(id) {
        if (!confirm("Resume certificate " + id + "?")) return;
        try {
            await this.api("/api/certificates/" + id + "/resume", { method: "POST" });
            this.toast("Certificate resumed");
            this.refreshAll();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async submitCsr() {
        const pem = document.getElementById("csrPem").value.trim();
        const issuerCaId = document.getElementById("csrIssuer").value || null;
        if (!pem) {
            this.toast("Paste a CSR in PEM format", "error");
            return;
        }
        try {
            const payload = {
                csrPem: pem,
                issuerCaId: issuerCaId,
                requestedBy: this.user
            };
            await this.api("/api/certificates/csr", { method: "POST", body: JSON.stringify(payload) });
            this.closeModal("csrModal");
            this.toast("CSR signed and issued");
            this.loadCertificates();
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- Request Certificate (manual) ---------- */
    async populateRequestForm() {
        let active = [];
        try {
            active = await this.api("/api/ca/active");
        } catch (e) {
            active = this.allCaList.filter(c => c.status === "ISSUED");
        }
        const select = document.getElementById("reqIssuer");
        select.innerHTML = active.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");

        let profiles = [];
        try {
            profiles = await this.api("/api/profiles");
        } catch (e) { profiles = []; }
        this.allProfiles = profiles;
        const pSelect = document.getElementById("reqProfile");
        const current = pSelect.value;
        pSelect.innerHTML = `<option value="">None (fill fields manually)</option>` +
            profiles.filter(p => !p.caProfile)
                .map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join("");
        pSelect.value = current;
    },

    onProfileSelect() {
        const id = document.getElementById("reqProfile").value;
        const p = (this.allProfiles || []).find(x => String(x.id) === String(id));
        const hint = document.getElementById("reqStorageHint");
        if (!p) {
            if (hint) hint.classList.add("hidden");
            return;
        }
        if (p.keyStorage === "PKCS11") {
            if (hint) {
                hint.textContent = "This profile stores the key pair on the PKCS#11 device (HSM): the private key is generated on the device at issuance and is never exportable.";
                hint.classList.remove("hidden");
            }
        } else if (hint) {
            hint.classList.add("hidden");
        }
        if (p.keyAlgorithm) {
            document.getElementById("reqKeyAlg").value = p.keyAlgorithm;
            this.renderKeySizeOptions("reqKeySize", p.keyAlgorithm);
        }
        if (p.keySize) {
            const size = document.getElementById("reqKeySize");
            if (Array.from(size.options).some(o => o.value === String(p.keySize))) {
                size.value = String(p.keySize);
            }
        }
        if (p.validityMinutes) {
            document.getElementById("reqValidityUnit").value = "minutes";
            document.getElementById("reqValidity").value = p.validityMinutes;
        } else if (p.validityDays) {
            document.getElementById("reqValidityUnit").value = "days";
            document.getElementById("reqValidity").value = p.validityDays;
        }
        this.toggleValidityUnit("reqValidity", "reqValidityUnit");
        this.toggleRequestKeySize();
        this.toast("Profile '" + p.name + "' applied as defaults");
    },

    toggleValidityUnit(inputId, unitId) {
        const unit = document.getElementById(unitId).value;
        const input = document.getElementById(inputId);
        if (unit === "minutes") {
            input.min = 1;
            input.max = 525600;
            if (parseInt(input.value, 10) > 525600) input.value = 525600;
        } else {
            input.min = 1;
            input.max = 3650;
            if (parseInt(input.value, 10) > 3650) input.value = 3650;
        }
    },

    toggleRequestKeySize() {
        this.renderKeySizeOptions("reqKeySize", document.getElementById("reqKeyAlg").value);
    },

    renderKeySizeOptions(selectId, algorithm) {
        const select = document.getElementById(selectId);
        if (!select) return null;
        const alg = algorithm || "RSA";
        const entry = (this.cryptoCatalog || []).find(a => a.name === alg);
        let options;
        if (entry) {
            options = entry.keySizeOptions.map(o => [String(o.size), o.label]);
        } else if (alg === "EC") {
            options = [["256", "P-256"], ["384", "P-384"], ["521", "P-521"]];
        } else if (alg === "ED25519") {
            options = [["256", "256 (fixed)"]];
        } else if (alg === "ED448") {
            options = [["456", "456 (fixed)"]];
        } else {
            options = [["2048", "RSA 2048"], ["3072", "RSA 3072"], ["4096", "RSA 4096"]];
        }
        const current = select.value;
        select.innerHTML = options.map(([v, l]) => `<option value="${v}">${escapeHtml(l)}</option>`).join("");
        if (options.some(([v]) => v === current)) select.value = current;
        const fixed = entry ? entry.fixedSize : (alg === "ED25519" || alg === "ED448");
        select.disabled = fixed;
        const group = select.closest(".form-group");
        if (group) group.classList.toggle("dim", fixed);
        return select;
    },

    renderKeyAlgorithmOptions(selectId) {
        const select = document.getElementById(selectId);
        if (!select || !this.cryptoCatalog || !this.cryptoCatalog.length) return select;
        const current = select.value;
        select.innerHTML = this.cryptoCatalog.map(a =>
            `<option value="${escapeHtml(a.name)}">${escapeHtml(a.label)}</option>`).join("");
        if (Array.from(select.options).some(o => o.value === current)) select.value = current;
        return select;
    },

    async loadCryptoCatalog() {
        try {
            this.cryptoCatalog = await this.api("/api/crypto/algorithms");
        } catch (e) {
            this.cryptoCatalog = [];
        }
        try {
            this.oidCatalog = await this.api("/api/crypto/oids");
        } catch (e) {
            this.oidCatalog = [];
        }
        this.prepareOidOptions();
        ["reqKeyAlg", "pKeyAlg", "caKeyAlg"].forEach(id => this.renderKeyAlgorithmOptions(id));
        this.renderKeySizeOptions("reqKeySize", document.getElementById("reqKeyAlg").value);
        this.renderKeySizeOptions("pKeySize", document.getElementById("pKeyAlg").value);
        this.renderKeySizeOptions("caKeySize", document.getElementById("caKeyAlg").value);
    },

    prepareOidOptions() {
        this.oidMap = {};
        const available = (this.oidCatalog || []).filter(o => !SYSTEM_MANAGED_OIDS.includes(o.oid));
        available.forEach(o => { this.oidMap[o.oid] = o.type; });
        this.oidSelectHtml = available.map(o =>
            `<option value="${escapeHtml(o.oid)}">${escapeHtml(o.label)} (${escapeHtml(o.oid)})</option>`
        ).join("");
    },

    addRequestExtRow(oid = "", type = "STRING", value = "") {
        this.addExtRow("reqExtRows", oid, type, value);
    },

    addExtRow(containerId, oid = "", type = "STRING", value = "") {
        const container = document.getElementById(containerId);
        const div = document.createElement("div");
        div.className = "ext-row";
        const known = oid && this.oidMap && this.oidMap[oid];
        const selected = !oid ? "" : (known ? oid : "__custom__");
        div.innerHTML = `
            <select class="ext-oid" title="Pick a well-known OID, or choose Custom OID to type one manually">
                <option value="">— choose OID —</option>
                ${this.oidSelectHtml || ""}
                <option value="__custom__">Custom OID… (type manually)</option>
            </select>
            <input class="ext-oid-custom" placeholder="1.2.3.4" value="${oid && !known ? escapeHtml(oid) : ""}" style="${oid && !known ? "" : "display:none"}">
            <select class="ext-type">
                <option value="STRING">STRING</option>
                <option value="INTEGER">INTEGER</option>
                <option value="BOOLEAN">BOOLEAN</option>
                <option value="OCTETS">OCTETS</option>
            </select>
            <input class="ext-value" placeholder="value">
            <button type="button" class="btn btn-sm btn-danger" title="Remove">&times;</button>`;
        div.querySelector(".ext-oid").value = selected;
        if (selected === "__custom__") {
            div.querySelector(".ext-oid").style.display = "none";
        }
        div.querySelector(".ext-type").value = type;
        div.querySelector(".ext-value").value = value;
        div.querySelector(".ext-oid").addEventListener("change", () => this.applyOidPreset(div));
        div.querySelector(".btn-danger").addEventListener("click", () => div.remove());
        container.appendChild(div);
    },

    applyOidPreset(row) {
        const sel = row.querySelector(".ext-oid");
        const custom = row.querySelector(".ext-oid-custom");
        if (sel.value === "__custom__") {
            sel.style.display = "none";
            custom.style.display = "";
            custom.focus();
        } else {
            custom.style.display = "none";
            sel.style.display = "";
            if (sel.value && this.oidMap && this.oidMap[sel.value]) {
                row.querySelector(".ext-type").value = this.oidMap[sel.value];
            }
        }
    },

    rowOid(row) {
        const sel = row.querySelector(".ext-oid");
        const custom = row.querySelector(".ext-oid-custom");
        if (sel.value === "__custom__" || custom.style.display !== "none") {
            return custom.value.trim();
        }
        return sel.value.trim();
    },

    requestExtensions() {
        return Array.from(document.querySelectorAll("#reqExtRows .ext-row")).map(row => ({
            oid: this.rowOid(row),
            type: row.querySelector(".ext-type").value,
            value: row.querySelector(".ext-value").value.trim()
        })).filter(e => e.oid);
    },

    async submitCertificateRequest() {
        const cn = document.getElementById("reqCn").value.trim();
        if (!cn) {
            this.toast("Common name is required", "error");
            return;
        }
        const splitList = (id) => document.getElementById(id).value.split(",")
            .map(s => s.trim()).filter(Boolean);
        const payload = {
            commonName: cn,
            organization: document.getElementById("reqO").value.trim(),
            organizationalUnit: document.getElementById("reqOu").value.trim(),
            country: document.getElementById("reqC").value.trim().toUpperCase(),
            state: document.getElementById("reqSt").value.trim(),
            locality: document.getElementById("reqL").value.trim(),
            emailAddress: document.getElementById("reqEmail").value.trim(),
            dnsNames: splitList("reqDns"),
            ipAddresses: splitList("reqIps"),
            keyAlgorithm: document.getElementById("reqKeyAlg").value,
            keySize: parseInt(document.getElementById("reqKeySize").value, 10),
            issuerCaId: document.getElementById("reqIssuer").value || null,
            requestedBy: this.user
        };
        const validityUnit = document.getElementById("reqValidityUnit").value;
        const validityValue = parseInt(document.getElementById("reqValidity").value, 10);
        if (validityUnit === "minutes") {
            payload.validityMinutes = validityValue || 60;
        } else {
            payload.validityDays = validityValue || 365;
        }
        const profileId = document.getElementById("reqProfile").value;
        if (profileId) payload.profileId = parseInt(profileId, 10);
        const ext = this.requestExtensions();
        if (ext.length) payload.additionalExtensions = ext;
        try {
            const res = await this.api("/api/certificates/request", { method: "POST", body: JSON.stringify(payload) });
            this.toast("Certificate '" + res.data.commonName + "' issued");
            document.getElementById("reqCn").value = "";
            document.getElementById("reqExtRows").innerHTML = "";
            this.loadCertificates();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async downloadCert(id) {
        try {
            const pem = await this.api("/api/certificates/" + id + "/pem");
            this.downloadBlob("cert-" + id + ".pem",
                new Blob([pem], { type: "application/x-pem-file" }));
        } catch (e) { this.toast(e.message, "error"); }
    },

    async downloadKey(id) {
        try {
            const pem = await this.api("/api/certificates/" + id + "/key");
            this.downloadBlob("private-key-" + id + ".pem",
                new Blob([pem], { type: "application/x-pem-file" }));
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- Certificate Profiles (admin) ---------- */
    async loadProfileTypes() {
        if (this.profileTypes) return;
        try {
            this.profileTypes = await this.api("/api/profiles/types");
            const sel = document.getElementById("pType");
            sel.innerHTML = this.profileTypes.map(t => {
                const code = t.code || t;
                const label = this.humanizeType(code);
                return `<option value="${escapeHtml(code)}">${escapeHtml(label)}</option>`;
            }).join("");
        } catch (e) { this.profileTypes = []; }
    },

    humanizeType(code) {
        if (!code) return "Custom";
        return code.replace(/_/g, " ").toLowerCase().replace(/^\w/, c => c.toUpperCase());
    },

    typePreset(code) {
        if (!code || code === "CUSTOM") return null;
        return (this.profileTypes || []).find(t => (t.code || t) === code) || null;
    },

    async onProfileTypeChange() {
        const code = document.getElementById("pType").value;
        const t = this.typePreset(code);
        document.getElementById("pTypeHint").textContent = t && t.description
            ? t.description
            : "Select a built-in type to auto-fill key usage, extended key usage and validity. You can still adjust individual fields.";
        if (!t) return;
        const p = {
            keyAlgorithm: t.keyAlgorithm,
            keySize: t.keySize,
            validityDays: t.validityDays,
            caProfile: t.caProfile,
            keyUsage: t.keyUsage || [],
            extendedKeyUsage: t.extendedKeyUsage || [],
            description: t.description
        };
        this.fillProfileForm(p, true);
    },

    fillProfileForm(p, preset) {
        document.getElementById("pKeyAlg").value = p.keyAlgorithm || "RSA";
        const sizeSelect = this.renderKeySizeOptions("pKeySize", p.keyAlgorithm || "RSA");
        const size = p.keySize || 2048;
        if (Array.from(sizeSelect.options).some(o => o.value === String(size))) {
            sizeSelect.value = String(size);
        }
        if (!preset && p.validityMinutes) {
            document.getElementById("pValidityUnit").value = "minutes";
            document.getElementById("pValidity").value = p.validityMinutes;
        } else {
            document.getElementById("pValidityUnit").value = "days";
            document.getElementById("pValidity").value = p.validityDays || 365;
        }
        this.toggleValidityUnit("pValidity", "pValidityUnit");
        if (preset) {
            document.getElementById("pCaProfile").checked = !!p.caProfile;
            this.setCheckboxes("pKeyUsage", p.keyUsage || []);
            this.setCheckboxes("pEku", p.extendedKeyUsage || []);
            if (p.description) document.getElementById("pDescription").value = p.description;
        }
    },

    async loadProfiles() {
        if (!this.roles.includes("ADMIN")) return;
        try {
            const list = await this.api("/api/profiles");
            this.allProfiles = list;
            const rows = list.map(p => {
                const caBadge = p.caProfile
                    ? `<span class="badge CA">CA</span>` : `<span class="badge issued">Leaf</span>`;
                const storageBadge = p.keyStorage === "PKCS11"
                    ? `<span class="badge pkcs11">PKCS#11</span>` : `<span class="badge issued">Database</span>`;
                return `<tr>
                    <td>${p.id}</td>
                    <td><strong>${escapeHtml(p.name)}</strong></td>
                    <td>${escapeHtml(p.description || "-")}</td>
                    <td>${escapeHtml(this.humanizeType(p.type || "CUSTOM"))} ${caBadge}</td>
                    <td>${escapeHtml(p.keyAlgorithm)} ${p.keySize}</td>
                    <td>${p.validityMinutes ? p.validityMinutes + " min" : p.validityDays + " days"}</td>
                    <td>${storageBadge}</td>
                    <td>${(p.keyUsage || []).join(", ") || "-"}</td>
                    <td>${(p.extendedKeyUsage || []).join(", ") || "-"}</td>
                    <td class="actions">
                        <button class="btn btn-sm" onclick="App.editProfile(${p.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="App.deleteProfile(${p.id})">Delete</button>
                    </td>
                </tr>`;
            }).join("");
            document.getElementById("profileTableBody").innerHTML = rows || emptyRow(10);
        } catch (e) { this.toast(e.message, "error"); }
    },

    openProfileModal(profile) {
        this.editingProfileId = profile ? profile.id : null;
        document.getElementById("profileModalTitle").textContent = profile ? "Edit Profile: " + profile.name : "New Certificate Profile";
        document.getElementById("pName").value = profile ? profile.name : "";
        document.getElementById("pDescription").value = profile ? (profile.description || "") : "";
        document.getElementById("pType").value = (profile && profile.type) || "CUSTOM";
        this.onProfileTypeChange();
        this.fillProfileForm(profile || {}, false);
        document.getElementById("pCaProfile").checked = profile ? !!profile.caProfile : false;
        document.getElementById("pKeyStorage").value = (profile && profile.keyStorage) || "DATABASE";
        this.setCheckboxes("pKeyUsage", (profile ? profile.keyUsage : []) || []);
        this.setCheckboxes("pEku", (profile ? profile.extendedKeyUsage : []) || []);
        document.getElementById("pExtRows").innerHTML = "";
        ((profile ? profile.additionalExtensions : []) || []).forEach(e =>
            this.addProfileExtRow(e.oid, e.type, e.value));
        this.openModal("profileModal");
    },

    async newProfile() {
        await this.loadProfileTypes();
        this.openProfileModal(null);
    },

    async editProfile(id) {
        await this.loadProfileTypes();
        const p = (this.allProfiles || []).find(x => String(x.id) === String(id));
        if (p) this.openProfileModal(p);
    },

    setCheckboxes(groupId, values) {
        const wanted = values.map(v => String(v).toLowerCase());
        document.querySelectorAll("#" + groupId + " input[type=checkbox]").forEach(cb => {
            cb.checked = wanted.includes(String(cb.value).toLowerCase());
        });
    },

    readCheckboxes(groupId) {
        return Array.from(document.querySelectorAll("#" + groupId + " input[type=checkbox]:checked"))
            .map(cb => cb.value);
    },

    addProfileExtRow(oid = "", type = "STRING", value = "") {
        this.addExtRow("pExtRows", oid, type, value);
    },

    profileExtensions() {
        return Array.from(document.querySelectorAll("#pExtRows .ext-row")).map(row => ({
            oid: this.rowOid(row),
            type: row.querySelector(".ext-type").value,
            value: row.querySelector(".ext-value").value.trim()
        })).filter(e => e.oid);
    },

    async saveProfile() {
        const name = document.getElementById("pName").value.trim();
        if (!name) {
            this.toast("Profile name is required", "error");
            return;
        }
        const payload = {
            name: name,
            description: document.getElementById("pDescription").value.trim(),
            type: document.getElementById("pType").value,
            keyAlgorithm: document.getElementById("pKeyAlg").value,
            keySize: parseInt(document.getElementById("pKeySize").value, 10) || 2048,
            caProfile: document.getElementById("pCaProfile").checked,
            keyStorage: document.getElementById("pKeyStorage").value,
            keyUsage: this.readCheckboxes("pKeyUsage"),
            extendedKeyUsage: this.readCheckboxes("pEku"),
            additionalExtensions: this.profileExtensions()
        };
        if (document.getElementById("pValidityUnit").value === "minutes") {
            payload.validityMinutes = parseInt(document.getElementById("pValidity").value, 10) || 60;
        } else {
            payload.validityDays = parseInt(document.getElementById("pValidity").value, 10) || 365;
        }
        try {
            const path = "/api/profiles" + (this.editingProfileId ? "/" + this.editingProfileId : "");
            const method = this.editingProfileId ? "PUT" : "POST";
            await this.api(path, { method: method, body: JSON.stringify(payload) });
            this.closeModal("profileModal");
            this.toast("Profile saved");
            this.loadProfiles();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async deleteProfile(id) {
        if (!confirm("Delete profile #" + id + "?")) return;
        try {
            const res = await this.api("/api/profiles/" + id, { method: "DELETE" });
            this.toast(res.message || "Profile deleted");
            this.loadProfiles();
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- PKCS#11 (admin) ---------- */
    async loadPkcs11Settings() {
        try {
            const s = await this.api("/api/pkcs11");
            document.getElementById("pkcs11Enabled").checked = !!s.enabled;
            document.getElementById("pkcs11ProviderName").value = s.providerName || "";
            document.getElementById("pkcs11Library").value = s.libraryPath || "";
            document.getElementById("pkcs11Slot").value = s.slotIndex != null ? s.slotIndex : 0;
            document.getElementById("pkcs11DefaultStorage").value = s.keyStorageDefault || "DATABASE";
            document.getElementById("pkcs11Pin").value = "";
            this.matchPkcs11Preset(s);
        } catch (e) { this.toast(e.message, "error"); }
    },

    async loadPkcs11Presets() {
        try {
            this.p11Presets = await this.api("/api/pkcs11/presets");
            const sel = document.getElementById("pkcs11Preset");
            sel.innerHTML = '<option value="">-- select a known provider to pre-fill --</option>'
                + this.p11Presets.map((p, i) => `<option value="${i}">${escapeHtml(p.name)}</option>`).join("");
            document.getElementById("pkcs11PresetLibs").innerHTML = "";
            document.getElementById("pkcs11PresetLibsGroup").classList.add("hidden");
        } catch (e) { this.toast(e.message, "error"); }
    },

    matchPkcs11Preset(settings) {
        if (!this.p11Presets || !settings.providerName) return;
        const idx = this.p11Presets.findIndex(p => p.providerName === settings.providerName);
        if (idx >= 0) {
            document.getElementById("pkcs11Preset").value = String(idx);
        }
    },

    onPkcs11PresetChange() {
        const sel = document.getElementById("pkcs11Preset");
        const libsGroup = document.getElementById("pkcs11PresetLibsGroup");
        const libsSel = document.getElementById("pkcs11PresetLibs");
        if (sel.value === "") {
            libsGroup.classList.add("hidden");
            libsSel.innerHTML = "";
            return;
        }
        const preset = this.p11Presets[parseInt(sel.value, 10)];
        if (!preset) return;
        document.getElementById("pkcs11ProviderName").value = preset.providerName || "";
        document.getElementById("pkcs11Library").value = preset.libraryPath || "";
        document.getElementById("pkcs11Slot").value = preset.slotIndex != null ? preset.slotIndex : 0;
        libsSel.innerHTML = preset.libraryPaths.map(p =>
            `<option value="${escapeHtml(p)}"${p === preset.libraryPath ? " selected" : ""}>${escapeHtml(p)}</option>`
        ).join("");
        libsGroup.classList.toggle("hidden", preset.libraryPaths.length < 2);
    },

    onPkcs11PresetLibChange() {
        const v = document.getElementById("pkcs11PresetLibs").value;
        if (v) {
            document.getElementById("pkcs11Library").value = v;
        }
    },

    async savePkcs11Settings() {
        const payload = {
            enabled: document.getElementById("pkcs11Enabled").checked,
            providerName: document.getElementById("pkcs11ProviderName").value.trim(),
            libraryPath: document.getElementById("pkcs11Library").value.trim(),
            slotIndex: parseInt(document.getElementById("pkcs11Slot").value, 10) || 0,
            tokenPin: document.getElementById("pkcs11Pin").value,
            keyStorageDefault: document.getElementById("pkcs11DefaultStorage").value
        };
        try {
            await this.api("/api/pkcs11", { method: "POST", body: JSON.stringify(payload) });
            document.getElementById("pkcs11Pin").value = "";
            this.toast("PKCS#11 settings saved");
        } catch (e) { this.toast(e.message, "error"); }
    },

    async testPkcs11() {
        const resultEl = document.getElementById("pkcs11Result");
        resultEl.classList.remove("hidden");
        resultEl.textContent = "Testing connection...";
        try {
            const res = await this.api("/api/pkcs11/test", { method: "POST", body: "{}" });
            resultEl.textContent = JSON.stringify(res.data, null, 2);
            this.toast("PKCS#11 connection OK");
        } catch (e) {
            resultEl.textContent = "Connection failed: " + e.message;
            this.toast("PKCS#11 connection failed", "error");
        }
    },

    async disconnectPkcs11() {
        try {
            await this.api("/api/pkcs11/disconnect", { method: "POST", body: "{}" });
            this.toast("PKCS#11 provider disconnected");
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- User Management (admin) ---------- */
    async loadUsers() {
        try {
            const users = await this.api("/api/users");
            const rows = users.map(u => {
                const roleBadges = (u.roles || []).map(r =>
                    `<span class="badge ${r === "ADMIN" ? "pkcs11" : "issued"}">${escapeHtml(r)}</span>`).join(" ");
                const statusBadge = u.enabled
                    ? `<span class="badge issued">Enabled</span>` : `<span class="badge revoked">Disabled</span>`;
                const isSelf = u.username === this.user;
                const isAdmin = (u.roles || []).includes("ADMIN");
                return `<tr>
                    <td>${u.id}</td>
                    <td><strong>${escapeHtml(u.username)}</strong>${isSelf ? ' <span class="hint">(you)</span>' : ""}</td>
                    <td>${roleBadges || "-"}</td>
                    <td>${statusBadge}</td>
                    <td>${fmtDate(u.createdAt)}</td>
                    <td class="actions">
                        ${isAdmin
                            ? (isSelf ? "" : `<button class="btn btn-sm btn-warning" onclick="App.setUserAdmin(${u.id}, false)">Remove admin</button>`)
                            : `<button class="btn btn-sm btn-success" onclick="App.setUserAdmin(${u.id}, true)">Make admin</button>`}
                        ${u.enabled
                            ? (isSelf ? "" : `<button class="btn btn-sm btn-danger" onclick="App.setUserEnabled(${u.id}, false)">Disable</button>`)
                            : `<button class="btn btn-sm btn-success" onclick="App.setUserEnabled(${u.id}, true)">Enable</button>`}
                        <button class="btn btn-sm" onclick="App.resetUserPassword(${u.id})">Reset password</button>
                        ${isSelf ? "" : `<button class="btn btn-sm btn-danger" onclick="App.deleteUser(${u.id})">Delete</button>`}
                    </td>
                </tr>`;
            }).join("");
            document.getElementById("userTableBody").innerHTML = rows || emptyRow(6);
        } catch (e) { this.toast(e.message, "error"); }
    },

    async newUser() {
        document.getElementById("uUsername").value = "";
        document.getElementById("uPassword").value = "";
        document.getElementById("uAdmin").checked = false;
        this.openModal("userModal");
    },

    async saveUser() {
        const payload = {
            username: document.getElementById("uUsername").value.trim(),
            password: document.getElementById("uPassword").value,
            admin: document.getElementById("uAdmin").checked
        };
        if (!payload.username || !payload.password) {
            this.toast("Username and password are required", "error");
            return;
        }
        try {
            await this.api("/api/users", { method: "POST", body: JSON.stringify(payload) });
            this.closeModal("userModal");
            this.toast("User created");
            this.loadUsers();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async setUserAdmin(id, admin) {
        if (!confirm((admin ? "Grant" : "Remove") + " administrator role?")) return;
        try {
            await this.api("/api/users/" + id, { method: "PUT", body: JSON.stringify({ admin: admin }) });
            this.toast(admin ? "Administrator role granted" : "Administrator role removed");
            this.loadUsers();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async setUserEnabled(id, enabled) {
        if (!confirm(enabled ? "Enable this account?" : "Disable this account? The user will no longer be able to log in.")) return;
        try {
            await this.api("/api/users/" + id, { method: "PUT", body: JSON.stringify({ enabled: enabled }) });
            this.toast(enabled ? "Account enabled" : "Account disabled");
            this.loadUsers();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async resetUserPassword(id) {
        const password = prompt("New password for user #" + id + " (at least 6 characters):");
        if (!password || password.length < 6) {
            this.toast("Password must be at least 6 characters", "error");
            return;
        }
        try {
            await this.api("/api/users/" + id + "/password", { method: "PUT", body: JSON.stringify({ password: password }) });
            this.toast("Password reset");
        } catch (e) { this.toast(e.message, "error"); }
    },

    async deleteUser(id) {
        if (!confirm("Delete user #" + id + "? This cannot be undone.")) return;
        try {
            await this.api("/api/users/" + id, { method: "DELETE" });
            this.toast("User deleted");
            this.loadUsers();
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- Signed Audit Log (admin) ---------- */
    async loadAuditLog() {
        try {
            const entries = await this.api("/api/audit");
            const rows = entries.map(e => `<tr>
                <td>${e.id}</td>
                <td>${fmtDate(e.timestamp)}</td>
                <td>${escapeHtml(e.actor || "")}</td>
                <td>${escapeHtml(e.category || "")}</td>
                <td>${escapeHtml(e.action || "")}</td>
                <td class="audit-detail">${escapeHtml(e.detail || "")}</td>
                <td class="mono">${e.hash || ""}</td>
                <td class="mono">${e.signature || ""}</td>
            </tr>`).join("");
            document.getElementById("auditLogBody").innerHTML = rows || '<tr><td colspan="8">No audit entries yet.</td></tr>';
        } catch (e) { this.toast(e.message, "error"); }
    },

    async verifyAuditLog() {
        const el = document.getElementById("auditVerifyResult");
        el.classList.remove("hidden");
        el.textContent = "Verifying chain...";
        try {
            const r = await this.api("/api/audit/verify");
            const ok = !!r.valid;
            el.textContent = `Integrity: ${ok ? "OK - " + r.verified + "/" + r.total + " entries verified intact" : "BROKEN - failed at entry #" + r.failedAt + " (" + r.message + ")"}`;
            el.className = "verify-badge " + (ok ? "ok" : "bad");
            this.toast(ok ? "Audit chain is intact" : "Audit chain broken!", ok ? "success" : "error");
        } catch (e) {
            el.textContent = "Verification failed: " + e.message;
            el.className = "verify-badge bad";
        }
    },

    /* ---------- CRL ---------- */
    async loadCrlHistory() {
        const caId = document.getElementById("crlCaSelect").value;
        if (!caId) return;
        try {
            const history = await this.api("/api/crl/" + caId + "/history");
            const rows = history.map(c => `<tr>
                <td>${c.crlNumber}</td>
                <td>${escapeHtml(c.caName)}</td>
                <td>${fmtDate(c.thisUpdate)}</td>
                <td>${fmtDate(c.nextUpdate)}</td>
                <td>${c.revokedSerials.length}</td>
                <td>${c.current ? '<span class="badge ISSUED">current</span>' : '<span class="badge REVOKED">superseded</span>'}</td>
            </tr>`).join("");
            document.getElementById("crlHistoryBody").innerHTML = rows || emptyRow(6);
        } catch (e) {
            document.getElementById("crlHistoryBody").innerHTML = emptyRow(6);
        }
    },

    async generateCrl() {
        const caId = document.getElementById("crlCaSelect").value;
        if (!caId) { this.toast("Select a CA first", "error"); return; }
        try {
            const result = await this.api("/api/crl/" + caId + "/generate", { method: "POST" });
            this.toast(result.message);
            this.loadCrlHistory();
        } catch (e) { this.toast(e.message, "error"); }
    },

    async viewCrlPem() {
        const caId = document.getElementById("crlCaSelect").value;
        if (!caId) { this.toast("Select a CA first", "error"); return; }
        try {
            const pem = await this.api("/api/crl/" + caId + "/pem");
            const out = document.getElementById("crlOutput");
            out.textContent = pem;
            out.classList.remove("hidden");
        } catch (e) { this.toast(e.message, "error"); }
    },

    downloadCrl() {
        const caId = document.getElementById("crlCaSelect").value;
        if (!caId) { this.toast("Select a CA first", "error"); return; }
        window.open("/api/crl/" + caId, "_blank");
    },

    /* ---------- OCSP ---------- */
    async checkOcsp() {
        const serial = document.getElementById("ocspSerial").value.trim();
        if (!serial) { this.toast("Enter a serial number", "error"); return; }
        try {
            const result = await this.api("/api/ocsp/status/" + serial);
            const status = result.data.status;
            const el = document.getElementById("ocspResult");
            el.textContent = "Status: " + status;
            el.className = "ocsp-result " + (status.startsWith("GOOD") ? "good" : status.startsWith("REVOKED") ? "revoked" : "unknown");
            el.classList.remove("hidden");
        } catch (e) { this.toast(e.message, "error"); }
    },

    /* ---------- API Console ---------- */
    apiEndpoints: [
        { group: "System", method: "GET", path: "/api/info", desc: "Platform summary: counts and configuration.", kind: "json" },
        { group: "System", method: "GET", path: "/api/me", desc: "Current authenticated user and roles.", kind: "json" },
        { group: "System", method: "GET", path: "/api/pkcs11", desc: "Current PKCS#11 device settings (admin only). The token PIN is never returned.", kind: "json" },
        { group: "System", method: "GET", path: "/api/pkcs11/presets", desc: "Known PKCS#11 providers (SoftHSM2, OpenSC, YubiKey PIV, Utimaco, Thales Luna, Entrust nShield, eToken) with typical library paths per OS (admin only).", kind: "json" },
        { group: "System", method: "POST", path: "/api/pkcs11", desc: "Save PKCS#11 device settings (admin only).", kind: "json", body: `{\n  "enabled": true,\n  "providerName": "SunPKCS11-CM",\n  "libraryPath": "C:\\\\Program Files\\\\SoftHSM2\\\\lib\\\\softhsm2.dll",\n  "slotIndex": 0,\n  "tokenPin": "1234",\n  "keyStorageDefault": "DATABASE"\n}` },
        { group: "System", method: "POST", path: "/api/pkcs11/test", desc: "Load the provider and verify the token accepts the PIN + slot (admin only).", kind: "json" },
        { group: "System", method: "POST", path: "/api/pkcs11/disconnect", desc: "Unload the PKCS#11 provider (admin only).", kind: "json" },
{ group: "System", method: "GET", path: "/api/audit", desc: "Full signed audit log: every entry carries its hash (SHA-256 of the previous entry + own fields) and an HMAC-SHA256 signature over the payload (admin only).", kind: "json" },
{ group: "System", method: "GET", path: "/api/audit/verify", desc: "Recompute the whole hash chain and verify every HMAC-SHA256 signature against the stored audit secret (admin only). Returns valid/total/verified/failedAt/message.", kind: "json" },
{ group: "System", method: "GET", path: "/api/users", desc: "List all platform users with their roles and enabled state (admin only).", kind: "json" },
{ group: "System", method: "POST", path: "/api/users", desc: "Create a user (admin only). username + password (min 6 chars) + optional admin=true.", kind: "json", body: `{\n  "username": "alice",\n  "password": "alice123",\n  "admin": false\n}` },
{ group: "System", method: "PUT", path: "/api/users/{id}", desc: "Update a user (admin only): grant/revoke the administrator role with admin=true/false and/or enable/disable the account with enabled=true/false. The last administrator cannot be demoted/disabled and nobody can disable their own account.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "admin": true\n}` },
{ group: "System", method: "PUT", path: "/api/users/{id}/password", desc: "Reset a user's password (admin only).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "password": "newpass123"\n}` },
{ group: "System", method: "DELETE", path: "/api/users/{id}", desc: "Delete a user (admin only). You cannot delete yourself or the last administrator.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },
        { group: "CA Management", method: "POST", path: "/api/ca", desc: "Create a new CA (admin only). The CA is generated and activated immediately. Set keyStorage to PKCS11 to keep the private key on the configured PKCS#11 device (requires the device enabled + library configured) or DATABASE to store it in the platform DB (default). keyAlgorithm supports RSA, EC (P-256/P-384/P-521), ED25519 and ED448.", kind: "json", body: `{\n  "name": "Example Root CA",\n  "subjectDn": "CN=Example Root CA, O=Example Corp, C=US",\n  "caType": "ROOT",\n  "keyAlgorithm": "RSA",\n  "keySize": 4096,\n  "validityDays": 3650,\n  "keyStorage": "DATABASE",\n  "requestedBy": "admin"\n}` },
        { group: "CA Management", method: "GET", path: "/api/ca", desc: "List all CAs (admin only).", kind: "json" },
        { group: "CA Management", method: "GET", path: "/api/ca/active", desc: "List active (ISSUED) CAs. Readable by any authenticated user (powers CSR issuer / CRL dropdowns).", kind: "json" },
        { group: "CA Management", method: "GET", path: "/api/ca/{id}", desc: "Fetch a single CA by ID (admin only). Includes keyAlgorithm, keySize and signatureAlgorithm.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },
        { group: "CA Management", method: "GET", path: "/api/ca/{id}/certificate.pem", desc: "Download a CA certificate in PEM (admin only).", kind: "pem", params: [{ name: "id", type: "path", required: true, default: "1" }], filename: "ca-cert.pem" },
        { group: "CA Management", method: "POST", path: "/api/ca/{id}/revoke", desc: "Revoke a CA (admin only).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "reason": "CA revoked",\n  "by": "admin"\n}` },
        { group: "CA Management", method: "POST", path: "/api/ca/{id}/suspend", desc: "Suspend a CA (admin only).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "by": "admin"\n}` },
        { group: "CA Management", method: "POST", path: "/api/ca/{id}/resume", desc: "Resume a suspended CA (admin only).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "by": "admin"\n}` },

        { group: "Profiles", method: "GET", path: "/api/profiles/types", desc: "List the built-in profile types (CUSTOM, CA, SERVER, CLIENT, CODE_SIGNING, EMAIL, DOCUMENT_SIGNING, CLASS_1, CLASS_2, CLASS_3, AADHAAR_ESIGN) with their default parameters.", kind: "json" },
        { group: "Profiles", method: "GET", path: "/api/profiles", desc: "List all certificate profiles. Readable by any authenticated user.", kind: "json" },
        { group: "Profiles", method: "GET", path: "/api/profiles/{id}", desc: "Fetch a single certificate profile.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },
        { group: "Profiles", method: "POST", path: "/api/profiles", desc: "Create a certificate profile (admin only). Set type to a built-in preset (e.g. CODE_SIGNING) and omit the other fields to use its defaults, or set type to CUSTOM and define everything. keyStorage selects where platform-generated keys go: DATABASE (default, exportable PEM) or PKCS11 (generated on the device at issuance).", kind: "json", body: `{\n  "name": "HSM TLS",\n  "type": "SERVER",\n  "keyStorage": "PKCS11"\n}` },
        { group: "Profiles", method: "PUT", path: "/api/profiles/{id}", desc: "Update a certificate profile (admin only). keyAlgorithm supports RSA, EC (P-256/P-384/P-521), ED25519 and ED448.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "name": "SSL Certificate",\n  "type": "SERVER",\n  "keyAlgorithm": "RSA",\n  "keySize": 2048,\n  "validityDays": 825,\n  "caProfile": false,\n  "keyUsage": ["digitalSignature", "keyEncipherment"],\n  "extendedKeyUsage": ["serverAuth"]\n}` },
        { group: "Profiles", method: "DELETE", path: "/api/profiles/{id}", desc: "Delete a certificate profile (admin only).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },

        { group: "Certificates", method: "POST", path: "/api/certificates/csr", desc: "Submit a PKCS#10 CSR for signing; the certificate is issued immediately.", kind: "json", body: `{\n  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\\n...\\n-----END CERTIFICATE REQUEST-----",\n  "issuerCaId": 2,\n  "requestedBy": "requester"\n}` },
        { group: "Certificates", method: "POST", path: "/api/certificates/request", desc: "Request a certificate from manual fields; the platform generates the key pair and CSR. keyAlgorithm supports RSA, EC (P-256/P-384/P-521), ED25519 and ED448 (Ed25519/Ed448 sizes are fixed). Optionally pass profileId (a non-CA profile) whose keyStorage governs where keys live: DATABASE keeps the PEM in the DB (downloadable by the owner), PKCS11 generates the key on the device at issuance and stores key + certificate on the token. Also supports additionalExtensions (custom OIDs) and validityMinutes (1..525600) for sub-day validity.", kind: "json", body: `{\n  "commonName": "app.example.com",\n  "organization": "Example Corp",\n  "country": "US",\n  "dnsNames": ["app.example.com"],\n  "ipAddresses": ["10.0.0.5"],\n  "keyAlgorithm": "RSA",\n  "keySize": 2048,\n  "validityMinutes": 90,\n  "issuerCaId": 2,\n  "profileId": 4,\n  "additionalExtensions": [{"oid": "1.2.3.4.5", "type": "STRING", "value": "custom"}],\n  "requestedBy": "requester"\n}` },
        { group: "Certificates", method: "GET", path: "/api/certificates/{id}/key", desc: "Download the private key PEM for a platform-generated request (requester/owner only).", kind: "pem", params: [{ name: "id", type: "path", required: true, default: "1" }], filename: "private-key.pem" },
        { group: "Certificates", method: "GET", path: "/api/certificates", desc: "List certificates. Optionally filter by status or CA.", kind: "json", params: [
            { name: "status", type: "query", required: false, default: "", placeholder: "ISSUED | PENDING | REVOKED | SUSPENDED" },
            { name: "caId", type: "query", required: false, default: "", placeholder: "CA id" }
        ] },
        { group: "Certificates", method: "GET", path: "/api/certificates/{id}", desc: "Fetch a single certificate by ID. Includes keyAlgorithm, keySize and (once issued) signatureAlgorithm.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },
        { group: "Certificates", method: "GET", path: "/api/certificates/{id}/pem", desc: "Download a certificate in PEM.", kind: "pem", params: [{ name: "id", type: "path", required: true, default: "1" }], filename: "cert.pem" },
        { group: "Certificates", method: "POST", path: "/api/certificates/{id}/revoke", desc: "Revoke a certificate with a reason.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }], body: `{\n  "reason": "SUPERSEDED"\n}` },
        { group: "Certificates", method: "POST", path: "/api/certificates/{id}/suspend", desc: "Suspend a certificate (certificateHold).", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },
        { group: "Certificates", method: "POST", path: "/api/certificates/{id}/resume", desc: "Resume a suspended certificate.", kind: "json", params: [{ name: "id", type: "path", required: true, default: "1" }] },

        { group: "CRL", method: "POST", path: "/api/crl/{caId}/generate", desc: "Generate a fresh CRL for a CA.", kind: "json", params: [{ name: "caId", type: "path", required: true, default: "1" }] },
        { group: "CRL", method: "GET", path: "/api/crl/{caId}", desc: "Download the current CRL in DER (application/pkix-crl).", kind: "binary", params: [{ name: "caId", type: "path", required: true, default: "1" }], filename: "crl.der" },
        { group: "CRL", method: "GET", path: "/api/crl/{caId}/pem", desc: "View the current CRL in PEM.", kind: "text", params: [{ name: "caId", type: "path", required: true, default: "1" }] },
        { group: "CRL", method: "GET", path: "/api/crl/{caId}/history", desc: "CRL history (last 10 kept) for a CA.", kind: "json", params: [{ name: "caId", type: "path", required: true, default: "1" }] },

        { group: "OCSP", method: "POST", path: "/api/ocsp", desc: "RFC 6960 binary OCSP request. Pick a DER OCSP request file; the binary response is returned.", kind: "file" },
        { group: "OCSP", method: "GET", path: "/api/ocsp/status/{serialHex}", desc: "Human-readable status for a certificate serial (hex).", kind: "json", params: [{ name: "serialHex", type: "path", required: true, default: "01", placeholder: "e.g. 1a2b3c" }] },
        { group: "OCSP", method: "GET", path: "/api/ocsp/status", desc: "Human-readable status via query parameter.", kind: "json", params: [{ name: "serial", type: "query", required: true, default: "01", placeholder: "e.g. 1a2b3c" }] },

        { group: "Crypto", method: "GET", path: "/api/crypto/algorithms", desc: "List supported key algorithms with their key sizes, NIST curves and derived signature algorithms. The UI renders its algorithm/size selects from this catalog.", kind: "json" },
        { group: "Crypto", method: "GET", path: "/api/crypto/oids", desc: "List well-known X.509 extension OIDs (with friendly labels and a suggested value type). The UI offers these in a dropdown when adding custom extensions, while still allowing arbitrary OIDs to be typed manually.", kind: "json" },
        { group: "Crypto", method: "POST", path: "/api/crypto/derive", desc: "Validate an algorithm/size and derive the effective parameters (normalized algorithm, key size and signature algorithm). Omit keySize to use the platform default; an unsupported algorithm or size returns 400 with the reason.", kind: "json", body: `{\n  "keyAlgorithm": "EC",\n  "keySize": 521\n}` }
    ],

    apiSelected: null,

    renderApiList() {
        const groups = [];
        this.apiEndpoints.forEach((ep, i) => {
            if (!groups.includes(ep.group)) groups.push(ep.group);
        });
        document.getElementById("apiListBody").innerHTML = groups.map(g =>
            `<div class="api-group-title">${escapeHtml(g)}</div>` +
            this.apiEndpoints.map((ep, i) =>
                ep.group === g
                    ? `<div class="api-item" data-index="${i}"><span class="method-badge method-${ep.method.toLowerCase()}">${ep.method}</span><code>${escapeHtml(ep.path)}</code></div>`
                    : ""
            ).join("")
        ).join("");
        document.querySelectorAll(".api-item").forEach(el => {
            el.addEventListener("click", () => this.selectApiEndpoint(parseInt(el.dataset.index, 10)));
        });
    },

    selectApiEndpoint(index) {
        const ep = this.apiEndpoints[index];
        this.apiSelected = ep;
        document.querySelectorAll(".api-item").forEach(el => el.classList.toggle("active", parseInt(el.dataset.index, 10) === index));
        document.getElementById("apiDetailEmpty").classList.add("hidden");
        document.getElementById("apiDetail").classList.remove("hidden");

        const badge = document.getElementById("apiMethod");
        badge.textContent = ep.method;
        badge.className = "method-badge method-" + ep.method.toLowerCase();
        document.getElementById("apiPath").textContent = ep.path;
        document.getElementById("apiDesc").textContent = ep.desc;

        const paramsHtml = (ep.params || []).map(p => {
            const isPath = p.type === "path";
            const label = (isPath ? "Path" : "Query") + " parameter: " + p.name + (p.required ? ' <span class="req">*</span>' : "");
            return `<div class="api-param-row">
                <div class="api-param-name">${escapeHtml(label)}</div>
                <div class="form-group">
                    <input type="text" data-param-name="${escapeHtml(p.name)}" data-param-type="${isPath ? "path" : "query"}"
                        value="${escapeHtml(p.default || "")}" placeholder="${escapeHtml(p.placeholder || "")}">
                </div>
            </div>`;
        }).join("");
        document.getElementById("apiParams").innerHTML = paramsHtml;

        const bodyGroup = document.getElementById("apiBodyGroup");
        const fileGroup = document.getElementById("apiFileGroup");
        const bodyEl = document.getElementById("apiBody");
        if (ep.kind === "json") {
            bodyEl.value = ep.body || "";
            bodyEl.rows = Math.max(6, ((ep.body || "").match(/\n/g) || []).length + 2);
            bodyGroup.classList.toggle("hidden", !ep.body);
        } else {
            bodyEl.value = "";
            bodyGroup.classList.add("hidden");
        }
        fileGroup.classList.toggle("hidden", ep.kind !== "file");

        document.getElementById("apiMeta").textContent = "";
        document.getElementById("apiResponse").classList.add("hidden");
        document.getElementById("apiDownloadBtn").classList.add("hidden");
    },

    async sendApi() {
        const ep = this.apiSelected;
        if (!ep) return;
        let url = ep.path;
        const inputs = document.querySelectorAll("#apiParams input");
        inputs.forEach(input => {
            const name = input.dataset.paramName;
            const type = input.dataset.paramType;
            const value = input.value.trim();
            if (type === "path") {
                url = url.replace("{" + name + "}", encodeURIComponent(value || ""));
            }
        });
        const query = [];
        inputs.forEach(input => {
            const name = input.dataset.paramName;
            const type = input.dataset.paramType;
            const value = input.value.trim();
            if (type === "query" && value) query.push(encodeURIComponent(name) + "=" + encodeURIComponent(value));
        });
        if (query.length) url += (url.includes("?") ? "&" : "?") + query.join("&");

        const headers = { ...this.authHeader() };
        const options = { method: ep.method };
        let bodyPayload = null;

        if (ep.kind === "file") {
            const file = document.getElementById("apiFile").files[0];
            if (!file) { this.toast("Select a binary request file", "error"); return; }
            bodyPayload = file;
            headers["Content-Type"] = "application/ocsp-request";
        } else if (ep.kind === "json" && ep.body !== undefined) {
            bodyPayload = document.getElementById("apiBody").value.trim();
            if (bodyPayload) {
                try { JSON.parse(bodyPayload); } catch (e) { this.toast("Request body is not valid JSON", "error"); return; }
                headers["Content-Type"] = "application/json";
            } else {
                bodyPayload = null;
            }
        }
        if (bodyPayload !== null) options.body = bodyPayload;

        const meta = document.getElementById("apiMeta");
        const out = document.getElementById("apiResponse");
        const dl = document.getElementById("apiDownloadBtn");
        meta.textContent = "→ " + ep.method + " " + url;
        meta.className = "api-meta";

        try {
            const res = await fetch(url, options);
            const contentType = res.headers.get("content-type") || "";
            const status = res.status;
            const isBinary = contentType.includes("application/pkix-crl") || contentType.includes("application/ocsp-response") || contentType.includes("application/octet-stream");
            let displayText;
            let downloadName = null;

            if (isBinary) {
                const blob = await res.blob();
                downloadName = ep.filename || "response.bin";
                const bytes = new Uint8Array(await blob.arrayBuffer());
                displayText = `Binary response (${bytes.length} bytes)\n\n` + hexDump(bytes);
            } else {
                const text = await res.text();
                displayText = text;
                if (contentType.includes("application/json")) {
                    try { displayText = JSON.stringify(JSON.parse(text), null, 2); } catch (e) { /* keep raw */ }
                }
            }

            meta.textContent = "← " + status + " " + (status < 400 ? "OK" : "ERROR") + "  ·  " + url;
            meta.className = "api-meta " + (status < 400 ? "ok" : "err");
            if (downloadName) {
                dl.classList.remove("hidden");
                dl.onclick = () => this.downloadBlob(downloadName, blob);
            } else {
                dl.classList.add("hidden");
            }
            out.textContent = displayText;
            out.classList.remove("hidden");
            if (status >= 400 && res.status === 401) this.logout();
        } catch (e) {
            meta.textContent = "✗ Request failed: " + e.message;
            meta.className = "api-meta err";
            out.textContent = e.message;
            out.classList.remove("hidden");
            dl.classList.add("hidden");
        }
    },

    downloadBlob(name, blob) {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = name;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    },

    /* ---------- Modal helpers ---------- */
    openModal(id) { document.getElementById(id).classList.remove("hidden"); },
    closeModal(id) { document.getElementById(id).classList.add("hidden"); },

    async populateCaSelects() {
        let active = [];
        try {
            active = await this.api("/api/ca/active");
        } catch (e) {
            active = this.allCaList.filter(c => c.status === "ISSUED");
        }
        const selectIssuer = document.getElementById("csrIssuer");
        const selectParent = document.getElementById("caParent");
        selectIssuer.innerHTML = active.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");
        selectParent.innerHTML = active.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");
        if (active.length > 0) {
            document.getElementById("crlCaSelect").innerHTML = active.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");
        }
    },

    async populateCertSearchCas() {
        let active = [];
        try {
            active = await this.api("/api/ca/active");
        } catch (e) {
            active = [];
        }
        const sel = document.getElementById("certSearchCa");
        sel.innerHTML = '<option value="">All CAs</option>'
            + active.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");
    },

    async bindEvents() {
        document.getElementById("loginBtn").addEventListener("click", async () => {
            const user = document.getElementById("loginUser").value.trim();
            const pass = document.getElementById("loginPass").value;
            try {
                await this.login(user, pass);
            } catch (e) {
                this.logout();
                this.toast("Invalid credentials", "error");
            }
        });
        document.getElementById("logoutBtn").addEventListener("click", () => this.logout());

        this.updateThemeButton();
        document.getElementById("themeToggle").addEventListener("click", () => {
            const current = document.documentElement.getAttribute("data-theme");
            this.setTheme(current === "light" ? "dark" : "light");
        });

        document.querySelectorAll(".nav-link").forEach(link => {
            link.addEventListener("click", (e) => {
                e.preventDefault();
                document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
                document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
                link.classList.add("active");
                document.getElementById("tab-" + link.dataset.tab).classList.add("active");
                if (link.dataset.tab === "cas") this.loadCas();
                if (link.dataset.tab === "profiles") this.loadProfiles();
                if (link.dataset.tab === "certificates") { this.populateCertSearchCas(); this.loadCertificates(); }
                if (link.dataset.tab === "request") this.populateRequestForm();
                if (link.dataset.tab === "crl") { this.populateCaSelects(); this.loadCrlHistory(); }
                if (link.dataset.tab === "settings") { this.loadPkcs11Settings(); this.loadPkcs11Presets(); }
                if (link.dataset.tab === "users") this.loadUsers();
                if (link.dataset.tab === "audit") this.loadAuditLog();
                if (link.dataset.tab === "api") this.renderApiList();
            });
        });

        document.getElementById("certSearchBtn").addEventListener("click", () => this.loadCertificates());
        document.getElementById("certSearchReset").addEventListener("click", () => {
            document.getElementById("certSearch").value = "";
            document.getElementById("certSearchStatus").value = "";
            document.getElementById("certSearchCa").value = "";
            this.loadCertificates();
        });
        document.getElementById("certSearch").addEventListener("keydown", (e) => {
            if (e.key === "Enter") this.loadCertificates();
        });

        document.querySelectorAll("[data-close]").forEach(el => {
            el.addEventListener("click", () => this.closeModal(el.dataset.close));
        });
        document.querySelectorAll(".modal").forEach(m => {
            m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); });
        });

        document.getElementById("newCaBtn").addEventListener("click", () => {
            this.populateCaSelects();
            this.setupCaKeyStorage();
            this.renderKeySizeOptions("caKeySize", document.getElementById("caKeyAlg").value);
            this.openModal("caModal");
        });
        document.getElementById("submitCaBtn").addEventListener("click", () => this.submitCa());
        document.getElementById("caKeyStorage").addEventListener("change", () => this.toggleCaPkcs11Alias());
        document.getElementById("caKeyAlg").addEventListener("change", () => {
            this.renderKeySizeOptions("caKeySize", document.getElementById("caKeyAlg").value);
        });
        document.getElementById("newCsrBtn").addEventListener("click", () => {
            this.populateCaSelects();
            this.openModal("csrModal");
        });
        document.getElementById("submitCsrBtn").addEventListener("click", () => this.submitCsr());
        document.getElementById("reqSubmitBtn").addEventListener("click", () => this.submitCertificateRequest());
        document.getElementById("reqKeyAlg").addEventListener("change", () => this.toggleRequestKeySize());
        document.getElementById("reqValidityUnit").addEventListener("change", () => this.toggleValidityUnit("reqValidity", "reqValidityUnit"));
        document.getElementById("pValidityUnit").addEventListener("change", () => this.toggleValidityUnit("pValidity", "pValidityUnit"));
        document.getElementById("pKeyAlg").addEventListener("change", () => {
            this.renderKeySizeOptions("pKeySize", document.getElementById("pKeyAlg").value);
        });
        document.getElementById("reqProfile").addEventListener("change", () => this.onProfileSelect());
        document.getElementById("reqAddExtBtn").addEventListener("click", () => this.addRequestExtRow());
        document.getElementById("newProfileBtn").addEventListener("click", () => this.newProfile());
        document.getElementById("saveProfileBtn").addEventListener("click", () => this.saveProfile());
        document.getElementById("pType").addEventListener("change", () => this.onProfileTypeChange());
        document.getElementById("pAddExtBtn").addEventListener("click", () => this.addProfileExtRow());
        document.getElementById("copyPemBtn").addEventListener("click", () => {
            navigator.clipboard.writeText(document.getElementById("pemContent").textContent);
            this.toast("Copied to clipboard");
        });

        document.getElementById("genCrlBtn").addEventListener("click", () => this.generateCrl());
        document.getElementById("viewCrlPemBtn").addEventListener("click", () => this.viewCrlPem());
        document.getElementById("downloadCrlBtn").addEventListener("click", () => this.downloadCrl());
        document.getElementById("ocspCheckBtn").addEventListener("click", () => this.checkOcsp());
        document.getElementById("savePkcs11Btn").addEventListener("click", () => this.savePkcs11Settings());
        document.getElementById("testPkcs11Btn").addEventListener("click", () => this.testPkcs11());
        document.getElementById("disconnectPkcs11Btn").addEventListener("click", () => this.disconnectPkcs11());
        document.getElementById("pkcs11Preset").addEventListener("change", () => this.onPkcs11PresetChange());
        document.getElementById("pkcs11PresetLibs").addEventListener("change", () => this.onPkcs11PresetLibChange());
        document.getElementById("verifyAuditBtn").addEventListener("click", () => this.verifyAuditLog());
        document.getElementById("newUserBtn").addEventListener("click", () => this.newUser());
        document.getElementById("saveUserBtn").addEventListener("click", () => this.saveUser());
        document.getElementById("apiSendBtn").addEventListener("click", () => this.sendApi());

        document.addEventListener("keydown", (e) => { if (e.key === "Escape") document.querySelectorAll(".modal").forEach(m => m.classList.add("hidden")); });
    }
};

function serialHex(serial) {
    let hex = String(serial || "");
    if (!/^[0-9A-Fa-f]+$/.test(hex)) {
        try { hex = parseInt(serial).toString(16).toUpperCase(); } catch (e) { return "-"; }
    }
    hex = hex.toUpperCase();
    return hex.length > 28 ? hex.slice(0, 28) + "\u2026" : hex;
}

function fmtDate(iso) {
    if (!iso) return "-";
    return new Date(iso).toLocaleString();
}

function truncate(s, n) {
    return s && s.length > n ? s.slice(0, n) + "\u2026" : s;
}

function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[c]);
}

function emptyRow(cols) {
    return `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-dim);padding:24px">No records found</td></tr>`;
}

function hexDump(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i + 16);
        const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, "0")).join(" ");
        const ascii = Array.from(chunk).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
        lines.push(String(i).padStart(6, "0") + "  " + hex.padEnd(47) + "  " + ascii);
    }
    return lines.join("\n");
}

document.addEventListener("DOMContentLoaded", () => App.init());
