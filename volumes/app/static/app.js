const REVOKE_ENABLED = (function () {
  var s = document.currentScript || document.querySelector('script[data-revoke]');
  return s && s.dataset.revoke === "true";
})();
const ISSUE_ENABLED = (function () {
  var s = document.currentScript || document.querySelector('script[data-issue]');
  return s && s.dataset.issue === "true";
})();
let ALL = [];
const active = new Set(["valid", "expiring", "expired", "revoked"]);

function fmtDate(iso) { try { return new Date(iso).toISOString().slice(0, 10); } catch (e) { return "?"; } }

function lifePercent(c) {
  const nb = new Date(c.not_before).getTime();
  const na = new Date(c.not_after).getTime();
  const now = Date.now();
  if (na <= nb) return 100;
  const p = ((now - nb) / (na - nb)) * 100;
  return Math.max(0, Math.min(100, p));
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
}

function render() {
  const q = document.getElementById("search").value.trim().toLowerCase();
  const list = document.getElementById("list");
  const rows = ALL.filter(c => active.has(c.status)).filter(c => {
    if (!q) return true;
    return (c.subject_cn || "").toLowerCase().includes(q)
      || (c.serial || "").toLowerCase().includes(q)
      || (c.sans || []).join(" ").toLowerCase().includes(q)
      || (c.fingerprint_sha256 || "").toLowerCase().includes(q);
  });

  if (!rows.length) {
    list.innerHTML = '<div class="empty">No certificate matches.</div>';
    return;
  }

  list.innerHTML = rows.map(c => {
    const pct = lifePercent(c);
    const remainPct = (100 - pct).toFixed(0);
    const daysTxt = c.status === "revoked" ? "revoked"
      : c.status === "expired" ? "expired"
        : c.days_left + " d";
    const caTag = c.is_ca ? '<span class="ca-tag">CA</span>' : '';
    const sans = (c.sans && c.sans.length) ? c.sans.join(", ") : "—";
    const canRevoke = REVOKE_ENABLED && c.status !== "revoked" && c.status !== "expired" && !c.is_ca;
    const typeTxt = c.cert_type ? ` · ${esc(c.cert_type)}` : "";
    return `
      <div class="row ${c.status}" data-serial="${esc(c.serial)}">
        <div class="status-bar"></div>
        <div class="ident">
          <div class="cn">${esc(c.subject_cn)}${caTag}</div>
          <div class="sans" title="${esc(sans)}">${esc(sans)}</div>
          <div class="meta-serial">sn:${esc(c.serial)} · ${esc(c.key_type)}${typeTxt} · ${c.fingerprint_sha256.slice(0, 16)}…</div>
        </div>
        <div class="life">
          <div class="track"><div class="fill" style="width:${(c.status === 'revoked' || c.status === 'expired') ? 100 : pct}%"></div></div>
          <div class="dates"><span>${fmtDate(c.not_before)}</span><span>${fmtDate(c.not_after)}</span></div>
        </div>
        <div class="days"><b>${daysTxt}</b><span class="lbl">${c.status === 'valid' || c.status === 'expiring' ? remainPct + '% left' : ''}</span></div>
        <div class="actions">
          <button class="revoke" ${canRevoke ? '' : 'disabled'} data-serial="${esc(c.serial)}">Revoke</button>
        </div>
      </div>`;
  }).join("");

  list.querySelectorAll("button.revoke:not(:disabled)").forEach(b => {
    b.addEventListener("click", () => revoke(b.dataset.serial));
  });
  document.getElementById("foot").textContent =
    `${rows.length} certificate(s) shown out of ${ALL.length} · updated ${new Date().toLocaleTimeString('en-US')}`;
}

async function load() {
  try {
    const r = await fetch("/api/certs");
    const j = await r.json();
    if (j.error) { toast(j.error, "err"); return; }
    ALL = j.certs || [];
    for (const k of ["valid", "expiring", "expired", "revoked"]) {
      const el = document.querySelector(`.n[data-k="${k}"]`);
      if (el) el.textContent = j.summary[k] ?? 0;
    }
    render();
  } catch (e) { toast("Could not load: " + e.message, "err"); }
}

async function revoke(serial) {
  if (!confirm(`Revoke certificate sn:${serial}?\nThis action is irreversible.`)) return;
  try {
    const r = await fetch("/api/revoke", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ serial })
    });
    const j = await r.json();
    if (j.ok) { toast(j.message || "Revoked.", "ok"); load(); }
    else { toast(j.error || "Revocation failed.", "err"); }
  } catch (e) { toast("Error: " + e.message, "err"); }
}

let toastTimer;
function toast(msg, kind) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.className = "toast show " + (kind || "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = "toast", 4000);
}

function fieldRow(label, value) {
  return `<div class="mrow"><div class="mlabel">${esc(label)}</div><div class="mvalue">${value}</div></div>`;
}

function openModal(c) {
  document.getElementById("modalTitle").textContent = c.subject_cn || "(no CN)";
  const sans = (c.sans && c.sans.length) ? esc(c.sans.join(", ")) : "—";
  const provisioner = c.provisioner
    ? `<span class="prov-tag ${esc(c.provisioner)}">${esc(c.provisioner)}</span>`
    : "—";
  document.getElementById("modalBody").innerHTML = [
    fieldRow("Common Name", esc(c.subject_cn)),
    fieldRow("Subject", `<span class="mono">${esc(c.subject_dn)}</span>`),
    fieldRow("Issuer", `<span class="mono">${esc(c.issuer_dn)}</span>`),
    fieldRow("SANs", `<span class="mono">${sans}</span>`),
    fieldRow("Serial", `<span class="mono">${esc(c.serial)}</span>`),
    fieldRow("Status", esc(c.status)),
    fieldRow("Is CA", c.is_ca ? "yes" : "no"),
    fieldRow("Certificate type", c.cert_type ? esc(c.cert_type) : "—"),
    fieldRow("Provisioner", provisioner),
    fieldRow("Key type", `<span class="mono">${esc(c.key_type)}</span>`),
    fieldRow("Fingerprint (SHA-256)", `<span class="mono">${esc(c.fingerprint_sha256)}</span>`),
    fieldRow("Not before", fmtDate(c.not_before)),
    fieldRow("Not after", fmtDate(c.not_after)),
    fieldRow("Days left", String(c.days_left)),
    fieldRow("Revoked at", c.revoked_at ? esc(c.revoked_at) : "—"),
  ].join("");
  document.getElementById("modalBackdrop").classList.add("show");
}

function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("show");
}

document.getElementById("list").addEventListener("click", (e) => {
  if (e.target.closest("button.revoke")) return;
  const row = e.target.closest(".row");
  if (!row) return;
  const cert = ALL.find(c => c.serial === row.dataset.serial);
  if (cert) openModal(cert);
});
document.getElementById("modalClose").addEventListener("click", closeModal);
document.getElementById("modalBackdrop").addEventListener("click", (e) => {
  if (e.target.id === "modalBackdrop") closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  closeModal();
  const issueBackdrop = document.getElementById("issueBackdrop");
  if (issueBackdrop) issueBackdrop.classList.remove("show");
});

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

if (ISSUE_ENABLED) {
  let lastIssued = null;

  const showResult = () => document.getElementById("issueResult").classList.add("show");
  const openIssueModal = () => {
    document.getElementById("issueForm").reset();
    document.getElementById("issueResult").classList.remove("show");
    document.getElementById("issueBackdrop").classList.add("show");
    document.getElementById("issueCn").focus();
  };
  const closeIssueModal = () => document.getElementById("issueBackdrop").classList.remove("show");

  document.getElementById("issueBtn").addEventListener("click", openIssueModal);
  document.getElementById("issueClose").addEventListener("click", closeIssueModal);
  document.getElementById("issueBackdrop").addEventListener("click", (e) => {
    if (e.target.id === "issueBackdrop") closeIssueModal();
  });

  document.getElementById("dlCert").addEventListener("click", (e) => {
    e.preventDefault();
    if (lastIssued) downloadText(`${lastIssued.cn}.crt`, lastIssued.cert_pem);
  });
  document.getElementById("dlChain").addEventListener("click", (e) => {
    e.preventDefault();
    if (lastIssued) downloadText(`${lastIssued.cn}-chain.crt`, lastIssued.chain_pem);
  });
  document.getElementById("dlKey").addEventListener("click", (e) => {
    e.preventDefault();
    if (lastIssued) downloadText(`${lastIssued.cn}.key`, lastIssued.key_pem);
  });

  document.getElementById("issueForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const cert_type = document.getElementById("issueCertType").value;
    const cn = document.getElementById("issueCn").value.trim();
    const sans = document.getElementById("issueSans").value
      .split(",").map(s => s.trim()).filter(Boolean);
    const key_type = document.getElementById("issueKeyType").value;
    const btn = document.getElementById("issueSubmit");
    btn.disabled = true; btn.textContent = "Issuing…";
    try {
      const r = await fetch("/api/issue", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cn, sans, key_type, cert_type })
      });
      const j = await r.json();
      if (j.ok) {
        lastIssued = { cn, cert_pem: j.cert_pem, chain_pem: j.chain_pem, key_pem: j.key_pem };
        showResult();
        toast(`Certificate issued for ${cn}.`, "ok");
        load();
      } else {
        toast(j.error || "Issuance failed.", "err");
      }
    } catch (err) {
      toast("Error: " + err.message, "err");
    } finally {
      btn.disabled = false; btn.textContent = "Issue";
    }
  });
}

document.getElementById("search").addEventListener("input", render);
document.getElementById("refresh").addEventListener("click", load);
document.querySelectorAll(".chip").forEach(ch => {
  ch.addEventListener("click", () => {
    const f = ch.dataset.f;
    if (active.has(f)) { active.delete(f); ch.classList.remove("on"); }
    else { active.add(f); ch.classList.add("on"); }
    render();
  });
});

load();
setInterval(load, 60000);
