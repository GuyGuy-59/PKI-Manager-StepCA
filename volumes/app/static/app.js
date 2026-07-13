const REVOKE_ENABLED = (function () {
  var s = document.currentScript || document.querySelector('script[data-revoke]');
  return s && s.dataset.revoke === "true";
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
    return `
      <div class="row ${c.status}">
        <div class="status-bar"></div>
        <div class="ident">
          <div class="cn">${esc(c.subject_cn)}${caTag}</div>
          <div class="sans" title="${esc(sans)}">${esc(sans)}</div>
          <div class="meta-serial">sn:${esc(c.serial)} · ${esc(c.key_type)} · ${c.fingerprint_sha256.slice(0, 16)}…</div>
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
